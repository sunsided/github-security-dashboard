use assert2::check;
use chrono::{Duration, Utc};
use gh::{AppProvider, Error, PatProvider, Secret, TokenProvider};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PRIVATE_KEY: &[u8] = include_bytes!("fixtures/test-app-key.pem");
const PUBLIC_KEY: &[u8] = include_bytes!("fixtures/test-app-key.pub.pem");

fn provider(server: &MockServer) -> AppProvider {
    AppProvider::new("123456", PRIVATE_KEY, server.uri(), "test").unwrap()
}

async fn mount_installations(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/app/installations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 7, "account": { "login": "acme" } },
            { "id": 3, "account": { "login": "Me" } }
        ])))
        .expect(1)
        .mount(server)
        .await;
}

fn access_token(token: &str, expires_in: Duration) -> ResponseTemplate {
    ResponseTemplate::new(201).set_body_json(json!({
        "token": token,
        "expires_at": (Utc::now() + expires_in).to_rfc3339()
    }))
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    iat: i64,
    exp: i64,
}

#[tokio::test]
async fn app_jwt_is_signed_with_the_private_key() {
    let server = MockServer::start().await;
    mount_installations(&server).await;
    Mock::given(method("POST"))
        .and(path("/app/installations/7/access_tokens"))
        .respond_with(access_token("inst-7", Duration::hours(1)))
        .mount(&server)
        .await;

    provider(&server).token("acme").await.unwrap();

    let requests = server.received_requests().await.unwrap();
    let auth = requests[0]
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    let jwt = auth.strip_prefix("Bearer ").unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["123456"]);
    let key = DecodingKey::from_rsa_pem(PUBLIC_KEY).unwrap();
    let claims = jsonwebtoken::decode::<Claims>(jwt, &key, &validation)
        .unwrap()
        .claims;
    check!(claims.iss == "123456");
    check!(
        claims.exp - claims.iat <= 10 * 60,
        "GitHub rejects JWTs valid for over ten minutes"
    );
    check!(
        claims.iat < Utc::now().timestamp(),
        "backdated against clock drift"
    );
}

#[tokio::test]
async fn installation_tokens_are_cached_per_owner() {
    let server = MockServer::start().await;
    mount_installations(&server).await;
    Mock::given(method("POST"))
        .and(path("/app/installations/7/access_tokens"))
        .and(header_exists("authorization"))
        .respond_with(access_token("inst-7", Duration::hours(1)))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/app/installations/3/access_tokens"))
        .respond_with(access_token("inst-3", Duration::hours(1)))
        .expect(1)
        .mount(&server)
        .await;

    let app = provider(&server);
    check!(app.token("acme").await.unwrap().expose() == "inst-7");
    check!(app.token("ACME").await.unwrap().expose() == "inst-7");
    check!(
        app.token("me").await.unwrap().expose() == "inst-3",
        "logins compare case-insensitively"
    );
}

#[tokio::test]
async fn tokens_close_to_expiry_are_renewed() {
    let server = MockServer::start().await;
    mount_installations(&server).await;
    Mock::given(method("POST"))
        .and(path("/app/installations/7/access_tokens"))
        .respond_with(access_token("inst-7", Duration::minutes(2)))
        .expect(2)
        .mount(&server)
        .await;

    let app = provider(&server);
    app.token("acme").await.unwrap();
    app.token("acme").await.unwrap();
}

#[tokio::test]
async fn unknown_owners_use_the_fallback() {
    let server = MockServer::start().await;
    mount_installations(&server).await;

    let app = provider(&server).with_fallback(Arc::new(PatProvider::new(Secret::new("ghp_pat"))));
    check!(app.token("rust-lang").await.unwrap().expose() == "ghp_pat");
}

#[tokio::test]
async fn unknown_owners_without_fallback_use_the_oldest_installation() {
    let server = MockServer::start().await;
    mount_installations(&server).await;
    Mock::given(method("POST"))
        .and(path("/app/installations/3/access_tokens"))
        .respond_with(access_token("inst-3", Duration::hours(1)))
        .expect(1)
        .mount(&server)
        .await;

    check!(provider(&server).token("rust-lang").await.unwrap().expose() == "inst-3");
}

#[tokio::test]
async fn app_without_installations_fails_clearly() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/app/installations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let err = provider(&server).token("acme").await.unwrap_err();
    check!(let Error::Auth(message) = &err && message.contains("no installations"));
}

#[tokio::test]
async fn rejected_jwt_reports_github_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/app/installations"))
        .respond_with(ResponseTemplate::new(401).set_body_json(
            json!({ "message": "'Expiration time' claim ('exp') is too far in the future" }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let err = provider(&server).token("acme").await.unwrap_err();
    check!(err.reason().contains("too far in the future"));
}

#[test]
fn invalid_private_key_is_rejected() {
    let err = AppProvider::new("1", b"not a key", "http://localhost", "test")
        .err()
        .unwrap();
    check!(let Error::Auth(message) = &err && message.contains("private key"));
}

#[tokio::test]
async fn enterprise_installations_do_not_break_the_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/app/installations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 11, "account": { "slug": "big-corp", "name": "Big Corp" }, "target_type": "Enterprise" },
            { "id": 12, "account": { "login": "big-corp-eng" }, "target_type": "Organization" },
            { "id": 13, "account": null }
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/app/installations/12/access_tokens"))
        .respond_with(access_token("inst-12", Duration::hours(1)))
        .mount(&server)
        .await;

    check!(
        provider(&server)
            .token("big-corp-eng")
            .await
            .unwrap()
            .expose()
            == "inst-12"
    );
}

#[tokio::test]
async fn undecodable_responses_say_why() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/app/installations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "unexpected": true })))
        .mount(&server)
        .await;

    let err = provider(&server).token("acme").await.unwrap_err();
    check!(let Error::Auth(message) = &err && message.contains("/app/installations") && message.contains("expected a sequence"));
}

#[tokio::test]
async fn transient_app_api_failures_are_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/app/installations"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    mount_installations(&server).await;
    Mock::given(method("POST"))
        .and(path("/app/installations/7/access_tokens"))
        .respond_with(access_token("inst-7", Duration::hours(1)))
        .mount(&server)
        .await;

    let app = provider(&server).with_retry_backoff(std::time::Duration::ZERO);
    check!(app.token("acme").await.unwrap().expose() == "inst-7");
}
