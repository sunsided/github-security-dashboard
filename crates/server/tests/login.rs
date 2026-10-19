//! Signing in, against a fake identity provider.

use assert2::check;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, Response, StatusCode, header};
use chrono::Utc;
use collector::{Collector, CollectorConfig};
use gh::{ClientConfig, GitHub, PatProvider, Secret};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use server::api::AppState;
use server::config::Scoring;
use server::guard::{AllowedHosts, CSRF_HEADER};
use server::login::{Login, LoginConfig};
use server::realtime::{Hub, RealtimeConfig};
use server::scheduler::Scheduler;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const IDP_KEY: &str = include_str!("fixtures/idp-key.pem");
const IDP_JWKS: &str = include_str!("fixtures/idp-jwks.json");

/// Serves discovery and keys; tests add the token endpoint.
async fn identity_provider() -> MockServer {
    let idp = MockServer::start().await;
    let issuer = idp.uri();
    Mock::given(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        })))
        .mount(&idp)
        .await;
    Mock::given(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(IDP_JWKS, "application/json"))
        .mount(&idp)
        .await;
    idp
}

/// A token from the fake provider, with `extra` claims on top.
fn token(idp: &MockServer, audience: &str, extra: Value) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": idp.uri(),
        "aud": audience,
        "sub": "user-1",
        "email": "alice@example.org",
        "email_verified": true,
        "name": "Alice",
        "groups": ["security"],
        "iat": now,
        "exp": now + 300,
    });
    for (key, value) in extra.as_object().unwrap() {
        claims[key] = value.clone();
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-idp".into());
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(IDP_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}

async fn app(config: &str, env: &[(&str, &str)]) -> Router {
    let config: LoginConfig = toml::from_str(config).unwrap();
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let login = Login::from_config(&config, |name| env.get(name).cloned())
        .await
        .unwrap();

    let store = store::connect("sqlite::memory:").await.unwrap();
    let github = Arc::new(
        GitHub::new(
            ClientConfig {
                api_url: "http://127.0.0.1:9".into(),
                ..ClientConfig::default()
            },
            Arc::new(PatProvider::new(Secret::new("unused"))),
        )
        .unwrap(),
    );
    let hub = Arc::new(Hub::new(
        RealtimeConfig::default(),
        b"test signing key",
        AllowedHosts::new(&[]),
    ));
    let collector = Collector::new(
        Arc::clone(&github),
        Arc::clone(&store),
        CollectorConfig::default(),
    );
    let scheduler = Arc::new(Scheduler::new(
        collector,
        std::time::Duration::from_secs(3600),
        Arc::clone(&store),
        Arc::clone(&hub),
    ));
    let state = AppState {
        store,
        github,
        scheduler,
        scoring: Scoring::default(),
        auth: "personal access token",
        digest: None,
        realtime: hub,
    };
    server::app(state, AllowedHosts::new(&[]), Arc::new(login))
}

/// A request from `peer`, as the UI sends it, with extra `headers`.
fn request(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost:8080")
        .header(CSRF_HEADER, "1");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 5], 40000))));
    request
}

async fn send(app: &Router, request: Request<Body>) -> (Response<Body>, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (Response::from_parts(parts, Body::empty()), json)
}

fn location(response: &Response<Body>) -> String {
    response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned()
}

/// `name=value` pairs of the response's cookies, for a `Cookie` header.
fn cookies(response: &Response<Body>) -> HashMap<String, String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|c| {
            let pair = c.to_str().unwrap().split(';').next().unwrap();
            let (name, value) = pair.split_once('=').unwrap();
            (name.to_owned(), value.to_owned())
        })
        .collect()
}

#[tokio::test]
async fn without_login_everything_is_open() {
    let app = app("", &[]).await;
    let (response, me) = send(&app, request("GET", "/api/me", &[])).await;
    check!(response.status() == StatusCode::OK);
    check!(me == json!({ "mode": "none", "user": null, "sign_out_url": null }));
    let (response, _) = send(&app, request("GET", "/api/summary", &[])).await;
    check!(response.status() == StatusCode::OK);
}

fn proxy_config(idp: &MockServer, extra: &str) -> String {
    format!(
        "mode = \"proxy\"\n{extra}\n[proxy]\nissuer = \"{}\"\naudiences = [\"oauth2-proxy\"]\n\
         sign_out_url = \"/oauth2/sign_out\"",
        idp.uri()
    )
}

#[tokio::test]
async fn proxy_tokens_are_verified() {
    let idp = identity_provider().await;
    let app = app(&proxy_config(&idp, ""), &[]).await;

    let good = format!("Bearer {}", token(&idp, "oauth2-proxy", json!({})));
    let (response, me) = send(&app, request("GET", "/api/me", &[("authorization", &good)])).await;
    check!(response.status() == StatusCode::OK);
    check!(me["mode"] == "proxy");
    check!(me["user"]["subject"] == "user-1");
    check!(me["user"]["email"] == "alice@example.org");
    check!(me["sign_out_url"] == "/oauth2/sign_out");

    let (response, body) = send(&app, request("GET", "/api/summary", &[])).await;
    check!(response.status() == StatusCode::UNAUTHORIZED);
    check!(body["login"] == Value::Null, "the proxy handles sign-in");

    for bad in [
        token(&idp, "another-app", json!({})),
        token(
            &idp,
            "oauth2-proxy",
            json!({ "iss": "https://evil.example" }),
        ),
        token(
            &idp,
            "oauth2-proxy",
            json!({ "exp": Utc::now().timestamp() - 600 }),
        ),
        "not-a-token".to_owned(),
    ] {
        let (response, _) = send(
            &app,
            request("GET", "/api/summary", &[("authorization", &bad)]),
        )
        .await;
        check!(response.status() == StatusCode::UNAUTHORIZED, "{bad}");
    }

    let (response, _) = send(&app, request("GET", "/auth/../api/summary", &[])).await;
    check!(
        response.status() == StatusCode::UNAUTHORIZED,
        "no detour through /auth/"
    );

    let (response, _) = send(&app, request("GET", "/healthz", &[])).await;
    check!(response.status() == StatusCode::OK, "probes need no token");
    let mut probe = request("GET", "/healthz", &[]);
    probe
        .headers_mut()
        .insert("host", "10.1.2.3:8080".parse().unwrap());
    let (response, _) = send(&app, probe).await;
    check!(response.status() == StatusCode::OK, "probes come by pod IP");
}

#[tokio::test]
async fn realtime_tokens_carry_the_user() {
    let idp = identity_provider().await;
    let app = app(&proxy_config(&idp, ""), &[]).await;
    let good = token(&idp, "oauth2-proxy", json!({}));
    let (response, body) = send(
        &app,
        request("POST", "/api/realtime/token", &[("authorization", &good)]),
    )
    .await;
    check!(response.status() == StatusCode::OK);
    let claims = jsonwebtoken::dangerous::insecure_decode::<Value>(body["token"].as_str().unwrap())
        .unwrap()
        .claims;
    check!(claims["sub"] == "user-1");
}

#[tokio::test]
async fn allow_list_turns_away_other_users() {
    let idp = identity_provider().await;
    let app = app(&proxy_config(&idp, "[allow]\ngroups = [\"admins\"]"), &[]).await;
    let token = token(&idp, "oauth2-proxy", json!({}));
    let (response, _) = send(
        &app,
        request("GET", "/api/summary", &[("authorization", &token)]),
    )
    .await;
    check!(response.status() == StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn proxy_headers_from_trusted_addresses() {
    let headers = [
        ("x-forwarded-user", "bob"),
        ("x-forwarded-email", "bob@example.org"),
    ];
    let trusted = app(
        "mode = \"proxy\"\n[proxy]\ntrust = \"headers\"\ntrusted_proxies = [\"10.0.0.0/24\"]",
        &[],
    )
    .await;
    let (response, me) = send(&trusted, request("GET", "/api/me", &headers)).await;
    check!(response.status() == StatusCode::OK);
    check!(me["user"]["subject"] == "bob");

    let elsewhere = app(
        "mode = \"proxy\"\n[proxy]\ntrust = \"headers\"\ntrusted_proxies = [\"192.168.0.0/16\"]",
        &[],
    )
    .await;
    let (response, _) = send(&elsewhere, request("GET", "/api/me", &headers)).await;
    check!(response.status() == StatusCode::UNAUTHORIZED);
}

fn oidc_config(idp: &MockServer) -> String {
    format!(
        "mode = \"oidc\"\n[oidc]\nissuer = \"{}\"\nclient_id = \"dashboard\"\n\
         client_secret_env = \"OIDC_SECRET\"\nredirect_url = \"http://localhost:8080/auth/callback\"",
        idp.uri()
    )
}

/// Query parameters of a URL.
fn query(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

#[tokio::test]
async fn oidc_sign_in_round_trip() {
    let idp = identity_provider().await;
    let app = app(&oidc_config(&idp), &[("OIDC_SECRET", "s3cret")]).await;

    // Unauthenticated: API calls get 401, pages a redirect to sign in.
    let (response, body) = send(&app, request("GET", "/api/summary", &[])).await;
    check!(response.status() == StatusCode::UNAUTHORIZED);
    check!(body["login"] == "/auth/login");
    let (response, _) = send(&app, request("GET", "/repo/acme/api?x=1", &[])).await;
    check!(response.status() == StatusCode::SEE_OTHER);
    check!(location(&response) == "/auth/login?return_to=%2Frepo%2Facme%2Fapi%3Fx%3D1");

    // 1. Off to the provider, with PKCE.
    let (response, _) = send(
        &app,
        request("GET", "/auth/login?return_to=%2Frepo%2Facme%2Fapi", &[]),
    )
    .await;
    check!(response.status() == StatusCode::SEE_OTHER);
    let authorize = location(&response);
    check!(authorize.starts_with(&format!("{}/authorize?", idp.uri())));
    let params = query(&authorize);
    check!(params["response_type"] == "code");
    check!(params["client_id"] == "dashboard");
    check!(params["redirect_uri"] == "http://localhost:8080/auth/callback");
    check!(params["code_challenge_method"] == "S256");
    check!(params["scope"] == "openid email profile");
    let sign_in = cookies(&response);
    let sign_in_cookie = format!("dashboard-sign-in={}", sign_in["dashboard-sign-in"]);
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    check!(set_cookie.contains("HttpOnly"));
    check!(set_cookie.contains("SameSite=Lax"));

    // 2. The provider redeems the code only with the PKCE verifier.
    let pending = jsonwebtoken::dangerous::insecure_decode::<Value>(&sign_in["dashboard-sign-in"])
        .unwrap()
        .claims;
    let verifier = pending["verifier"].as_str().unwrap();
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("code=the-code"))
        .and(body_string_contains(format!("code_verifier={verifier}")))
        .and(wiremock::matchers::header(
            "authorization",
            "Basic ZGFzaGJvYXJkOnMzY3JldA==", // dashboard:s3cret
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "opaque",
            "token_type": "Bearer",
            "id_token": token(&idp, "dashboard", json!({ "nonce": params["nonce"] })),
        })))
        .expect(1)
        .mount(&idp)
        .await;

    // A callback with someone else's state is refused.
    let (response, _) = send(
        &app,
        request(
            "GET",
            "/auth/callback?code=the-code&state=forged",
            &[("cookie", &sign_in_cookie)],
        ),
    )
    .await;
    check!(response.status() == StatusCode::BAD_REQUEST);

    // 3. Back with the code: signed in and sent where the user was going.
    let callback = format!("/auth/callback?code=the-code&state={}", params["state"]);
    let (response, _) = send(
        &app,
        request("GET", &callback, &[("cookie", &sign_in_cookie)]),
    )
    .await;
    check!(response.status() == StatusCode::SEE_OTHER);
    check!(location(&response) == "/repo/acme/api");
    let session = cookies(&response);
    check!(
        session["dashboard-sign-in"] == "",
        "sign-in state is cleared"
    );
    let session_cookie = format!("dashboard-session={}", session["dashboard-session"]);

    let (response, me) = send(
        &app,
        request("GET", "/api/me", &[("cookie", &session_cookie)]),
    )
    .await;
    check!(response.status() == StatusCode::OK);
    check!(me["mode"] == "oidc");
    check!(me["user"]["subject"] == "user-1");
    check!(me["user"]["name"] == "Alice");
    let (response, _) = send(
        &app,
        request("GET", "/api/summary", &[("cookie", &session_cookie)]),
    )
    .await;
    check!(response.status() == StatusCode::OK);

    // A session cookie can't be replayed as a sign-in, nor vice versa.
    let swapped = format!("dashboard-session={}", sign_in["dashboard-sign-in"]);
    let (response, _) = send(&app, request("GET", "/api/me", &[("cookie", &swapped)])).await;
    check!(response.status() == StatusCode::UNAUTHORIZED);

    // Signing out clears the session.
    let (response, body) = send(
        &app,
        request("POST", "/auth/logout", &[("cookie", &session_cookie)]),
    )
    .await;
    check!(response.status() == StatusCode::OK);
    check!(body["redirect"] == "/auth/signed-out");
    check!(cookies(&response)["dashboard-session"] == "");
}

#[tokio::test]
async fn oidc_rejects_id_tokens_with_the_wrong_nonce() {
    let idp = identity_provider().await;
    let app = app(&oidc_config(&idp), &[("OIDC_SECRET", "s3cret")]).await;
    let (response, _) = send(&app, request("GET", "/auth/login", &[])).await;
    let params = query(&location(&response));
    let sign_in_cookie = format!(
        "dashboard-sign-in={}",
        cookies(&response)["dashboard-sign-in"]
    );
    Mock::given(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": token(&idp, "dashboard", json!({ "nonce": "replayed" })),
        })))
        .mount(&idp)
        .await;

    let callback = format!("/auth/callback?code=c&state={}", params["state"]);
    let (response, _) = send(
        &app,
        request("GET", &callback, &[("cookie", &sign_in_cookie)]),
    )
    .await;
    check!(response.status() == StatusCode::BAD_GATEWAY);
    check!(!cookies(&response).contains_key("dashboard-session"));
}

#[tokio::test]
async fn oidc_needs_its_secrets() {
    let idp = identity_provider().await;
    let config: LoginConfig = toml::from_str(&oidc_config(&idp)).unwrap();
    let err = Login::from_config(&config, |_| None).await.err().unwrap();
    check!(err.to_string().contains("OIDC_SECRET"));

    let config: LoginConfig = toml::from_str(&format!(
        "{}\nsession_key_env = \"SESSION_KEY\"",
        oidc_config(&idp)
    ))
    .unwrap();
    let short = Login::from_config(&config, |name| {
        Some(
            if name == "SESSION_KEY" {
                "too short"
            } else {
                "s"
            }
            .to_owned(),
        )
    })
    .await
    .err()
    .unwrap();
    check!(short.to_string().contains("32 bytes"));
}
