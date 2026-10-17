use assert2::check;
use gh::{ClientConfig, Error, GitHub, OwnerKind, PatProvider, Secret};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn client(server: &MockServer) -> GitHub {
    let config = ClientConfig {
        api_url: server.uri(),
        graphql_url: format!("{}/graphql", server.uri()),
        backoff: Duration::ZERO,
        max_rate_limit_wait: Duration::from_secs(5),
        ..ClientConfig::default()
    };
    GitHub::new(config, Arc::new(PatProvider::new(Secret::new("t0ken")))).unwrap()
}

fn repo_node(name: &str, commits: Option<i64>) -> Value {
    json!({
        "name": name,
        "owner": { "login": "acme", "__typename": "Organization" },
        "url": format!("https://github.com/acme/{name}"),
        "description": null,
        "isArchived": false,
        "isFork": false,
        "isPrivate": true,
        "primaryLanguage": { "name": "Rust" },
        "stargazerCount": 3,
        "forkCount": 1,
        "pushedAt": "2026-10-01T10:00:00Z",
        "defaultBranchRef": commits.map(|c| json!({
            "name": "main",
            "target": { "committedDate": "2026-09-30T08:00:00Z", "history": { "totalCount": c } }
        })),
        "issues": { "totalCount": 5 },
        "pullRequests": { "totalCount": 2 },
        "refs": { "totalCount": 7 },
        "releases": { "totalCount": 1 }
    })
}

/// Serves a fixed sequence of responses, repeating the last one.
struct Sequence(std::sync::Mutex<Vec<ResponseTemplate>>);

impl Respond for Sequence {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let mut queue = self.0.lock().unwrap();
        if queue.len() > 1 {
            queue.remove(0)
        } else {
            queue[0].clone()
        }
    }
}

#[tokio::test]
async fn lists_owner_repositories_across_pages() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(header("authorization", "Bearer t0ken"))
        .and(body_partial_json(json!({ "variables": { "after": null } })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "repositoryOwner": { "repositories": {
                "pageInfo": { "hasNextPage": true, "endCursor": "c1" },
                "nodes": [repo_node("alpha", Some(120))]
            }}}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(json!({ "variables": { "after": "c1" } })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "repositoryOwner": { "repositories": {
                "pageInfo": { "hasNextPage": false, "endCursor": null },
                "nodes": [repo_node("empty", None)]
            }}}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let repos = client(&server)
        .owner_repositories("acme", 25)
        .await
        .unwrap();
    check!(repos.len() == 2);

    let alpha = &repos[0];
    check!(alpha.owner_kind == OwnerKind::Organization);
    check!(alpha.commits == Some(120));
    check!(alpha.default_branch.as_deref() == Some("main"));
    check!(
        (
            alpha.open_issues,
            alpha.open_prs,
            alpha.tags,
            alpha.releases
        ) == (5, 2, 7, 1)
    );
    check!(alpha.language.as_deref() == Some("Rust"));

    let empty = &repos[1];
    check!(empty.commits == None);
    check!(empty.last_commit_at == None);
}

#[tokio::test]
async fn unknown_owner_is_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "repositoryOwner": null },
            "errors": [{ "type": "NOT_FOUND", "message": "Could not resolve to a RepositoryOwner", "path": ["repositoryOwner"] }]
        })))
        .mount(&server)
        .await;

    let err = client(&server)
        .owner_repositories("nobody", 25)
        .await
        .unwrap_err();
    check!(let Error::NotFound(_) = err, "{err:?}");
    check!(err.is_inaccessible());
}

#[tokio::test]
async fn other_graphql_errors_fail() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": null,
            "errors": [{ "type": "MAX_NODE_LIMIT_EXCEEDED", "message": "too many nodes" }]
        })))
        .mount(&server)
        .await;

    let err = client(&server)
        .repository("acme", "alpha")
        .await
        .unwrap_err();
    assert2::assert!(let Error::GraphQl(messages) = &err);
    check!(messages == &["too many nodes"]);
}

#[tokio::test]
async fn retries_secondary_rate_limit_and_server_errors() {
    let server = MockServer::start().await;
    let ok = ResponseTemplate::new(200)
        .insert_header("x-ratelimit-limit", "5000")
        .insert_header("x-ratelimit-remaining", "4990")
        .insert_header("x-ratelimit-reset", "1900000000")
        .insert_header("x-ratelimit-resource", "graphql")
        .set_body_json(json!({ "data": { "repository": repo_node("alpha", Some(1)) } }));
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(Sequence(std::sync::Mutex::new(vec![
            ResponseTemplate::new(403)
                .insert_header("retry-after", "0")
                .set_body_json(json!({ "message": "secondary rate limit" })),
            ResponseTemplate::new(502),
            ok,
        ])))
        .expect(3)
        .mount(&server)
        .await;

    let gh = client(&server);
    let repo = gh.repository("acme", "alpha").await.unwrap();
    check!(repo.name == "alpha");
    check!(gh.rate_limit_remaining() == Some(4990));
    check!(gh.rate_limits().contains_key("graphql"));
}

#[tokio::test]
async fn gives_up_when_primary_reset_is_too_far_away() {
    let server = MockServer::start().await;
    let reset = chrono::Utc::now().timestamp() + 3600;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ratelimit-limit", "5000")
                .insert_header("x-ratelimit-remaining", "0")
                .insert_header("x-ratelimit-reset", reset.to_string().as_str())
                .set_body_json(json!({ "message": "API rate limit exceeded" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let err = client(&server)
        .contributor_count("acme", "alpha")
        .await
        .unwrap_err();
    check!(let Error::RateLimited { .. } = err, "{err:?}");
}

#[tokio::test]
async fn plain_forbidden_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({ "message": "Resource not accessible by integration" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let err = client(&server)
        .contributor_count("acme", "alpha")
        .await
        .unwrap_err();
    check!(err.is_inaccessible());
    check!(err.to_string().contains("Resource not accessible"), "{err}");
}

#[tokio::test]
async fn contributor_count_from_last_link() {
    let server = MockServer::start().await;
    let link = format!(
        r#"<{0}/repositories/1/contributors?per_page=1&anon=1&page=2>; rel="next", <{0}/repositories/1/contributors?per_page=1&anon=1&page=42>; rel="last""#,
        server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/repos/acme/alpha/contributors"))
        .and(query_param("per_page", "1"))
        .and(query_param("anon", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", link.as_str())
                .set_body_json(json!([{}])),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/solo/contributors"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "login": "me" }])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/empty/contributors"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/huge/contributors"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "The history or contributor list is too large to list contributors for this repository via the API."
        })))
        .mount(&server)
        .await;

    let gh = client(&server);
    check!(gh.contributor_count("acme", "alpha").await.unwrap() == Some(42));
    check!(gh.contributor_count("acme", "solo").await.unwrap() == Some(1));
    check!(gh.contributor_count("acme", "empty").await.unwrap() == Some(0));
    check!(gh.contributor_count("acme", "huge").await.unwrap() == None);
}

#[tokio::test]
async fn etag_hit_replays_cached_response() {
    let server = MockServer::start().await;
    let link = format!(r#"<{}/x?per_page=1&page=9>; rel="last""#, server.uri());
    Mock::given(method("GET"))
        .and(path("/repos/acme/alpha/contributors"))
        .and(header("if-none-match", "\"abc\""))
        .respond_with(ResponseTemplate::new(304))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/alpha/contributors"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"abc\"")
                .insert_header("link", link.as_str())
                .set_body_json(json!([{}])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let gh = client(&server);
    check!(gh.contributor_count("acme", "alpha").await.unwrap() == Some(9));
    check!(gh.contributor_count("acme", "alpha").await.unwrap() == Some(9));
}

fn dependabot_json(number: i64, repo: &str) -> Value {
    json!({
        "number": number, "state": "open", "html_url": format!("https://github.com/acme/{repo}/security/dependabot/{number}"),
        "created_at": "2026-01-01T00:00:00Z", "fixed_at": null, "dismissed_at": null, "auto_dismissed_at": null,
        "dependency": { "package": { "ecosystem": "cargo", "name": "openssl" }, "manifest_path": "Cargo.lock" },
        "security_advisory": { "summary": "Use after free", "severity": "critical" },
        "repository": { "name": repo, "owner": { "login": "acme" } }
    })
}

#[tokio::test]
async fn org_alerts_follow_cursor_pages() {
    let server = MockServer::start().await;
    let next = format!(
        r#"<{}/orgs/acme/dependabot/alerts?state=open&per_page=100&after=CURSOR>; rel="next""#,
        server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/orgs/acme/dependabot/alerts"))
        .and(query_param("after", "CURSOR"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([dependabot_json(2, "web")])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/dependabot/alerts"))
        .and(query_param("state", "open"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", next.as_str())
                .set_body_json(json!([dependabot_json(1, "api")])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let alerts = client(&server)
        .org_alerts("acme", gh::AlertKind::Dependabot)
        .await
        .unwrap();
    let ids: Vec<_> = alerts.iter().map(|a| (a.repo.as_str(), a.number)).collect();
    check!(ids == [("api", 1), ("web", 2)]);
    check!(alerts[0].severity == Some(gh::AlertSeverity::Critical));
}

#[tokio::test]
async fn secret_scanning_requests_hide_secrets() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/me/app/secret-scanning/alerts"))
        .and(query_param("hide_secret", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let alerts = client(&server)
        .repo_alerts("me", "app", gh::AlertKind::SecretScanning)
        .await
        .unwrap();
    check!(alerts.is_empty());
}

#[tokio::test]
async fn disabled_feature_is_inaccessible() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/me/app/code-scanning/alerts"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "Code scanning is not enabled for this repository."
        })))
        .mount(&server)
        .await;

    let err = client(&server)
        .repo_alerts("me", "app", gh::AlertKind::CodeScanning)
        .await
        .unwrap_err();
    check!(err.is_inaccessible());
    check!(err.to_string().contains("not enabled"));
}
