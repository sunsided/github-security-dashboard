use collector::{Collector, CollectorConfig, RepoRef};
use gh::{ClientConfig, GitHub, PatProvider, Secret};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use store::{RepoFilter, RepoKind, RunStatus};
use wiremock::matchers::{body_partial_json, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn repo_node(owner: &str, typename: &str, name: &str) -> Value {
    json!({
        "name": name,
        "owner": { "login": owner, "__typename": typename },
        "url": format!("https://github.com/{owner}/{name}"),
        "description": null,
        "isArchived": false,
        "isFork": false,
        "isPrivate": false,
        "primaryLanguage": null,
        "stargazerCount": 0,
        "forkCount": 0,
        "pushedAt": "2026-10-01T10:00:00Z",
        "defaultBranchRef": { "name": "main", "target": {
            "committedDate": "2026-09-30T08:00:00Z", "history": { "totalCount": 10 } } },
        "issues": { "totalCount": 4 },
        "pullRequests": { "totalCount": 1 },
        "refs": { "totalCount": 0 },
        "releases": { "totalCount": 0 }
    })
}

async fn github_mock() -> MockServer {
    let server = MockServer::start().await;

    let owner_page = |login: &str, nodes: Vec<Value>| {
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_partial_json(
                json!({ "variables": { "login": login } }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "repositoryOwner": { "repositories": {
                    "pageInfo": { "hasNextPage": false, "endCursor": null },
                    "nodes": nodes
                }}}
            })))
    };
    owner_page(
        "acme",
        vec![
            repo_node("acme", "Organization", "api"),
            repo_node("acme", "Organization", "web"),
        ],
    )
    .mount(&server)
    .await;
    owner_page("me", vec![repo_node("me", "User", "dotfiles")])
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(
            json!({ "variables": { "login": "ghost" } }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "repositoryOwner": null },
            "errors": [{ "type": "NOT_FOUND", "message": "Could not resolve" }]
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(body_partial_json(
            json!({ "variables": { "owner": "sveltejs", "name": "kit" } }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "repository": repo_node("sveltejs", "Organization", "kit") }
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex("^/repos/[^/]+/[^/]+/contributors$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{}, {}, {}])))
        .mount(&server)
        .await;

    server
}

fn github(server: &MockServer) -> Arc<GitHub> {
    let config = ClientConfig {
        api_url: server.uri(),
        graphql_url: format!("{}/graphql", server.uri()),
        backoff: Duration::ZERO,
        ..ClientConfig::default()
    };
    Arc::new(GitHub::new(config, Arc::new(PatProvider::new(Secret::new("t")))).unwrap())
}

fn repo_ref(s: &str) -> RepoRef {
    RepoRef::try_from(s.to_owned()).unwrap()
}

#[tokio::test]
async fn collects_owners_and_external_repos() {
    let server = github_mock().await;
    let store = store::connect("sqlite::memory:").await.unwrap();
    let config = CollectorConfig {
        owners: vec!["acme".into(), "me".into(), "ghost".into()],
        // The duplicate of an owned repository must not be tracked twice.
        external_repos: vec![repo_ref("sveltejs/kit"), repo_ref("ACME/api")],
        ..CollectorConfig::default()
    };

    let summary = Collector::new(github(&server), store.clone(), config)
        .run()
        .await
        .unwrap();

    assert_eq!(summary.repos, 4);
    assert_eq!(summary.status, RunStatus::Partial);
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert!(summary.errors[0].starts_with("owner ghost"));

    let repos = store.list_repos(&RepoFilter::default()).await.unwrap();
    let kinds: Vec<_> = repos
        .iter()
        .map(|r| (format!("{}/{}", r.info.owner, r.info.name), r.info.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            ("acme/api".to_owned(), RepoKind::Org),
            ("acme/web".to_owned(), RepoKind::Org),
            ("me/dotfiles".to_owned(), RepoKind::User),
            ("sveltejs/kit".to_owned(), RepoKind::External),
        ]
    );

    let latest = repos[0].latest.as_ref().unwrap();
    assert_eq!(latest.run_id, summary.run);
    assert_eq!(latest.stats.contributors, Some(3));
    assert_eq!(latest.stats.commits, Some(10));
    assert_eq!(latest.stats.open_issues, 4);

    let runs = store.list_runs(1).await.unwrap();
    assert_eq!(runs[0].status, RunStatus::Partial);
    assert!(runs[0].finished_at.is_some());
}

#[tokio::test]
async fn run_fails_when_nothing_could_be_collected() {
    let server = github_mock().await;
    let store = store::connect("sqlite::memory:").await.unwrap();
    let config = CollectorConfig {
        owners: vec!["ghost".into()],
        ..CollectorConfig::default()
    };

    let summary = Collector::new(github(&server), store, config)
        .run()
        .await
        .unwrap();
    assert_eq!(summary.status, RunStatus::Failed);
    assert_eq!(summary.repos, 0);
}
