//! Repository listing and statistics.

use crate::client::GitHub;
use crate::{Error, Result, link};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;

const REPO_FIELDS: &str = r#"
fragment RepoFields on Repository {
  name
  owner { login __typename }
  url
  description
  isArchived
  isFork
  isPrivate
  primaryLanguage { name }
  stargazerCount
  forkCount
  pushedAt
  defaultBranchRef {
    name
    target { ... on Commit { committedDate history { totalCount } } }
  }
  issues(states: OPEN) { totalCount }
  pullRequests(states: OPEN) { totalCount }
  refs(refPrefix: "refs/tags/") { totalCount }
  releases { totalCount }
}
"#;

const OWNER_REPOS_QUERY: &str = r#"
query OwnerRepos($login: String!, $first: Int!, $after: String) {
  repositoryOwner(login: $login) {
    repositories(first: $first, after: $after, ownerAffiliations: [OWNER],
                 orderBy: { field: NAME, direction: ASC }) {
      pageInfo { hasNextPage endCursor }
      nodes { ...RepoFields }
    }
  }
}
"#;

const REPO_QUERY: &str = r#"
query Repo($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) { ...RepoFields }
}
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerKind {
    Organization,
    User,
}

/// Repository metadata and statistics, flattened from GraphQL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Repository {
    pub owner: String,
    pub owner_kind: OwnerKind,
    pub name: String,
    pub url: String,
    pub description: Option<String>,
    pub archived: bool,
    pub fork: bool,
    pub private: bool,
    pub language: Option<String>,
    pub default_branch: Option<String>,
    pub stars: i64,
    pub forks: i64,
    pub open_issues: i64,
    pub open_prs: i64,
    pub tags: i64,
    pub releases: i64,
    /// Commits on the default branch; `None` for empty repositories.
    pub commits: Option<i64>,
    pub last_commit_at: Option<DateTime<Utc>>,
    pub pushed_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepoNode {
    name: String,
    owner: OwnerNode,
    url: String,
    description: Option<String>,
    is_archived: bool,
    is_fork: bool,
    is_private: bool,
    primary_language: Option<NameNode>,
    stargazer_count: i64,
    fork_count: i64,
    pushed_at: Option<DateTime<Utc>>,
    default_branch_ref: Option<BranchNode>,
    issues: Count,
    pull_requests: Count,
    refs: Option<Count>,
    releases: Count,
}

#[derive(Deserialize)]
struct OwnerNode {
    login: String,
    #[serde(rename = "__typename")]
    typename: OwnerKind,
}

#[derive(Deserialize)]
struct NameNode {
    name: String,
}

#[derive(Deserialize)]
struct BranchNode {
    name: String,
    target: Option<CommitNode>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitNode {
    committed_date: Option<DateTime<Utc>>,
    history: Option<Count>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Count {
    total_count: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageInfo {
    has_next_page: bool,
    end_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnerReposData {
    repository_owner: Option<OwnerReposNode>,
}

#[derive(Deserialize)]
struct OwnerReposNode {
    repositories: RepoConnection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepoConnection {
    page_info: PageInfo,
    /// Entries the token may not read (e.g. repositories a GitHub App was
    /// not installed on) come back as `null`.
    nodes: Vec<Option<RepoNode>>,
}

#[derive(Deserialize)]
struct RepoData {
    repository: Option<RepoNode>,
}

impl From<RepoNode> for Repository {
    fn from(node: RepoNode) -> Self {
        let (default_branch, commit) = match node.default_branch_ref {
            Some(branch) => (Some(branch.name), branch.target),
            None => (None, None),
        };
        let (commits, last_commit_at) = match commit {
            Some(c) => (c.history.map(|h| h.total_count), c.committed_date),
            None => (None, None),
        };
        Self {
            owner: node.owner.login,
            owner_kind: node.owner.typename,
            name: node.name,
            url: node.url,
            description: node.description,
            archived: node.is_archived,
            fork: node.is_fork,
            private: node.is_private,
            language: node.primary_language.map(|l| l.name),
            default_branch,
            stars: node.stargazer_count,
            forks: node.fork_count,
            open_issues: node.issues.total_count,
            open_prs: node.pull_requests.total_count,
            tags: node.refs.map_or(0, |r| r.total_count),
            releases: node.releases.total_count,
            commits,
            last_commit_at,
            pushed_at: node.pushed_at,
        }
    }
}

fn is_not_found(e: &crate::GraphQlError) -> bool {
    e.kind.as_deref() == Some("NOT_FOUND")
}

/// Errors about a single entry of the repository list, which then is
/// `null`; the rest of the page is still valid.
fn is_about_one_repository(e: &crate::GraphQlError) -> bool {
    let path: Vec<_> = e.path.iter().take(3).filter_map(|p| p.as_str()).collect();
    is_not_found(e) || path == ["repositoryOwner", "repositories", "nodes"]
}

impl GitHub {
    /// All repositories owned by an organization or user, with statistics.
    ///
    /// `page_size` trades request count against GraphQL query cost; counting
    /// commit history is expensive on large repositories, so keep it modest.
    pub async fn owner_repositories(&self, login: &str, page_size: u32) -> Result<Vec<Repository>> {
        let query = format!("{OWNER_REPOS_QUERY}{REPO_FIELDS}");
        let mut repos = Vec::new();
        let mut hidden = 0;
        let mut after: Option<String> = None;
        loop {
            let data: Option<OwnerReposData> = self
                .graphql(
                    login,
                    &query,
                    json!({ "login": login, "first": page_size, "after": after }),
                    is_about_one_repository,
                )
                .await?;
            let owner = data
                .and_then(|d| d.repository_owner)
                .ok_or_else(|| Error::NotFound(format!("owner {login}")))?;
            let connection = owner.repositories;
            for node in connection.nodes {
                match node {
                    Some(node) => repos.push(Repository::from(node)),
                    None => hidden += 1,
                }
            }
            match connection.page_info {
                PageInfo {
                    has_next_page: true,
                    end_cursor: Some(cursor),
                } => after = Some(cursor),
                _ => {
                    if hidden > 0 {
                        tracing::info!(
                            owner = login,
                            hidden,
                            "repositories not visible to this token were skipped"
                        );
                    }
                    return Ok(repos);
                }
            }
        }
    }

    /// A single repository with statistics.
    pub async fn repository(&self, owner: &str, name: &str) -> Result<Repository> {
        let query = format!("{REPO_QUERY}{REPO_FIELDS}");
        let data: Option<RepoData> = self
            .graphql(
                owner,
                &query,
                json!({ "owner": owner, "name": name }),
                is_not_found,
            )
            .await?;
        data.and_then(|d| d.repository)
            .map(Repository::from)
            .ok_or_else(|| Error::NotFound(format!("repository {owner}/{name}")))
    }

    /// Number of contributors, anonymous ones included.
    ///
    /// Requests a single item per page and reads the count off the `last`
    /// link. Returns `None` when GitHub refuses to compute the list because
    /// the history is too large.
    pub async fn contributor_count(&self, owner: &str, name: &str) -> Result<Option<i64>> {
        let url = self.api_url(&format!(
            "/repos/{owner}/{name}/contributors?per_page=1&anon=1"
        ));
        let fetched = match self.get_cached(owner, &url).await {
            Ok(fetched) => fetched,
            Err(Error::Status {
                status: StatusCode::FORBIDDEN,
                message,
                ..
            }) if message.contains("too large") => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        if fetched.status == StatusCode::NO_CONTENT {
            return Ok(Some(0));
        }
        if let Some(last) = fetched.link.as_deref().and_then(link::last_page) {
            return Ok(Some(i64::try_from(last).unwrap_or(i64::MAX)));
        }
        let items: Vec<serde_json::Value> = serde_json::from_slice(&fetched.body)?;
        Ok(Some(items.len() as i64))
    }
}
