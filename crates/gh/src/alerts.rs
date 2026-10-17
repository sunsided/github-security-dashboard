//! Dependabot, code scanning and secret scanning alerts.

use crate::client::GitHub;
use crate::{Result, link};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const PER_PAGE: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertKind {
    Dependabot,
    CodeScanning,
    SecretScanning,
}

impl AlertKind {
    pub const ALL: [Self; 3] = [Self::Dependabot, Self::CodeScanning, Self::SecretScanning];

    fn path(self) -> &'static str {
        match self {
            Self::Dependabot => "dependabot",
            Self::CodeScanning => "code-scanning",
            Self::SecretScanning => "secret-scanning",
        }
    }

    /// Extra query parameters for list requests.
    fn list_params(self) -> &'static str {
        match self {
            // Never transfer secret values; the dashboard has no use for them.
            Self::SecretScanning => "&hide_secret=true",
            _ => "",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AlertStatus {
    Open,
    Fixed,
    /// Dismissed, auto-dismissed, or resolved without a fix.
    Dismissed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// An alert flattened from any of the three APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityAlert {
    pub kind: AlertKind,
    pub owner: String,
    pub repo: String,
    pub number: i64,
    pub status: AlertStatus,
    /// `None` where GitHub assigns none (secret scanning).
    pub severity: Option<AlertSeverity>,
    pub title: String,
    pub location: Option<String>,
    pub html_url: String,
    pub created_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct RepoRef {
    name: String,
    owner: Login,
}

#[derive(Deserialize)]
struct Login {
    login: String,
}

#[derive(Deserialize)]
struct DependabotAlert {
    number: i64,
    state: String,
    html_url: String,
    created_at: DateTime<Utc>,
    fixed_at: Option<DateTime<Utc>>,
    dismissed_at: Option<DateTime<Utc>>,
    auto_dismissed_at: Option<DateTime<Utc>>,
    dependency: Dependency,
    security_advisory: Advisory,
    repository: Option<RepoRef>,
}

#[derive(Deserialize)]
struct Dependency {
    package: Option<Package>,
    manifest_path: Option<String>,
}

#[derive(Deserialize)]
struct Package {
    ecosystem: String,
    name: String,
}

#[derive(Deserialize)]
struct Advisory {
    summary: String,
    severity: String,
}

#[derive(Deserialize)]
struct CodeScanningAlert {
    number: i64,
    state: String,
    html_url: String,
    created_at: DateTime<Utc>,
    fixed_at: Option<DateTime<Utc>>,
    dismissed_at: Option<DateTime<Utc>>,
    rule: Rule,
    most_recent_instance: Option<Instance>,
    repository: Option<RepoRef>,
}

#[derive(Deserialize)]
struct Rule {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    security_severity_level: Option<String>,
}

#[derive(Deserialize)]
struct Instance {
    location: Option<Location>,
}

#[derive(Deserialize)]
struct Location {
    path: Option<String>,
}

/// Deliberately has no `secret` field: values are never deserialized.
#[derive(Deserialize)]
struct SecretScanningAlert {
    number: i64,
    state: String,
    resolution: Option<String>,
    html_url: String,
    created_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    secret_type: Option<String>,
    secret_type_display_name: Option<String>,
    repository: Option<RepoRef>,
}

fn severity(s: &str) -> Option<AlertSeverity> {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Some(AlertSeverity::Critical),
        "high" => Some(AlertSeverity::High),
        "medium" | "moderate" => Some(AlertSeverity::Medium),
        "low" => Some(AlertSeverity::Low),
        _ => None,
    }
}

fn repo_of(repository: Option<RepoRef>, owner: &str, repo: &str) -> (String, String) {
    repository.map_or_else(
        || (owner.to_owned(), repo.to_owned()),
        |r| (r.owner.login, r.name),
    )
}

impl DependabotAlert {
    fn flatten(self, owner: &str, repo: &str) -> SecurityAlert {
        let (owner, repo) = repo_of(self.repository, owner, repo);
        let location = match (self.dependency.package, self.dependency.manifest_path) {
            (Some(p), Some(m)) => Some(format!("{}/{} ({m})", p.ecosystem, p.name)),
            (Some(p), None) => Some(format!("{}/{}", p.ecosystem, p.name)),
            (None, m) => m,
        };
        SecurityAlert {
            kind: AlertKind::Dependabot,
            owner,
            repo,
            number: self.number,
            status: match self.state.as_str() {
                "open" => AlertStatus::Open,
                "fixed" => AlertStatus::Fixed,
                _ => AlertStatus::Dismissed,
            },
            severity: severity(&self.security_advisory.severity),
            title: self.security_advisory.summary,
            location,
            html_url: self.html_url,
            created_at: self.created_at,
            closed_at: self
                .fixed_at
                .or(self.dismissed_at)
                .or(self.auto_dismissed_at),
        }
    }
}

impl CodeScanningAlert {
    fn flatten(self, owner: &str, repo: &str) -> SecurityAlert {
        let (owner, repo) = repo_of(self.repository, owner, repo);
        let rule = self.rule;
        // Security queries carry a CVSS-derived level; plain code quality
        // findings only have error/warning/note, which rank below them.
        let severity = rule
            .security_severity_level
            .as_deref()
            .and_then(severity)
            .or(match rule.severity.as_deref() {
                Some("error") => Some(AlertSeverity::Medium),
                Some(_) => Some(AlertSeverity::Low),
                None => None,
            });
        let path = self
            .most_recent_instance
            .and_then(|i| i.location)
            .and_then(|l| l.path);
        SecurityAlert {
            kind: AlertKind::CodeScanning,
            owner,
            repo,
            number: self.number,
            status: match self.state.as_str() {
                "open" => AlertStatus::Open,
                "fixed" | "closed" => AlertStatus::Fixed,
                _ => AlertStatus::Dismissed,
            },
            severity,
            title: rule
                .description
                .or(rule.name)
                .or(rule.id.clone())
                .unwrap_or_else(|| "code scanning alert".into()),
            location: match (rule.id, path) {
                (Some(id), Some(path)) => Some(format!("{id} in {path}")),
                (id, path) => id.or(path),
            },
            html_url: self.html_url,
            created_at: self.created_at,
            closed_at: self.fixed_at.or(self.dismissed_at),
        }
    }
}

impl SecretScanningAlert {
    fn flatten(self, owner: &str, repo: &str) -> SecurityAlert {
        let (owner, repo) = repo_of(self.repository, owner, repo);
        SecurityAlert {
            kind: AlertKind::SecretScanning,
            owner,
            repo,
            number: self.number,
            status: match (self.state.as_str(), self.resolution.as_deref()) {
                ("open", _) => AlertStatus::Open,
                (_, Some("revoked")) => AlertStatus::Fixed,
                _ => AlertStatus::Dismissed,
            },
            severity: None,
            title: self
                .secret_type_display_name
                .or(self.secret_type.clone())
                .unwrap_or_else(|| "secret".into()),
            location: self.secret_type,
            html_url: self.html_url,
            created_at: self.created_at,
            closed_at: self.resolved_at,
        }
    }
}

fn flatten(
    kind: AlertKind,
    value: serde_json::Value,
    owner: &str,
    repo: &str,
) -> Result<SecurityAlert> {
    Ok(match kind {
        AlertKind::Dependabot => {
            serde_json::from_value::<DependabotAlert>(value)?.flatten(owner, repo)
        }
        AlertKind::CodeScanning => {
            serde_json::from_value::<CodeScanningAlert>(value)?.flatten(owner, repo)
        }
        AlertKind::SecretScanning => {
            serde_json::from_value::<SecretScanningAlert>(value)?.flatten(owner, repo)
        }
    })
}

impl GitHub {
    /// Open alerts of one kind across an organization. Requires the token
    /// to belong to an owner or security manager of the organization.
    pub async fn org_alerts(&self, org: &str, kind: AlertKind) -> Result<Vec<SecurityAlert>> {
        let url = self.api_url(&format!(
            "/orgs/{org}/{}/alerts?state=open&per_page={PER_PAGE}{}",
            kind.path(),
            kind.list_params()
        ));
        let items: Vec<serde_json::Value> = self.get_all_pages(org, url).await?;
        items
            .into_iter()
            .map(|v| flatten(kind, v, org, ""))
            .collect()
    }

    /// Open alerts of one kind in a repository.
    pub async fn repo_alerts(
        &self,
        owner: &str,
        repo: &str,
        kind: AlertKind,
    ) -> Result<Vec<SecurityAlert>> {
        let url = self.api_url(&format!(
            "/repos/{owner}/{repo}/{}/alerts?state=open&per_page={PER_PAGE}{}",
            kind.path(),
            kind.list_params()
        ));
        let items: Vec<serde_json::Value> = self.get_all_pages(owner, url).await?;
        items
            .into_iter()
            .map(|v| flatten(kind, v, owner, repo))
            .collect()
    }

    /// A single alert in whatever state it is in now.
    pub async fn repo_alert(
        &self,
        owner: &str,
        repo: &str,
        kind: AlertKind,
        number: i64,
    ) -> Result<SecurityAlert> {
        let mut url = self.api_url(&format!(
            "/repos/{owner}/{repo}/{}/alerts/{number}",
            kind.path()
        ));
        if kind == AlertKind::SecretScanning {
            url.push_str("?hide_secret=true");
        }
        let fetched = self.get_cached(owner, &url).await?;
        flatten(kind, serde_json::from_slice(&fetched.body)?, owner, repo)
    }

    /// Follows `rel="next"` links (page- or cursor-based) and concatenates
    /// the JSON arrays.
    async fn get_all_pages<T: DeserializeOwned>(
        &self,
        owner: &str,
        first: String,
    ) -> Result<Vec<T>> {
        let mut items = Vec::new();
        let mut next = Some(first);
        while let Some(url) = next {
            let fetched = self.get_cached(owner, &url).await?;
            let page: Vec<T> = serde_json::from_slice(&fetched.body)?;
            items.extend(page);
            next = fetched
                .link
                .as_deref()
                .and_then(|l| link::find_rel(l, "next"))
                .map(str::to_owned);
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;
    use serde_json::json;

    #[test]
    fn dependabot_alert() {
        let a = flatten(
            AlertKind::Dependabot,
            json!({
                "number": 7, "state": "auto_dismissed", "html_url": "https://h/7",
                "created_at": "2026-01-01T00:00:00Z", "fixed_at": null, "dismissed_at": null,
                "auto_dismissed_at": "2026-02-01T00:00:00Z",
                "dependency": { "package": { "ecosystem": "npm", "name": "vite" }, "manifest_path": "web/yarn.lock" },
                "security_advisory": { "summary": "Path traversal", "severity": "moderate" }
            }),
            "me",
            "repo",
        )
        .unwrap();
        check!((a.owner.as_str(), a.repo.as_str()) == ("me", "repo"));
        check!(a.status == AlertStatus::Dismissed);
        check!(a.severity == Some(AlertSeverity::Medium));
        check!(a.location.as_deref() == Some("npm/vite (web/yarn.lock)"));
        check!(a.closed_at.is_some());
    }

    #[test]
    fn code_scanning_severity_falls_back_to_rule_severity() {
        let alert = |rule: serde_json::Value| {
            flatten(
                AlertKind::CodeScanning,
                json!({
                    "number": 1, "state": "open", "html_url": "https://h/1",
                    "created_at": "2026-01-01T00:00:00Z", "fixed_at": null, "dismissed_at": null,
                    "rule": rule,
                    "most_recent_instance": { "location": { "path": "src/main.rs" } },
                    "repository": { "name": "api", "owner": { "login": "acme" } }
                }),
                "acme",
                "",
            )
            .unwrap()
        };
        let security = alert(
            json!({ "id": "js/xss", "severity": "error", "security_severity_level": "high", "description": "XSS" }),
        );
        check!(security.severity == Some(AlertSeverity::High));
        check!(security.repo == "api", "org endpoints name the repository");
        check!(security.location.as_deref() == Some("js/xss in src/main.rs"));

        let quality =
            alert(json!({ "id": "x", "severity": "warning", "security_severity_level": null }));
        check!(quality.severity == Some(AlertSeverity::Low));
    }

    #[test]
    fn secret_scanning_resolution() {
        let alert = |state: &str, resolution: Option<&str>| {
            flatten(
                AlertKind::SecretScanning,
                json!({
                    "number": 3, "state": state, "resolution": resolution, "html_url": "https://h/3",
                    "created_at": "2026-01-01T00:00:00Z", "resolved_at": null,
                    "secret_type": "github_personal_access_token",
                    "secret_type_display_name": "GitHub Personal Access Token",
                    "secret": "ghp_must_never_be_kept"
                }),
                "me",
                "repo",
            )
            .unwrap()
        };
        let open = alert("open", None);
        check!(open.status == AlertStatus::Open);
        check!(open.severity == None);
        check!(open.title == "GitHub Personal Access Token");
        check!(!format!("{open:?}").contains("ghp_must_never_be_kept"));
        check!(alert("resolved", Some("revoked")).status == AlertStatus::Fixed);
        check!(alert("resolved", Some("false_positive")).status == AlertStatus::Dismissed);
    }
}
