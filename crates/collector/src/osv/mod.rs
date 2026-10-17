//! Minimal client for the OSV vulnerability database (<https://osv.dev>).

mod cvss;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use store::Severity;

/// OSV accepts at most 1000 queries per batch.
const BATCH_SIZE: usize = 1000;

#[derive(Debug, thiserror::Error)]
pub enum OsvError {
    #[error("OSV request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("OSV returned {status} for {url}")]
    Status {
        status: reqwest::StatusCode,
        url: String,
    },
}

/// A dependency with an exact version, parsed from a package URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub purl: String,
    /// `npm/@sveltejs/kit`: ecosystem and name, without the version.
    pub package: String,
    pub version: String,
}

impl Dependency {
    /// Accepts purls with a concrete version only. Unresolved references
    /// (`@^4.17.0`, pnpm's `@catalog:`) would make OSV report every
    /// advisory ever published for the package.
    pub fn parse(purl: &str) -> Option<Self> {
        let rest = purl.strip_prefix("pkg:")?;
        let rest = rest.split(['?', '#']).next()?;
        let (package, version) = rest.rsplit_once('@')?;
        let version = percent_decode(version);
        let concrete = version.chars().next().is_some_and(|c| {
            c.is_ascii_digit()
                || (c == 'v' && version[1..].starts_with(|c: char| c.is_ascii_digit()))
        }) && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+_".contains(c));
        // The repository itself shows up as pkg:github/...; OSV has nothing on it.
        if !concrete || package.starts_with("github/") {
            return None;
        }
        Some(Self {
            purl: purl.to_owned(),
            package: percent_decode(package),
            version,
        })
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What the dashboard needs from an OSV advisory.
#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub severity: Severity,
    /// Where the severity came from: "GitHub", "CVSS 9.8", or "unknown".
    pub severity_basis: String,
    pub published: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct BatchResponse {
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnRef>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct VulnRef {
    id: String,
}

#[derive(Deserialize)]
struct Vuln {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    published: Option<DateTime<Utc>>,
    #[serde(default)]
    severity: Vec<VulnSeverity>,
    database_specific: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct VulnSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

/// Severity of an advisory: GitHub's label where the advisory has been
/// reviewed by GitHub (what Dependabot would show), otherwise the CVSS v3
/// base score, otherwise medium.
fn severity_of(vuln: &Vuln) -> (Severity, String) {
    let label = vuln
        .database_specific
        .as_ref()
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
        .and_then(|s| match s.to_ascii_uppercase().as_str() {
            "CRITICAL" => Some(Severity::Critical),
            "HIGH" => Some(Severity::High),
            "MODERATE" | "MEDIUM" => Some(Severity::Medium),
            "LOW" => Some(Severity::Low),
            _ => None,
        });
    if let Some(severity) = label {
        return (severity, "GitHub".into());
    }
    let score = vuln
        .severity
        .iter()
        .filter(|s| s.kind == "CVSS_V3")
        .find_map(|s| cvss::base_score(&s.score));
    match score {
        Some(score) => {
            let severity = if score >= 9.0 {
                Severity::Critical
            } else if score >= 7.0 {
                Severity::High
            } else if score >= 4.0 {
                Severity::Medium
            } else {
                Severity::Low
            };
            (severity, format!("CVSS {score:.1}"))
        }
        None => (Severity::Medium, "unknown".into()),
    }
}

pub struct OsvClient {
    http: reqwest::Client,
    api_url: String,
    /// Advisories change rarely; kept for the lifetime of the collector.
    advisories: Mutex<HashMap<String, Advisory>>,
}

impl OsvClient {
    pub fn new(api_url: impl Into<String>, user_agent: &str) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(user_agent)
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_default();
        Self {
            http,
            api_url: api_url.into().trim_end_matches('/').to_owned(),
            advisories: Mutex::default(),
        }
    }

    async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<reqwest::Response, OsvError> {
        let url = format!("{}{path}", self.api_url);
        let response = self.http.post(&url).json(&body).send().await?;
        if !response.status().is_success() {
            return Err(OsvError::Status {
                status: response.status(),
                url,
            });
        }
        Ok(response)
    }

    /// Advisory IDs affecting each dependency, in input order.
    pub async fn affected(&self, deps: &[Dependency]) -> Result<Vec<Vec<String>>, OsvError> {
        let mut results = Vec::with_capacity(deps.len());
        for chunk in deps.chunks(BATCH_SIZE) {
            let queries: Vec<_> = chunk
                .iter()
                .map(|d| json!({ "package": { "purl": d.purl } }))
                .collect();
            let batch: BatchResponse = self
                .post("/v1/querybatch", json!({ "queries": queries }))
                .await?
                .json()
                .await?;
            for (dep, result) in chunk.iter().zip(batch.results) {
                let mut ids: Vec<String> = result.vulns.into_iter().map(|v| v.id).collect();
                // Rare: a package with more advisories than fit one page.
                let mut token = result.next_page_token;
                while let Some(page_token) = token {
                    let page: BatchResponse = self
                        .post(
                            "/v1/querybatch",
                            json!({ "queries": [{ "package": { "purl": dep.purl }, "page_token": page_token }] }),
                        )
                        .await?
                        .json()
                        .await?;
                    let next = page.results.into_iter().next();
                    token = next.as_ref().and_then(|r| r.next_page_token.clone());
                    ids.extend(next.into_iter().flat_map(|r| r.vulns).map(|v| v.id));
                }
                results.push(ids);
            }
        }
        Ok(results)
    }

    /// Details of one advisory, cached.
    pub async fn advisory(&self, id: &str) -> Result<Advisory, OsvError> {
        if let Some(cached) = self.advisories.lock().unwrap().get(id) {
            return Ok(cached.clone());
        }
        let url = format!("{}/v1/vulns/{id}", self.api_url);
        let response = self.http.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(OsvError::Status {
                status: response.status(),
                url,
            });
        }
        let vuln: Vuln = response.json().await?;
        let (severity, severity_basis) = severity_of(&vuln);
        let summary = vuln
            .summary
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                vuln.details
                    .map(|d| d.lines().next().unwrap_or_default().to_owned())
            })
            .unwrap_or_default();
        let advisory = Advisory {
            id: vuln.id,
            summary,
            severity,
            severity_basis,
            published: vuln.published,
        };
        self.advisories
            .lock()
            .unwrap()
            .insert(id.to_owned(), advisory.clone());
        Ok(advisory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    #[test]
    fn parses_concrete_dependencies_only() {
        let dep = Dependency::parse("pkg:npm/%40sveltejs/kit@2.5.0").unwrap();
        check!(dep.package == "npm/@sveltejs/kit");
        check!(dep.version == "2.5.0");
        check!(Dependency::parse("pkg:cargo/digest@0.10.7").is_some());
        check!(Dependency::parse("pkg:golang/golang.org/x/net@v0.17.0").is_some());
        check!(
            Dependency::parse("pkg:pypi/django@4.2.1?arch=any")
                .unwrap()
                .version
                == "4.2.1"
        );

        for unresolved in [
            "pkg:npm/vite@catalog:",
            "pkg:npm/lodash@%5E4.17.0",
            "pkg:npm/lodash@~4.17.0",
            "pkg:npm/lodash@*",
            "pkg:npm/lodash",
            "pkg:github/sveltejs/kit@main",
            "not-a-purl",
        ] {
            check!(Dependency::parse(unresolved) == None, "{unresolved}");
        }
    }

    fn vuln(database_specific: serde_json::Value, severity: serde_json::Value) -> Vuln {
        serde_json::from_value(json!({
            "id": "X-1", "summary": "s",
            "database_specific": database_specific, "severity": severity
        }))
        .unwrap()
    }

    #[test]
    fn severity_prefers_github_then_cvss_then_medium() {
        let both = vuln(
            json!({ "severity": "MODERATE" }),
            json!([{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]),
        );
        check!(severity_of(&both) == (Severity::Medium, "GitHub".to_owned()));

        let cvss_only = vuln(
            json!({ "license": "CC0-1.0" }),
            json!([{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" }]),
        );
        check!(severity_of(&cvss_only) == (Severity::Medium, "CVSS 5.9".to_owned()));

        let critical = vuln(
            serde_json::Value::Null,
            json!([{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]),
        );
        check!(severity_of(&critical).0 == Severity::Critical);

        let nothing = vuln(serde_json::Value::Null, json!([]));
        check!(severity_of(&nothing) == (Severity::Medium, "unknown".to_owned()));
    }
}
