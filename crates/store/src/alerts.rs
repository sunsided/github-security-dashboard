//! Security alerts, their audit events, and the rules that derive one from
//! the other.

use crate::api::{RepoId, RunId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

crate::string_enum! {
    /// Where an alert comes from.
    pub enum AlertSource {
        Dependabot = "dependabot",
        CodeScanning = "code_scanning",
        SecretScanning = "secret_scanning",
        /// Estimated from the dependency graph and the OSV database, for
        /// repositories whose Dependabot alerts can't be read.
        Osv = "osv",
    }
}

impl AlertSource {
    /// The sources GitHub itself reports alerts for.
    pub const ALL: [Self; 3] = [Self::Dependabot, Self::CodeScanning, Self::SecretScanning];
}

crate::string_enum! {
    /// Normalized severity, most severe first.
    pub enum Severity {
        Critical = "critical",
        High = "high",
        Medium = "medium",
        Low = "low",
    }
}

crate::string_enum! {
    pub enum AlertState {
        Open = "open",
        Fixed = "fixed",
        /// Dismissed or resolved without a fix (false positive, won't fix, …).
        Dismissed = "dismissed",
        /// No longer retrievable, e.g. the repository or feature went away.
        Gone = "gone",
    }
}

crate::string_enum! {
    pub enum EventKind {
        Opened = "opened",
        Reopened = "reopened",
        SeverityChanged = "severity_changed",
        Fixed = "fixed",
        Dismissed = "dismissed",
        Gone = "gone",
    }
}

crate::string_enum! {
    /// Whether an alert source could be read for a repository.
    pub enum SourceStatus {
        Ok = "ok",
        /// Feature disabled, or the token may not read it (403/404).
        Unavailable = "unavailable",
        /// Deliberately not checked (e.g. archived repositories).
        Skipped = "skipped",
        Error = "error",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AlertId(pub i64);

/// An alert as observed on GitHub (or estimated, for external repositories).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRecord {
    pub source: AlertSource,
    /// GitHub's alert number, unique per repository and source.
    pub number: i64,
    pub state: AlertState,
    pub severity: Severity,
    pub title: String,
    /// Package, rule or secret type, depending on the source.
    pub location: Option<String>,
    pub html_url: String,
    pub created_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    /// Derived from a dependency scan rather than read from GitHub.
    pub estimated: bool,
    /// What the alert is an instance of: advisory IDs and aliases (GHSA,
    /// CVE, RUSTSEC) for dependency alerts, the rule ID for code scanning,
    /// the secret type for secret scanning.
    pub advisory_ids: Vec<String>,
    /// Package ecosystem of dependency alerts, see [`ecosystem_name`].
    pub ecosystem: Option<String>,
}

/// One name per package ecosystem, whether it came from GitHub (`rust`,
/// `pip`, `go`) or from a package URL (`cargo`, `pypi`, `golang`).
pub fn ecosystem_name(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "rust" | "cargo" | "crates.io" => "cargo".into(),
        "pip" | "pypi" => "pip".into(),
        "go" | "golang" => "go".into(),
        "rubygems" | "gem" => "rubygems".into(),
        "actions" | "github-actions" | "githubactions" => "actions".into(),
        other => other.to_owned(),
    }
}

/// An open alert together with the repository it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAlert {
    pub owner: String,
    pub repo: String,
    pub archived: bool,
    /// See [`crate::RepoOverview::last_seen_run`].
    pub repo_last_seen_run: RunId,
    #[serde(flatten)]
    pub alert: Alert,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub id: AlertId,
    pub repo_id: RepoId,
    #[serde(flatten)]
    pub record: AlertRecord,
    pub first_seen_run: RunId,
    pub last_seen_run: RunId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertEvent {
    pub id: i64,
    pub alert_id: AlertId,
    pub run_id: RunId,
    pub at: DateTime<Utc>,
    pub kind: EventKind,
    pub old: Option<String>,
    pub new: Option<String>,
    /// Recorded when the source was first read for this repository, i.e.
    /// describes a pre-existing alert rather than a change.
    pub baseline: bool,
    // Denormalized for display.
    pub owner: String,
    pub repo: String,
    pub source: AlertSource,
    pub number: i64,
    pub title: String,
    /// The alert's current severity and link (not as of the event).
    pub severity: Severity,
    pub html_url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFilter {
    pub repo: Option<RepoId>,
    pub since: Option<DateTime<Utc>>,
    /// Only events with a higher ID, i.e. recorded after that event.
    pub after_id: Option<i64>,
    /// Oldest first instead of newest first. With a `limit`, this keeps the
    /// events right after `after_id`, so a capped read can resume there.
    pub oldest_first: bool,
    pub limit: u32,
    /// Also return baseline events (see [`AlertEvent::baseline`]).
    pub include_baseline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSource {
    pub source: AlertSource,
    pub status: SourceStatus,
    pub message: Option<String>,
    pub checked_at: DateTime<Utc>,
    /// First run that read this source successfully; kept across failures.
    pub first_collected_run: Option<RunId>,
}

/// Open alerts per severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

impl SeverityCounts {
    pub fn total(&self) -> i64 {
        self.critical + self.high + self.medium + self.low
    }

    pub fn add(&mut self, severity: Severity, n: i64) {
        match severity {
            Severity::Critical => self.critical += n,
            Severity::High => self.high += n,
            Severity::Medium => self.medium += n,
            Severity::Low => self.low += n,
        }
    }
}

/// A change to record in the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub kind: EventKind,
    pub old: Option<String>,
    pub new: Option<String>,
}

/// Derives audit events from the previously stored and the newly observed
/// state of one alert. Backends call this so that all of them log the same
/// history for the same observations.
pub fn changes(previous: Option<&AlertRecord>, current: &AlertRecord) -> Vec<Change> {
    let event = |kind, old: Option<&str>, new: Option<&str>| Change {
        kind,
        old: old.map(str::to_owned),
        new: new.map(str::to_owned),
    };

    let Some(previous) = previous else {
        // Alerts first seen in a closed state carry no news.
        return match current.state {
            AlertState::Open => vec![event(
                EventKind::Opened,
                None,
                Some(current.severity.as_str()),
            )],
            _ => Vec::new(),
        };
    };

    let mut out = Vec::new();
    match (previous.state, current.state) {
        (AlertState::Open, AlertState::Open) => {}
        (_, AlertState::Open) => out.push(event(
            EventKind::Reopened,
            Some(previous.state.as_str()),
            Some(current.state.as_str()),
        )),
        (old, new) if old != new => {
            let kind = match new {
                AlertState::Fixed => EventKind::Fixed,
                AlertState::Dismissed => EventKind::Dismissed,
                AlertState::Gone | AlertState::Open => EventKind::Gone,
            };
            out.push(event(kind, Some(old.as_str()), Some(new.as_str())));
        }
        _ => {}
    }
    if previous.severity != current.severity && current.state == AlertState::Open {
        out.push(event(
            EventKind::SeverityChanged,
            Some(previous.severity.as_str()),
            Some(current.severity.as_str()),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;
    use chrono::TimeZone;

    fn alert(state: AlertState, severity: Severity) -> AlertRecord {
        AlertRecord {
            source: AlertSource::Dependabot,
            number: 1,
            state,
            severity,
            title: "x".into(),
            location: None,
            html_url: "https://github.com/a/b/security/dependabot/1".into(),
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            closed_at: None,
            estimated: false,
            advisory_ids: Vec::new(),
            ecosystem: None,
        }
    }

    fn kinds(changes: Vec<Change>) -> Vec<EventKind> {
        changes.into_iter().map(|c| c.kind).collect()
    }

    use AlertState::*;
    use Severity::*;

    #[test]
    fn new_alerts() {
        check!(kinds(changes(None, &alert(Open, High))) == [EventKind::Opened]);
        check!(changes(None, &alert(Fixed, High)).is_empty());
    }

    #[test]
    fn unchanged_alert_has_no_events() {
        check!(changes(Some(&alert(Open, High)), &alert(Open, High)).is_empty());
        check!(changes(Some(&alert(Fixed, High)), &alert(Fixed, High)).is_empty());
    }

    #[test]
    fn closing_and_reopening() {
        let fixed = changes(Some(&alert(Open, High)), &alert(Fixed, High));
        check!(fixed[0].kind == EventKind::Fixed);
        check!(fixed[0].old.as_deref() == Some("open"));
        check!(fixed[0].new.as_deref() == Some("fixed"));
        check!(
            kinds(changes(Some(&alert(Open, Low)), &alert(Dismissed, Low)))
                == [EventKind::Dismissed]
        );
        check!(kinds(changes(Some(&alert(Open, Low)), &alert(Gone, Low))) == [EventKind::Gone]);
        check!(
            kinds(changes(Some(&alert(Dismissed, Low)), &alert(Open, Low)))
                == [EventKind::Reopened]
        );
        check!(
            kinds(changes(Some(&alert(Fixed, Low)), &alert(Dismissed, Low)))
                == [EventKind::Dismissed]
        );
    }

    #[test]
    fn severity_changes_only_matter_while_open() {
        let c = changes(Some(&alert(Open, Medium)), &alert(Open, Critical));
        check!(kinds(c.clone()) == [EventKind::SeverityChanged]);
        check!((c[0].old.as_deref(), c[0].new.as_deref()) == (Some("medium"), Some("critical")));

        check!(
            kinds(changes(Some(&alert(Dismissed, Low)), &alert(Open, High)))
                == [EventKind::Reopened, EventKind::SeverityChanged]
        );
        check!(kinds(changes(Some(&alert(Open, Low)), &alert(Fixed, High))) == [EventKind::Fixed]);
    }

    #[test]
    fn ecosystems_get_one_name_each() {
        check!(ecosystem_name("rust") == "cargo");
        check!(ecosystem_name("cargo") == "cargo");
        check!(ecosystem_name("pypi") == "pip");
        check!(ecosystem_name("PIP") == "pip");
        check!(ecosystem_name("golang") == "go");
        check!(ecosystem_name("gem") == "rubygems");
        check!(ecosystem_name("npm") == "npm");
    }

    #[test]
    fn counts() {
        let mut c = SeverityCounts::default();
        c.add(Critical, 2);
        c.add(Low, 1);
        check!((c.critical, c.low, c.total()) == (2, 1, 3));
    }
}
