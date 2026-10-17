//! What a digest says, independent of where it goes.

use chrono::{DateTime, Utc};
use serde::Serialize;
use store::{AlertEvent, AlertSource, EventKind, Severity, SeverityCounts};

/// One alert worth naming in the digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Item {
    /// `owner/name`
    pub repository: String,
    pub source: AlertSource,
    pub title: String,
    pub severity: Severity,
    pub url: String,
    /// What happened: "opened", "reopened", or "high → critical".
    pub change: String,
    pub estimated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Closed {
    pub fixed: usize,
    pub dismissed: usize,
    /// No longer on GitHub (repository or feature gone).
    pub gone: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub open_alerts: SeverityCounts,
    pub repositories_with_alerts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Digest {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    /// Alert event IDs covered, inclusive.
    pub first_event_id: i64,
    pub last_event_id: i64,
    pub events: usize,
    /// Opened or reopened alerts, most severe first.
    pub new: Vec<Item>,
    /// Alerts whose severity went up, most severe first.
    pub escalated: Vec<Item>,
    pub closed: Closed,
    pub totals: Totals,
    pub dashboard_url: Option<String>,
}

fn rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

fn item(event: &AlertEvent, change: String) -> Item {
    Item {
        repository: format!("{}/{}", event.owner, event.repo),
        source: event.source,
        title: event.title.clone(),
        severity: event.severity,
        url: event.html_url.clone(),
        change,
        estimated: event.source == AlertSource::Osv,
    }
}

impl Digest {
    /// Summarizes `events` (any order, baseline events excluded by the
    /// caller). `None` when there is nothing to report.
    pub fn build(
        events: &[AlertEvent],
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        totals: Totals,
        dashboard_url: Option<String>,
    ) -> Option<Self> {
        let first_event_id = events.iter().map(|e| e.id).min()?;
        let last_event_id = events.iter().map(|e| e.id).max()?;

        let mut chronological: Vec<&AlertEvent> = events.iter().collect();
        chronological.sort_by_key(|e| e.id);

        let mut new = Vec::new();
        let mut escalated = Vec::new();
        let mut closed = Closed::default();
        for event in chronological {
            match event.kind {
                EventKind::Opened => new.push(item(event, "opened".into())),
                EventKind::Reopened => new.push(item(event, "reopened".into())),
                EventKind::SeverityChanged => {
                    let from = event
                        .old
                        .as_deref()
                        .and_then(|s| s.parse::<Severity>().ok());
                    let to = event
                        .new
                        .as_deref()
                        .and_then(|s| s.parse::<Severity>().ok());
                    if let (Some(from), Some(to)) = (from, to)
                        && rank(to) < rank(from)
                    {
                        escalated.push(item(event, format!("{from} → {to}")));
                    }
                }
                EventKind::Fixed => closed.fixed += 1,
                EventKind::Dismissed => closed.dismissed += 1,
                EventKind::Gone => closed.gone += 1,
            }
        }
        // Stable sort: equally severe alerts stay in the order they happened.
        new.sort_by_key(|i| rank(i.severity));
        escalated.sort_by_key(|i| rank(i.severity));

        Some(Self {
            period_start,
            period_end,
            first_event_id,
            last_event_id,
            events: events.len(),
            new,
            escalated,
            closed,
            totals,
            dashboard_url,
        })
    }

    /// One line for headers and notification previews.
    pub fn headline(&self) -> String {
        let mut parts = Vec::new();
        if !self.new.is_empty() {
            let critical = self
                .new
                .iter()
                .filter(|i| i.severity == Severity::Critical)
                .count();
            let mut part = format!(
                "{} new alert{}",
                self.new.len(),
                if self.new.len() == 1 { "" } else { "s" }
            );
            if critical > 0 {
                part.push_str(&format!(" ({critical} critical)"));
            }
            parts.push(part);
        }
        if !self.escalated.is_empty() {
            parts.push(format!("{} escalated", self.escalated.len()));
        }
        let closed = self.closed.fixed + self.closed.dismissed + self.closed.gone;
        if closed > 0 {
            parts.push(format!("{closed} closed"));
        }
        if parts.is_empty() {
            "no new or closed alerts".into()
        } else {
            parts.join(", ")
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use assert2::check;
    use store::{AlertId, RunId};

    pub(crate) fn event(
        id: i64,
        kind: EventKind,
        severity: Severity,
        old: Option<&str>,
        new: Option<&str>,
    ) -> AlertEvent {
        AlertEvent {
            id,
            alert_id: AlertId(id),
            run_id: RunId(1),
            at: "2026-10-17T06:00:00Z".parse().unwrap(),
            kind,
            old: old.map(str::to_owned),
            new: new.map(str::to_owned),
            baseline: false,
            owner: "acme".into(),
            repo: "api".into(),
            source: AlertSource::Dependabot,
            number: id,
            title: format!("advisory {id}"),
            severity,
            html_url: format!("https://github.com/acme/api/security/dependabot/{id}"),
        }
    }

    pub(crate) fn totals() -> Totals {
        Totals {
            open_alerts: SeverityCounts {
                critical: 1,
                high: 2,
                medium: 0,
                low: 0,
            },
            repositories_with_alerts: 2,
        }
    }

    fn build(events: &[AlertEvent]) -> Option<Digest> {
        Digest::build(
            events,
            "2026-10-16T06:00:00Z".parse().unwrap(),
            "2026-10-17T06:00:00Z".parse().unwrap(),
            totals(),
            None,
        )
    }

    #[test]
    fn nothing_to_report_without_events() {
        check!(build(&[]) == None);
    }

    #[test]
    fn sorts_new_alerts_by_severity_and_counts_closures() {
        use EventKind::*;
        use Severity::*;
        let digest = build(&[
            event(10, Opened, Low, None, Some("low")),
            event(11, Opened, Critical, None, Some("critical")),
            event(12, Reopened, High, Some("fixed"), Some("open")),
            event(
                13,
                SeverityChanged,
                Critical,
                Some("medium"),
                Some("critical"),
            ),
            event(14, SeverityChanged, Low, Some("high"), Some("low")),
            event(15, Fixed, High, Some("open"), Some("fixed")),
            event(16, Dismissed, Low, Some("open"), Some("dismissed")),
            event(17, Fixed, Medium, Some("open"), Some("fixed")),
        ])
        .unwrap();

        let new: Vec<_> = digest
            .new
            .iter()
            .map(|i| (i.severity, i.change.as_str()))
            .collect();
        check!(new == [(Critical, "opened"), (High, "reopened"), (Low, "opened")]);
        check!(digest.escalated.len() == 1, "downgrades are not news");
        check!(digest.escalated[0].change == "medium → critical");
        check!(
            digest.closed
                == Closed {
                    fixed: 2,
                    dismissed: 1,
                    gone: 0
                }
        );
        check!((digest.first_event_id, digest.last_event_id, digest.events) == (10, 17, 8));
        check!(digest.headline() == "3 new alerts (1 critical), 1 escalated, 3 closed");
    }

    #[test]
    fn a_day_of_only_good_news_still_reports() {
        let digest = build(&[event(5, EventKind::Fixed, Severity::High, None, None)]).unwrap();
        check!(digest.new.is_empty());
        check!(digest.headline() == "1 closed");
    }
}
