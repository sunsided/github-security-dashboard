//! Daily digest of alert changes.
//!
//! Every target keeps its own watermark (the last alert event it received)
//! in the store, so a failed delivery is made up for by the next one, and
//! adding a target doesn't replay history: its first digest covers the last
//! 24 hours. Days without news send nothing but are recorded, which tells a
//! restarted server that the day's digest is done.

mod config;
mod content;
mod render;
mod schedule;
mod send;

pub use config::{DigestConfig, TargetConfig, TargetKind};
pub use content::{Closed, Digest, Item, Totals};
pub use render::JSON_SCHEMA_VERSION;
pub use schedule::DailySlot;
pub use send::CloudEvent;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use std::sync::Arc;
use store::{DeliveryRecord, EventFilter, RepoFilter, SeverityCounts, Store};

/// Events in one digest at most; a day's worth is normally far below.
/// Beyond it, the digest covers the oldest events and the rest follow.
const MAX_EVENTS: u32 = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] store::StoreError),
    #[error("unknown digest target {0:?}")]
    UnknownTarget(String),
}

struct Target {
    config: TargetConfig,
    /// The webhook URL; never logged.
    url: String,
}

/// What happened for one target in a digest round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    Quiet { target: String },
    Sent { target: String, events: usize },
    Failed { target: String, error: String },
}

pub struct DigestService {
    store: Arc<dyn Store>,
    http: reqwest::Client,
    config: DigestConfig,
    targets: Vec<Target>,
    started_at: DateTime<Utc>,
    backoff: std::time::Duration,
    max_events: u32,
}

impl DigestService {
    /// `env` looks up the environment variables holding webhook URLs.
    pub fn new(
        store: Arc<dyn Store>,
        config: DigestConfig,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        config.validate()?;
        let targets = config
            .targets
            .iter()
            .map(|t| match env(&t.url_env).filter(|u| !u.trim().is_empty()) {
                Some(url) => Ok(Target {
                    config: t.clone(),
                    url: url.trim().to_owned(),
                }),
                None => Err(format!(
                    "environment variable {} (webhook URL of digest target {:?}) is not set",
                    t.url_env, t.name
                )),
            })
            .collect::<Result<_, _>>()?;
        let http = reqwest::Client::builder()
            .user_agent(concat!(
                "github-security-dashboard/",
                env!("CARGO_PKG_VERSION")
            ))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            store,
            http,
            config,
            targets,
            started_at: Utc::now(),
            backoff: std::time::Duration::from_secs(2),
            max_events: MAX_EVENTS,
        })
    }

    pub fn with_retry_backoff(mut self, backoff: std::time::Duration) -> Self {
        self.backoff = backoff;
        self
    }

    /// Lowers the per-digest event cap (10 000), e.g. to test truncation.
    pub fn with_event_cap(mut self, max_events: u32) -> Self {
        self.max_events = max_events.max(1);
        self
    }

    pub fn slot(&self) -> DailySlot {
        DailySlot {
            at: self.config.at,
            timezone: self.config.timezone,
        }
    }

    async fn totals(&self) -> Result<Totals, Error> {
        let repos = self.store.list_repos(&RepoFilter::default()).await?;
        let mut open = SeverityCounts::default();
        for repo in &repos {
            open.critical += repo.open_alerts.critical;
            open.high += repo.open_alerts.high;
            open.medium += repo.open_alerts.medium;
            open.low += repo.open_alerts.low;
        }
        Ok(Totals {
            open_alerts: open,
            repositories_with_alerts: repos.iter().filter(|r| r.open_alerts.total() > 0).count(),
        })
    }

    /// The digest `target` would receive now, without sending it.
    pub async fn preview(
        &self,
        target: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Option<Digest>, Error> {
        let name = match target {
            Some(name) => name.to_owned(),
            None => match self.targets.first() {
                Some(t) => t.config.name.clone(),
                None => return Ok(None),
            },
        };
        if !self.targets.iter().any(|t| t.config.name == name) {
            return Err(Error::UnknownTarget(name));
        }
        Ok(self.compose(&name, now).await?.0)
    }

    /// Builds the digest for a target from its watermark. Also returns the
    /// watermark to record if there's nothing to say.
    async fn compose(
        &self,
        target: &str,
        now: DateTime<Utc>,
    ) -> Result<(Option<Digest>, i64), Error> {
        let last = self.store.last_delivery(target).await?;
        let (filter, period_start, watermark) = match &last {
            Some(d) => (
                EventFilter {
                    after_id: Some(d.record.last_event_id),
                    ..Default::default()
                },
                d.record.attempted_at,
                d.record.last_event_id,
            ),
            None => {
                // A new target starts with the last day, not all of history.
                let since = now - Duration::hours(24);
                let newest = self
                    .store
                    .alert_events(&EventFilter {
                        limit: 1,
                        include_baseline: true,
                        ..Default::default()
                    })
                    .await?
                    .first()
                    .map_or(0, |e| e.id);
                (
                    EventFilter {
                        since: Some(since),
                        ..Default::default()
                    },
                    since,
                    newest,
                )
            }
        };
        // Oldest first: if the cap cuts, it cuts the newest events, and the
        // watermark (the last event included) leaves them for next time.
        // One more than fits tells whether anything is left over: exactly
        // `max_events` events are a full digest, not a truncated one.
        let mut events = self
            .store
            .alert_events(&EventFilter {
                limit: self.max_events + 1,
                include_baseline: false,
                oldest_first: true,
                ..filter
            })
            .await?;
        let truncated = events.len() > self.max_events as usize;
        events.truncate(self.max_events as usize);
        let totals = self.totals().await?;
        let digest = Digest::build(
            &events,
            period_start,
            now,
            totals,
            self.config.dashboard_url.clone(),
        )
        .map(|mut d| {
            d.truncated = truncated;
            d
        });
        Ok((digest, watermark))
    }

    /// Sends a digest to every target now, regardless of the schedule.
    pub async fn send_now(&self, now: DateTime<Utc>) -> Vec<Outcome> {
        let mut outcomes = Vec::new();
        for target in &self.targets {
            outcomes.push(self.send_to(target, now).await);
        }
        outcomes
    }

    async fn send_to(&self, target: &Target, now: DateTime<Utc>) -> Outcome {
        let name = target.config.name.clone();
        let (digest, watermark) = match self.compose(&name, now).await {
            Ok(composed) => composed,
            Err(e) => {
                return Outcome::Failed {
                    target: name,
                    error: e.to_string(),
                };
            }
        };

        let Some(digest) = digest else {
            // Nothing new: remember the day was handled.
            let marker = DeliveryRecord {
                target: name.clone(),
                attempted_at: now,
                first_event_id: watermark,
                last_event_id: watermark,
                events: 0,
                succeeded: true,
                error: None,
            };
            if let Err(e) = self.store.record_delivery(&marker).await {
                return Outcome::Failed {
                    target: name,
                    error: e.to_string(),
                };
            }
            tracing::info!(target = %name, "digest: nothing to report");
            return Outcome::Quiet { target: name };
        };

        let (body, kind) = match target.config.kind {
            TargetKind::Json => (render::json(&digest), "digest.v1"),
            TargetKind::Slack => (
                render::slack(&digest, self.config.timezone, self.config.max_items),
                "digest.slack.v1",
            ),
            TargetKind::Teams => (
                render::teams(&digest, self.config.timezone, self.config.max_items),
                "digest.teams.v1",
            ),
        };
        let event = CloudEvent {
            // Same events, same ID: a retried delivery can be deduplicated.
            id: format!("{name}-{}-{}", digest.first_event_id, digest.last_event_id),
            source: self.config.event_source.clone(),
            kind: format!("{}.{kind}", self.config.event_type_prefix),
            subject: name.clone(),
            time: now,
        };
        let result = send::deliver(&self.http, &target.url, &event, &body, self.backoff).await;

        let record = DeliveryRecord {
            target: name.clone(),
            attempted_at: now,
            first_event_id: digest.first_event_id,
            last_event_id: digest.last_event_id,
            events: digest.events as i64,
            succeeded: result.is_ok(),
            error: result.as_ref().err().map(|e| e.to_string()),
        };
        if let Err(e) = self.store.record_delivery(&record).await {
            tracing::error!(target = %name, error = %e, "could not record digest delivery");
        }
        match result {
            Ok(()) => {
                tracing::info!(target = %name, events = digest.events, headline = %digest.headline(), "digest sent");
                Outcome::Sent {
                    target: name,
                    events: digest.events,
                }
            }
            Err(e) => {
                tracing::warn!(target = %name, error = %e, "digest delivery failed");
                Outcome::Failed {
                    target: name,
                    error: e.to_string(),
                }
            }
        }
    }

    /// Sends to the targets whose digest for the most recent slot is still
    /// outstanding: after a missed slot (server down) as well as at the
    /// slot itself. A target without any delivery waits for the first slot
    /// after the server started, so starting up never sends unasked.
    pub async fn send_due(&self, now: DateTime<Utc>) -> Vec<Outcome> {
        let slot = self.slot().previous(now);
        let mut outcomes = Vec::new();
        for target in &self.targets {
            let last = match self.store.last_delivery(&target.config.name).await {
                Ok(last) => last,
                Err(e) => {
                    outcomes.push(Outcome::Failed {
                        target: target.config.name.clone(),
                        error: e.to_string(),
                    });
                    continue;
                }
            };
            let due = match last {
                Some(d) => d.record.attempted_at < slot,
                None => slot > self.started_at,
            };
            if due {
                outcomes.push(self.send_to(target, now).await);
            }
        }
        outcomes
    }

    /// Catches up on a missed slot, then sends at every slot.
    pub async fn run_forever(self: Arc<Self>) {
        let slot = self.slot();
        loop {
            self.send_due(Utc::now()).await;
            let next = slot.next(Utc::now());
            tracing::info!(next = %next, "next digest");
            let wait = (next - Utc::now()).to_std().unwrap_or_default();
            tokio::time::sleep(wait + std::time::Duration::from_secs(1)).await;
        }
    }
}
