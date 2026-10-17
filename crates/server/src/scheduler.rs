//! Runs the collector periodically and on demand, one run at a time, and
//! tells live clients about runs and alert changes.

use crate::realtime::{Event, Hub};
use collector::Collector;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use store::{EventFilter, RunStatus, Store};
use tokio::sync::Notify;

pub struct Scheduler {
    collector: Collector,
    interval: Duration,
    trigger: Notify,
    running: AtomicBool,
    store: Arc<dyn Store>,
    hub: Arc<Hub>,
}

impl Scheduler {
    pub fn new(
        collector: Collector,
        interval: Duration,
        store: Arc<dyn Store>,
        hub: Arc<Hub>,
    ) -> Self {
        Self {
            collector,
            interval,
            trigger: Notify::new(),
            running: AtomicBool::new(false),
            store,
            hub,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Asks for a run as soon as possible. Requests arriving while a run is
    /// in progress collapse into a single follow-up run.
    pub fn request_run(&self) {
        self.trigger.notify_one();
    }

    /// The newest alert event ID, the starting point for announcements.
    async fn newest_event(&self) -> i64 {
        match self
            .store
            .alert_events(&EventFilter {
                limit: 1,
                include_baseline: true,
                ..Default::default()
            })
            .await
        {
            Ok(events) => events.first().map_or(0, |e| e.id),
            Err(error) => {
                tracing::warn!(%error, "could not read alert events");
                0
            }
        }
    }

    /// Announces the repositories with alert events after `watermark` and
    /// returns the new watermark.
    async fn announce_changes(&self, watermark: i64) -> i64 {
        let filter = EventFilter {
            after_id: Some(watermark),
            limit: 100_000,
            include_baseline: true,
            ..Default::default()
        };
        let events = match self.store.alert_events(&filter).await {
            Ok(events) => events,
            Err(error) => {
                tracing::warn!(%error, "could not read alert events");
                return watermark;
            }
        };
        let Some(newest) = events.iter().map(|e| e.id).max() else {
            return watermark;
        };
        let repositories: BTreeSet<String> = events
            .iter()
            .map(|e| format!("{}/{}", e.owner, e.repo))
            .collect();
        self.hub.publish(Event::AlertsChanged {
            repositories: repositories.into_iter().collect(),
            events: events.len(),
        });
        newest
    }

    /// Runs immediately, then every `interval` or whenever requested.
    pub async fn run_forever(self: Arc<Self>) {
        let mut watermark = self.newest_event().await;
        loop {
            self.running.store(true, Ordering::Relaxed);
            self.hub.publish(Event::RunStarted);
            let result = self.collector.run().await;
            // Not running any more before clients are told, so data they
            // reload in response already says so.
            self.running.store(false, Ordering::Relaxed);
            let finished = match &result {
                Ok(summary) => Event::RunFinished {
                    run: Some(summary.run.0),
                    status: summary.status,
                    repos: summary.repos,
                    errors: summary.errors.len(),
                },
                Err(error) => {
                    tracing::error!(%error, "collector run failed");
                    Event::RunFinished {
                        run: None,
                        status: RunStatus::Failed,
                        repos: 0,
                        errors: 1,
                    }
                }
            };
            watermark = self.announce_changes(watermark).await;
            self.hub.publish(finished);

            tokio::select! {
                () = tokio::time::sleep(self.interval) => {}
                () = self.trigger.notified() => tracing::info!("run requested"),
            }
        }
    }
}
