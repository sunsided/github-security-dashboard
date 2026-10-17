//! Runs the collector periodically and on demand, one run at a time.

use collector::Collector;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

pub struct Scheduler {
    collector: Collector,
    interval: Duration,
    trigger: Notify,
    running: AtomicBool,
}

impl Scheduler {
    pub fn new(collector: Collector, interval: Duration) -> Self {
        Self {
            collector,
            interval,
            trigger: Notify::new(),
            running: AtomicBool::new(false),
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

    /// Runs immediately, then every `interval` or whenever requested.
    pub async fn run_forever(self: Arc<Self>) {
        loop {
            self.running.store(true, Ordering::Relaxed);
            if let Err(error) = self.collector.run().await {
                tracing::error!(%error, "collector run failed");
            }
            self.running.store(false, Ordering::Relaxed);

            tokio::select! {
                () = tokio::time::sleep(self.interval) => {}
                () = self.trigger.notified() => tracing::info!("run requested"),
            }
        }
    }
}
