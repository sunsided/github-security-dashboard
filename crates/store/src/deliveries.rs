//! Digest deliveries: which events reached which target, and when.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One attempt to deliver a digest to a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub target: String,
    pub attempted_at: DateTime<Utc>,
    /// Range of alert event IDs the digest covered, inclusive.
    pub first_event_id: i64,
    pub last_event_id: i64,
    pub events: i64,
    pub succeeded: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    pub id: i64,
    #[serde(flatten)]
    pub record: DeliveryRecord,
}
