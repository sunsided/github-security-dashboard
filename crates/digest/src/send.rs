//! Delivery as a CloudEvent in binary content mode: the event attributes
//! travel as `ce-*` headers, the payload is the body. Knative Eventing (and
//! any other CloudEvents consumer) can take the request as-is; Slack ignores
//! the extra headers.

use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use std::time::Duration;

const ATTEMPTS: u32 = 3;

/// CloudEvents 1.0 context attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudEvent {
    /// Unique per event from this source; retries reuse it so consumers
    /// can deduplicate.
    pub id: String,
    pub source: String,
    pub kind: String,
    pub subject: String,
    pub time: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("request failed: {0}")]
    Http(reqwest::Error),
    #[error("webhook answered {status}: {body}")]
    Status { status: StatusCode, body: String },
}

pub async fn deliver(
    http: &reqwest::Client,
    url: &str,
    event: &CloudEvent,
    body: &serde_json::Value,
    backoff: Duration,
) -> Result<(), DeliveryError> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let result = http
            .post(url)
            .header("ce-specversion", "1.0")
            .header("ce-id", &event.id)
            .header("ce-source", &event.source)
            .header("ce-type", &event.kind)
            .header("ce-subject", &event.subject)
            .header(
                "ce-time",
                event
                    .time
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            )
            .header("content-type", "application/json")
            .json(body)
            .send()
            .await;

        let error = match result {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                let status = response.status();
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok())
                    .map(Duration::from_secs);
                let text = response.text().await.unwrap_or_default();
                let error = DeliveryError::Status {
                    status,
                    body: text.chars().take(200).collect(),
                };
                let transient = status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS;
                if !transient || attempt >= ATTEMPTS {
                    return Err(error);
                }
                tokio::time::sleep(retry_after.unwrap_or(backoff * 2u32.pow(attempt - 1))).await;
                continue;
            }
            // Webhook URLs are secrets (Slack's especially): keep them out
            // of errors that end up in logs and the delivery history.
            Err(e) => DeliveryError::Http(e.without_url()),
        };
        if attempt >= ATTEMPTS {
            return Err(error);
        }
        tokio::time::sleep(backoff * 2u32.pow(attempt - 1)).await;
    }
}
