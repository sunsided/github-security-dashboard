//! Live updates for the UI over a WebSocket.
//!
//! A client first obtains a short-lived connection token from
//! `POST /api/realtime/token` (an HS256 JWT in Centrifugo's connection-token
//! format), opens `GET /api/realtime`, and sends the token as its first
//! message. Browsers can't set headers on WebSocket connections, so the
//! token travels in the protocol instead; authentication added in front of
//! the token endpoint later therefore covers the live connection as well.
//!
//! Protocol (JSON text frames):
//! - client: `{"connect":{"token":…}}` first, `{"refresh":{"token":…}}` before
//!   the token expires;
//! - server: `{"connected":{"expires_at":…}}`, `{"refreshed":{"expires_at":…}}`,
//!   `{"event":{"type":…}}`, and `{"resync":{}}` when the client fell behind.
//!
//! Events are hints: clients fetch the data itself from the REST API.

use crate::guard::AllowedHosts;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, TimeZone, Utc};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use store::RunStatus;
use tokio::sync::broadcast;
use tokio::time::Instant;

/// Close codes (application range 4000-4999).
pub mod close {
    /// Unexpected or malformed message.
    pub const PROTOCOL: u16 = 4000;
    /// Token missing, malformed or with a bad signature.
    pub const INVALID_TOKEN: u16 = 4001;
    /// Token expired, at connect time or later without a refresh.
    pub const TOKEN_EXPIRED: u16 = 4002;
    /// No token within the connect timeout.
    pub const CONNECT_TIMEOUT: u16 = 4008;
}

const PING_INTERVAL: Duration = Duration::from_secs(25);
/// A connection that hasn't answered pings for this long is dropped.
const PONG_TIMEOUT: Duration = Duration::from_secs(60);
/// Events a slow client may lag behind before it's told to resync.
const BACKLOG: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RealtimeConfig {
    /// Lifetime of a connection token.
    #[serde(with = "humantime_serde")]
    pub token_ttl: Duration,
    /// Time a client has to send its token after connecting.
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    /// Environment variable holding the HMAC signing key (e.g. one shared
    /// with Centrifugo's `token_hmac_secret_key`). Without it, a random key
    /// is generated per process: tokens then don't survive a restart, which
    /// clients handle by fetching a new one.
    pub signing_key_env: Option<String>,
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        Self {
            token_ttl: Duration::from_secs(5 * 60),
            connect_timeout: Duration::from_secs(10),
            signing_key_env: None,
        }
    }
}

/// Something clients may want to reload data for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type")]
pub enum Event {
    #[serde(rename = "run.started")]
    RunStarted,
    #[serde(rename = "run.finished")]
    RunFinished {
        run: Option<i64>,
        status: RunStatus,
        repos: usize,
        errors: usize,
    },
    #[serde(rename = "alerts.changed")]
    AlertsChanged {
        /// `owner/name` of every repository with alert events.
        repositories: Vec<String>,
        events: usize,
    },
    #[serde(rename = "digest.delivered")]
    DigestDelivered {
        target: String,
        /// `sent`, `quiet` or `failed`.
        outcome: String,
    },
}

/// Centrifugo connection-token claims. An empty `sub` is an anonymous user;
/// once authentication exists it carries the user ID.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
}

#[derive(Debug, PartialEq, Eq)]
enum TokenError {
    Invalid,
    Expired,
}

pub struct Hub {
    events: broadcast::Sender<Event>,
    encoding: EncodingKey,
    decoding: DecodingKey,
    config: RealtimeConfig,
    allowed_hosts: AllowedHosts,
}

#[derive(Serialize)]
pub struct IssuedToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

impl Hub {
    /// `key` is the HMAC secret; see [`Hub::random_key`].
    pub fn new(config: RealtimeConfig, key: &[u8], allowed_hosts: AllowedHosts) -> Self {
        let (events, _) = broadcast::channel(BACKLOG);
        Self {
            events,
            encoding: EncodingKey::from_secret(key),
            decoding: DecodingKey::from_secret(key),
            config,
            allowed_hosts,
        }
    }

    pub fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("the OS provides randomness");
        key
    }

    /// Tells every connected client. Without clients this is a no-op.
    pub fn publish(&self, event: Event) {
        let _ = self.events.send(event);
    }

    pub fn issue_token(&self, now: DateTime<Utc>) -> IssuedToken {
        let expires_at = now
            + chrono::Duration::from_std(self.config.token_ttl)
                .unwrap_or(chrono::Duration::minutes(5));
        let claims = Claims {
            sub: String::new(),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
        };
        let token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .expect("HS256 signing doesn't fail");
        IssuedToken {
            token,
            expires_at: Utc
                .timestamp_opt(claims.exp, 0)
                .single()
                .unwrap_or(expires_at),
        }
    }

    /// The token's expiry if it is valid now.
    fn verify(&self, token: &str) -> Result<DateTime<Utc>, TokenError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = 0;
        validation.required_spec_claims = ["exp".to_owned()].into();
        match jsonwebtoken::decode::<Claims>(token, &self.decoding, &validation) {
            Ok(data) => Utc
                .timestamp_opt(data.claims.exp, 0)
                .single()
                .ok_or(TokenError::Invalid),
            Err(e) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) => {
                Err(TokenError::Expired)
            }
            Err(_) => Err(TokenError::Invalid),
        }
    }

    /// Browsers send `Origin` on WebSocket upgrades but don't apply CORS to
    /// them, so a foreign page could otherwise open a socket here.
    fn origin_allowed(&self, headers: &HeaderMap) -> bool {
        let Some(origin) = headers.get(header::ORIGIN).and_then(|o| o.to_str().ok()) else {
            // Non-browser clients; they still need a token.
            return true;
        };
        let host = origin
            .split_once("://")
            .map_or(origin, |(_, rest)| rest)
            .split('/')
            .next()
            .unwrap_or_default();
        self.allowed_hosts.allows_host(host)
    }
}

pub async fn token(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    axum::Json(hub.issue_token(Utc::now()))
}

pub async fn connect(
    State(hub): State<Arc<Hub>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !hub.origin_allowed(&headers) {
        tracing::warn!(origin = ?headers.get(header::ORIGIN), "rejected WebSocket from foreign origin");
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    upgrade.on_upgrade(move |socket| session(socket, hub))
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ClientMessage {
    Connect { token: String },
    Refresh { token: String },
}

fn parse(message: &Message) -> Option<ClientMessage> {
    match message {
        Message::Text(text) => serde_json::from_str(text).ok(),
        _ => None,
    }
}

fn frame(value: serde_json::Value) -> Message {
    Message::Text(Utf8Bytes::from(value.to_string()))
}

async fn close(socket: &mut (impl SinkExt<Message> + Unpin), code: u16, reason: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: Utf8Bytes::from_static(reason),
        })))
        .await;
}

fn token_close(error: TokenError) -> (u16, &'static str) {
    match error {
        TokenError::Expired => (close::TOKEN_EXPIRED, "token expired"),
        TokenError::Invalid => (close::INVALID_TOKEN, "invalid token"),
    }
}

async fn session(socket: WebSocket, hub: Arc<Hub>) {
    let (mut sink, mut stream) = socket.split();

    // 1. The first message must be a valid connect.
    let first = tokio::time::timeout(hub.config.connect_timeout, stream.next()).await;
    let mut expires_at = match first {
        Err(_) => return close(&mut sink, close::CONNECT_TIMEOUT, "no token received").await,
        Ok(None | Some(Err(_))) => return,
        Ok(Some(Ok(message))) => match parse(&message) {
            Some(ClientMessage::Connect { token }) => match hub.verify(&token) {
                Ok(expires_at) => expires_at,
                Err(e) => {
                    let (code, reason) = token_close(e);
                    return close(&mut sink, code, reason).await;
                }
            },
            _ => return close(&mut sink, close::PROTOCOL, "expected connect").await,
        },
    };
    // Subscribe before confirming, so no event between the two is lost.
    let mut events = hub.events.subscribe();
    if sink
        .send(frame(
            serde_json::json!({ "connected": { "expires_at": expires_at } }),
        ))
        .await
        .is_err()
    {
        return;
    }

    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;
    let mut last_pong = Instant::now();

    loop {
        let until_expiry = (expires_at - Utc::now()).to_std().unwrap_or_default();
        tokio::select! {
            event = events.recv() => {
                let message = match event {
                    Ok(event) => serde_json::json!({ "event": event }),
                    Err(broadcast::error::RecvError::Lagged(_)) => serde_json::json!({ "resync": {} }),
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if sink.send(frame(message)).await.is_err() {
                    break;
                }
            }
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Pong(_))) => last_pong = Instant::now(),
                // Pings are answered by the WebSocket implementation.
                Some(Ok(Message::Ping(_))) => {}
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(message)) => match parse(&message) {
                    Some(ClientMessage::Refresh { token }) => match hub.verify(&token) {
                        Ok(new_expiry) => {
                            expires_at = new_expiry;
                            let reply = serde_json::json!({ "refreshed": { "expires_at": expires_at } });
                            if sink.send(frame(reply)).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            let (code, reason) = token_close(e);
                            close(&mut sink, code, reason).await;
                            break;
                        }
                    },
                    _ => {
                        close(&mut sink, close::PROTOCOL, "unexpected message").await;
                        break;
                    }
                },
            },
            () = tokio::time::sleep(until_expiry) => {
                close(&mut sink, close::TOKEN_EXPIRED, "token expired").await;
                break;
            }
            _ = ping.tick() => {
                if last_pong.elapsed() > PONG_TIMEOUT {
                    close(&mut sink, close::PROTOCOL, "no pong").await;
                    break;
                }
                if sink.send(Message::Ping(Default::default())).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    fn hub(ttl: Duration) -> Hub {
        Hub::new(
            RealtimeConfig {
                token_ttl: ttl,
                ..RealtimeConfig::default()
            },
            b"test key",
            AllowedHosts::new(&["dashboard.example".into()]),
        )
    }

    #[test]
    fn issued_tokens_verify_until_they_expire() {
        let hub = hub(Duration::from_secs(300));
        let now = Utc::now();
        let issued = hub.issue_token(now);
        check!(hub.verify(&issued.token) == Ok(issued.expires_at));
        check!((issued.expires_at - now).num_seconds() >= 299);

        let old = hub.issue_token(now - chrono::Duration::minutes(10));
        check!(hub.verify(&old.token) == Err(TokenError::Expired));
    }

    #[test]
    fn foreign_or_garbled_tokens_are_invalid() {
        let hub = hub(Duration::from_secs(300));
        let other = Hub::new(
            RealtimeConfig::default(),
            b"another key",
            AllowedHosts::new(&[]),
        );
        check!(hub.verify(&other.issue_token(Utc::now()).token) == Err(TokenError::Invalid));
        check!(hub.verify("not.a.jwt") == Err(TokenError::Invalid));
    }

    #[test]
    fn tokens_carry_centrifugo_claims() {
        let issued = hub(Duration::from_secs(60)).issue_token(Utc::now());
        let claims = jsonwebtoken::decode::<serde_json::Value>(
            &issued.token,
            &DecodingKey::from_secret(b"test key"),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap()
        .claims;
        check!(claims["sub"] == "");
        check!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap() == 60);
    }

    #[test]
    fn origins_follow_the_host_allowlist() {
        let hub = hub(Duration::from_secs(60));
        let headers = |origin: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::ORIGIN, origin.parse().unwrap());
            h
        };
        check!(hub.origin_allowed(&headers("http://localhost:5173")));
        check!(hub.origin_allowed(&headers("https://dashboard.example")));
        check!(!hub.origin_allowed(&headers("https://evil.example")));
        check!(
            hub.origin_allowed(&HeaderMap::new()),
            "non-browser clients still need a token"
        );
    }

    #[test]
    fn events_serialize_with_a_type() {
        let event = Event::AlertsChanged {
            repositories: vec!["acme/api".into()],
            events: 2,
        };
        check!(
            serde_json::to_value(&event).unwrap()
                == serde_json::json!({
                    "type": "alerts.changed", "repositories": ["acme/api"], "events": 2
                })
        );
    }
}
