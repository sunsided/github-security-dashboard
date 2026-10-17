//! HTTP plumbing: authentication headers, rate limits, retries, ETag caching.

use crate::auth::TokenProvider;
use crate::{Error, Result};
use chrono::{DateTime, TimeZone, Utc};
use reqwest::header::{ETAG, HeaderMap, IF_NONE_MATCH, LINK, RETRY_AFTER};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const API_VERSION: &str = "2022-11-28";

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub api_url: String,
    pub graphql_url: String,
    pub user_agent: String,
    /// Longest wait for a primary rate limit reset before giving up.
    pub max_rate_limit_wait: Duration,
    /// Retries for server errors and secondary rate limits.
    pub max_retries: u32,
    /// Initial backoff for server errors; doubles per attempt.
    pub backoff: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.github.com".into(),
            graphql_url: "https://api.github.com/graphql".into(),
            user_agent: concat!("github-security-dashboard/", env!("CARGO_PKG_VERSION")).into(),
            max_rate_limit_wait: Duration::from_secs(15 * 60),
            max_retries: 3,
            backoff: Duration::from_secs(1),
        }
    }
}

/// Last observed state of one rate limit bucket (`core`, `graphql`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RateLimit {
    pub limit: i64,
    pub remaining: i64,
    pub reset: DateTime<Utc>,
}

/// A response body together with the headers callers care about.
#[derive(Debug, Clone)]
pub(crate) struct Fetched {
    pub status: StatusCode,
    pub link: Option<String>,
    pub body: Arc<[u8]>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    etag: String,
    fetched: Fetched,
}

pub struct GitHub {
    http: reqwest::Client,
    config: ClientConfig,
    tokens: Arc<dyn TokenProvider>,
    rate_limits: Mutex<HashMap<String, RateLimit>>,
    etags: Mutex<HashMap<String, CacheEntry>>,
}

#[derive(Serialize)]
struct GraphQlRequest<'a, V> {
    query: &'a str,
    variables: V,
}

#[derive(Deserialize)]
struct GraphQlResponse<T> {
    data: Option<T>,
    #[serde(default)]
    errors: Vec<GraphQlError>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GraphQlError {
    pub message: String,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub path: Vec<serde_json::Value>,
}

impl GitHub {
    pub fn new(config: ClientConfig, tokens: Arc<dyn TokenProvider>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(config.user_agent.clone())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self {
            http,
            config,
            tokens,
            rate_limits: Mutex::default(),
            etags: Mutex::default(),
        })
    }

    /// Lowest remaining quota across all buckets seen so far.
    pub fn rate_limit_remaining(&self) -> Option<i64> {
        self.rate_limits
            .lock()
            .unwrap()
            .values()
            .map(|r| r.remaining)
            .min()
    }

    pub fn rate_limits(&self) -> HashMap<String, RateLimit> {
        self.rate_limits.lock().unwrap().clone()
    }

    pub(crate) fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.config.api_url.trim_end_matches('/'), path)
    }

    /// Runs a GraphQL query. Errors in the response fail the call unless
    /// `tolerate` accepts every one of them, in which case partial data is
    /// returned.
    pub(crate) async fn graphql<V, T>(
        &self,
        owner: &str,
        query: &str,
        variables: V,
        tolerate: impl Fn(&GraphQlError) -> bool,
    ) -> Result<Option<T>>
    where
        V: Serialize,
        T: DeserializeOwned,
    {
        let body = serde_json::to_vec(&GraphQlRequest { query, variables })?;
        let url = self.config.graphql_url.clone();
        let response = self
            .execute(owner, |http| {
                http.request(Method::POST, &url)
                    .header("content-type", "application/json")
                    .body(body.clone())
            })
            .await?;
        let parsed: GraphQlResponse<T> = serde_json::from_slice(&response.bytes().await?)?;
        if parsed.errors.iter().any(|e| !tolerate(e)) {
            return Err(Error::GraphQl(
                parsed.errors.into_iter().map(|e| e.message).collect(),
            ));
        }
        Ok(parsed.data)
    }

    /// GET with conditional request support: a `304 Not Modified` replays
    /// the cached body and does not count against the rate limit.
    pub(crate) async fn get_cached(&self, owner: &str, url: &str) -> Result<Fetched> {
        let etag = self.etags.lock().unwrap().get(url).map(|e| e.etag.clone());
        let response = self
            .execute(owner, |http| {
                let request = http.get(url);
                match &etag {
                    Some(etag) => request.header(IF_NONE_MATCH, etag),
                    None => request,
                }
            })
            .await?;

        if response.status() == StatusCode::NOT_MODIFIED
            && let Some(entry) = self.etags.lock().unwrap().get(url)
        {
            return Ok(entry.fetched.clone());
        }

        let status = response.status();
        let new_etag = header_str(response.headers(), ETAG.as_str()).map(str::to_owned);
        let link = header_str(response.headers(), LINK.as_str()).map(str::to_owned);
        let body: Arc<[u8]> = response.bytes().await?.to_vec().into();
        let fetched = Fetched { status, link, body };
        if let Some(etag) = new_etag {
            self.etags.lock().unwrap().insert(
                url.to_owned(),
                CacheEntry {
                    etag,
                    fetched: fetched.clone(),
                },
            );
        }
        Ok(fetched)
    }

    /// Sends a request built by `build`, retrying on rate limits and server
    /// errors. Returns successful (2xx) and `304` responses; everything else
    /// becomes [`Error::Status`].
    async fn execute(
        &self,
        owner: &str,
        build: impl Fn(&reqwest::Client) -> RequestBuilder,
    ) -> Result<Response> {
        let mut attempt = 0;
        loop {
            let token = self.tokens.token(owner).await?;
            let response = build(&self.http)
                .bearer_auth(token.expose())
                .header("accept", "application/vnd.github+json")
                .header("x-github-api-version", API_VERSION)
                .send()
                .await?;
            self.record_rate_limit(response.headers());

            let status = response.status();
            if status.is_success() || status == StatusCode::NOT_MODIFIED {
                return Ok(response);
            }

            let url = response.url().to_string();
            let wait = self.retry_delay(&response, attempt)?;
            match wait {
                Some(wait) if attempt < self.config.max_retries => {
                    tracing::warn!(%url, %status, ?wait, attempt, "retrying GitHub request");
                    tokio::time::sleep(wait).await;
                    attempt += 1;
                }
                _ => {
                    let body = response.text().await.unwrap_or_default();
                    let message = serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| v.get("message")?.as_str().map(str::to_owned))
                        .unwrap_or(body);
                    return Err(Error::Status {
                        status,
                        url,
                        message,
                    });
                }
            }
        }
    }

    /// Decides whether and how long to wait before retrying.
    fn retry_delay(&self, response: &Response, attempt: u32) -> Result<Option<Duration>> {
        let status = response.status();
        let headers = response.headers();

        if matches!(
            status,
            StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
        ) {
            // Secondary rate limit: GitHub says exactly how long to back off.
            if let Some(secs) =
                header_str(headers, RETRY_AFTER.as_str()).and_then(|v| v.parse().ok())
            {
                return Ok(Some(Duration::from_secs(secs)));
            }
            // Primary rate limit exhausted: wait for the window to reset.
            if header_str(headers, "x-ratelimit-remaining") == Some("0")
                && let Some(reset) = header_i64(headers, "x-ratelimit-reset")
                    .and_then(|t| Utc.timestamp_opt(t, 0).single())
            {
                let wait =
                    (reset - Utc::now()).to_std().unwrap_or_default() + Duration::from_secs(1);
                if wait > self.config.max_rate_limit_wait {
                    return Err(Error::RateLimited { reset });
                }
                return Ok(Some(wait));
            }
            return Ok(None);
        }

        if status.is_server_error() {
            return Ok(Some(self.config.backoff * 2u32.saturating_pow(attempt)));
        }
        Ok(None)
    }

    fn record_rate_limit(&self, headers: &HeaderMap) {
        let (Some(limit), Some(remaining), Some(reset)) = (
            header_i64(headers, "x-ratelimit-limit"),
            header_i64(headers, "x-ratelimit-remaining"),
            header_i64(headers, "x-ratelimit-reset").and_then(|t| Utc.timestamp_opt(t, 0).single()),
        ) else {
            return;
        };
        let resource = header_str(headers, "x-ratelimit-resource")
            .unwrap_or("core")
            .to_owned();
        self.rate_limits.lock().unwrap().insert(
            resource,
            RateLimit {
                limit,
                remaining,
                reset,
            },
        );
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn header_i64(headers: &HeaderMap, name: &str) -> Option<i64> {
    header_str(headers, name)?.parse().ok()
}
