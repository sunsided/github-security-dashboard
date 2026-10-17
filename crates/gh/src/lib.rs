//! Minimal GitHub API client for the security dashboard.
//!
//! Covers exactly what the collector needs: repository statistics via
//! GraphQL, a handful of REST endpoints, rate limit handling and conditional
//! requests. Authentication is pluggable through [`TokenProvider`].

mod alerts;
mod auth;
mod client;
mod link;
mod repos;

pub use alerts::{AlertKind, AlertSeverity, AlertStatus, SecurityAlert};
pub use auth::{PatProvider, Secret, TokenProvider};
pub use client::{ClientConfig, GitHub, GraphQlError, RateLimit};
pub use link::{find_rel, last_page};
pub use repos::{OwnerKind, Repository};

use chrono::{DateTime, Utc};
use reqwest::StatusCode;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("GitHub returned {status} for {url}: {message}")]
    Status {
        status: StatusCode,
        url: String,
        message: String,
    },
    #[error("rate limit exhausted until {reset}")]
    RateLimited { reset: DateTime<Utc> },
    #[error("GraphQL errors: {}", .0.join("; "))]
    GraphQl(Vec<String>),
    #[error("{0} not found")]
    NotFound(String),
    #[error("unexpected response: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("authentication failed: {0}")]
    Auth(String),
}

impl Error {
    /// `403` or `404`, i.e. the token can't see this resource or the feature
    /// is disabled for the repository.
    pub fn is_inaccessible(&self) -> bool {
        matches!(
            self,
            Self::NotFound(_)
                | Self::Status {
                    status: StatusCode::FORBIDDEN | StatusCode::NOT_FOUND,
                    ..
                }
        )
    }
}
