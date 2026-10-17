//! `config.toml` schema.

use anyhow::{Context, bail};
use collector::CollectorConfig;
use gh::Secret;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Hostnames besides the loopback ones the server answers to, e.g. when
    /// a reverse proxy forwards requests for `dashboard.example.org`.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default = "default_poll_interval", with = "humantime_serde")]
    pub poll_interval: Duration,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub collector: CollectorConfig,
    #[serde(default)]
    pub scoring: Scoring,
}

/// Weights of open alerts per severity in a repository's risk score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Scoring {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

impl Default for Scoring {
    fn default() -> Self {
        Self {
            critical: 10,
            high: 5,
            medium: 2,
            low: 1,
        }
    }
}

impl Scoring {
    pub fn score(&self, counts: &store::SeverityCounts) -> i64 {
        self.critical * counts.critical
            + self.high * counts.high
            + self.medium * counts.medium
            + self.low * counts.low
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// `sqlite://path/to/file.db`; more backends to come.
    pub url: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            url: "sqlite://dashboard.db".into(),
        }
    }
}

/// Credentials never live in the config file itself, only the name of the
/// environment variable holding them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default = "default_token_env")]
    pub token_env: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token_env: default_token_env(),
        }
    }
}

impl AuthConfig {
    pub fn token(&self) -> anyhow::Result<Secret> {
        match std::env::var(&self.token_env) {
            Ok(token) if !token.trim().is_empty() => Ok(Secret::new(token.trim())),
            _ => bail!(
                "environment variable {} is not set; put a GitHub token there (see .env.example)",
                self.token_env
            ),
        }
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

fn default_poll_interval() -> Duration {
    Duration::from_secs(30 * 60)
}

fn default_token_env() -> String {
    "GITHUB_TOKEN".into()
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing {}", path.display()))
    }

    fn parse(text: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(text)?;
        if config.collector.owners.is_empty() && config.collector.external_repos.is_empty() {
            bail!("nothing to collect: set collector.owners and/or collector.external_repos");
        }
        if config.poll_interval < Duration::from_secs(60) {
            bail!("poll_interval must be at least one minute");
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    #[test]
    fn example_config_parses() {
        let config = Config::parse(include_str!("../../../config.example.toml")).unwrap();
        check!(!config.collector.owners.is_empty());
        check!(config.listen.ip().is_loopback());
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let config = Config::parse("[collector]\nowners = [\"acme\"]").unwrap();
        check!(config.listen == default_listen());
        check!(config.poll_interval == Duration::from_secs(1800));
        check!(config.storage.url == "sqlite://dashboard.db");
        check!(config.auth.token_env == "GITHUB_TOKEN");
        check!(config.collector.page_size == 25);
        check!(config.scoring == Scoring::default());
    }

    #[test]
    fn scores_weight_severities() {
        let counts = store::SeverityCounts {
            critical: 1,
            high: 2,
            medium: 0,
            low: 3,
        };
        check!(Scoring::default().score(&counts) == 10 + 2 * 5 + 3);
    }

    #[test]
    fn rejects_empty_and_invalid_configs() {
        check!(Config::parse("").is_err());
        check!(Config::parse("[collector]\nexternal_repos = [\"nope\"]").is_err());
        check!(Config::parse("typo = 1\n[collector]\nowners = [\"a\"]").is_err());
        check!(Config::parse("poll_interval = \"5s\"\n[collector]\nowners = [\"a\"]").is_err());
    }
}
