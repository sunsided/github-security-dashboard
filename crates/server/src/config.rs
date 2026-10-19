//! `config.toml` schema.

use anyhow::{Context, anyhow, bail};
use collector::CollectorConfig;
use gh::{AppProvider, ClientConfig, PatProvider, Secret, TokenProvider};
use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    #[serde(default)]
    pub digest: daily_digest::DigestConfig,
    #[serde(default)]
    pub realtime: crate::realtime::RealtimeConfig,
    /// Signing in to the dashboard; [`AuthConfig`] is about GitHub.
    #[serde(default)]
    pub login: crate::login::LoginConfig,
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

/// Credentials never live in the config file itself: tokens come from
/// environment variables, the App's private key from a file or variable.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Personal access token. Required without an App; with one, it serves
    /// owners the App is not installed for, if set.
    #[serde(default = "default_token_env")]
    pub token_env: String,
    pub app: Option<AppConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token_env: default_token_env(),
            app: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Numeric App ID or client ID (`Iv23…`).
    pub app_id: AppId,
    /// PEM file downloaded from the App settings; relative paths are
    /// resolved against the directory of the config file.
    pub private_key_path: Option<PathBuf>,
    /// Alternatively, the environment variable holding the PEM.
    pub private_key_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum AppId {
    Number(u64),
    Text(String),
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(n) => write!(f, "{n}"),
            Self::Text(s) => f.write_str(s),
        }
    }
}

impl AuthConfig {
    /// Builds the token provider. `env` looks up environment variables
    /// (injected so tests need not mutate the process environment).
    pub fn provider(
        &self,
        github: &ClientConfig,
        env: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Arc<dyn TokenProvider>> {
        let pat = env(&self.token_env)
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .map(|t| Arc::new(PatProvider::new(Secret::new(t))) as Arc<dyn TokenProvider>);

        let Some(app) = &self.app else {
            return pat.ok_or_else(|| {
                anyhow!(
                    "environment variable {} is not set; put a GitHub token there (see .env.example) \
                     or configure [auth.app]",
                    self.token_env
                )
            });
        };

        let pem = match (&app.private_key_path, &app.private_key_env) {
            (Some(path), None) => std::fs::read(path)
                .with_context(|| format!("reading GitHub App private key {}", path.display()))?,
            (None, Some(var)) => env(var)
                .with_context(|| format!("environment variable {var} is not set"))?
                .into_bytes(),
            _ => bail!("[auth.app] needs exactly one of private_key_path and private_key_env"),
        };
        let mut provider = AppProvider::new(
            app.app_id.to_string(),
            &pem,
            &github.api_url,
            &github.user_agent,
        )?;
        if let Some(pat) = pat {
            provider = provider.with_fallback(pat);
        }
        Ok(Arc::new(provider))
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
        let mut config =
            Self::parse(&text).with_context(|| format!("parsing {}", path.display()))?;
        if let Some(app) = &mut config.auth.app
            && let Some(key) = &mut app.private_key_path
            && key.is_relative()
            && let Some(dir) = path.parent()
        {
            *key = dir.join(&*key);
        }
        Ok(config)
    }

    fn parse(text: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(text)?;
        if config.collector.owners.is_empty() && config.collector.external_repos.is_empty() {
            bail!("nothing to collect: set collector.owners and/or collector.external_repos");
        }
        if config.poll_interval < Duration::from_secs(60) {
            bail!("poll_interval must be at least one minute");
        }
        config.digest.validate().map_err(|e| anyhow!(e))?;
        config.login.validate()?;
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
        check!(config.login.mode == crate::login::Mode::None);
    }

    #[test]
    fn digest_settings_are_validated() {
        let ok = Config::parse(
            "[collector]\nowners = [\"a\"]\n[digest]\nenabled = true\nat = \"07:30\"\ntimezone = \"Europe/Berlin\"\n\
             [[digest.targets]]\nname = \"s\"\nkind = \"slack\"\nurl_env = \"S\"",
        )
        .unwrap();
        check!(ok.digest.at.to_string() == "07:30:00");
        check!(ok.digest.timezone == chrono_tz::Europe::Berlin);

        for broken in [
            "[digest]\nenabled = true",
            "[digest]\nat = \"8 am\"",
            "[digest]\ntimezone = \"Mars/Olympus\"",
            "[digest]\nenabled = true\n[[digest.targets]]\nname = \"x\"\nkind = \"carrier-pigeon\"\nurl_env = \"X\"",
        ] {
            let text = format!("[collector]\nowners = [\"a\"]\n{broken}");
            check!(Config::parse(&text).is_err(), "{broken}");
        }
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
        check!(Config::parse("[login]\nmode = \"oidc\"\n[collector]\nowners = [\"a\"]").is_err());
    }

    const TEST_KEY: &str = include_str!("../../gh/tests/fixtures/test-app-key.pem");

    fn auth(toml_text: &str) -> AuthConfig {
        Config::parse(&format!("{toml_text}\n[collector]\nowners = [\"acme\"]"))
            .unwrap()
            .auth
    }

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }

    #[test]
    fn app_id_accepts_numbers_and_client_ids() {
        let numeric = auth("[auth.app]\napp_id = 123456\nprivate_key_env = \"KEY\"");
        check!(numeric.app.unwrap().app_id.to_string() == "123456");
        let client = auth("[auth.app]\napp_id = \"Iv23liabc\"\nprivate_key_env = \"KEY\"");
        check!(client.app.unwrap().app_id == AppId::Text("Iv23liabc".into()));
    }

    #[test]
    fn pat_is_required_without_an_app() {
        let github = ClientConfig::default();
        let err = auth("").provider(&github, env(&[])).err().unwrap();
        check!(err.to_string().contains("GITHUB_TOKEN"));
        check!(
            auth("")
                .provider(&github, env(&[("GITHUB_TOKEN", "ghp_x")]))
                .is_ok()
        );
        check!(
            auth("")
                .provider(&github, env(&[("GITHUB_TOKEN", "  ")]))
                .is_err(),
            "blank tokens count as missing"
        );
    }

    #[test]
    fn app_key_from_environment() {
        let github = ClientConfig::default();
        let config = auth("[auth.app]\napp_id = 1\nprivate_key_env = \"APP_KEY\"");
        check!(
            config
                .provider(&github, env(&[("APP_KEY", TEST_KEY)]))
                .is_ok(),
            "no PAT needed"
        );

        let missing = config.provider(&github, env(&[])).err().unwrap();
        check!(missing.to_string().contains("APP_KEY"));

        let garbage = config
            .provider(&github, env(&[("APP_KEY", "nope")]))
            .err()
            .unwrap();
        check!(garbage.to_string().contains("private key"));
    }

    #[test]
    fn app_key_source_must_be_unambiguous() {
        let github = ClientConfig::default();
        for both_or_neither in [
            "[auth.app]\napp_id = 1",
            "[auth.app]\napp_id = 1\nprivate_key_env = \"K\"\nprivate_key_path = \"k.pem\"",
        ] {
            let err = auth(both_or_neither)
                .provider(&github, env(&[("K", TEST_KEY)]))
                .err()
                .unwrap();
            check!(err.to_string().contains("exactly one"));
        }
    }

    #[test]
    fn relative_key_path_is_resolved_against_the_config_file() {
        let dir = std::env::temp_dir().join(format!("gsd-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.pem"), TEST_KEY).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[auth.app]\napp_id = 1\nprivate_key_path = \"app.pem\"\n[collector]\nowners = [\"acme\"]",
        )
        .unwrap();

        let config = Config::load(&config_path).unwrap();
        let resolved = config
            .auth
            .app
            .as_ref()
            .unwrap()
            .private_key_path
            .clone()
            .unwrap();
        check!(resolved == dir.join("app.pem"));
        check!(
            config
                .auth
                .provider(&ClientConfig::default(), env(&[]))
                .is_ok()
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
