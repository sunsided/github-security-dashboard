//! `[digest]` settings.

use chrono::NaiveTime;
use chrono_tz::Tz;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DigestConfig {
    pub enabled: bool,
    /// Local time of the daily digest, `"HH:MM"`.
    #[serde(deserialize_with = "time_of_day")]
    pub at: NaiveTime,
    /// IANA time zone `at` is in, e.g. `"Europe/Berlin"`.
    #[serde(deserialize_with = "time_zone")]
    pub timezone: Tz,
    /// Where the dashboard is reachable, for links in the digest.
    pub dashboard_url: Option<String>,
    /// CloudEvents `source` attribute (a URI reference).
    pub event_source: String,
    /// Prefix of the CloudEvents `type` attribute; `.digest.v1` (JSON) or
    /// `.digest.slack.v1` (Slack message) is appended.
    pub event_type_prefix: String,
    /// Alerts listed per section before "and N more".
    pub max_items: usize,
    pub targets: Vec<TargetConfig>,
}

impl Default for DigestConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            at: NaiveTime::from_hms_opt(8, 0, 0).expect("valid time"),
            timezone: Tz::UTC,
            dashboard_url: None,
            event_source: "/github-security-dashboard".into(),
            event_type_prefix: "io.github.sunsided.security-dashboard".into(),
            max_items: 15,
            targets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    /// Identifies the target in logs and its delivery history.
    pub name: String,
    pub kind: TargetKind,
    /// Environment variable holding the webhook URL (it is a secret).
    pub url_env: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// Slack incoming webhook; the body is a Slack message.
    Slack,
    /// Any webhook; the body is the digest as JSON.
    Json,
}

impl DigestConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.targets.is_empty() {
            return Err("digest is enabled but has no [[digest.targets]]".into());
        }
        let mut names: Vec<&str> = self.targets.iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        if let Some(pair) = names.windows(2).find(|w| w[0] == w[1]) {
            return Err(format!("digest target name {:?} is used twice", pair[0]));
        }
        if self.max_items == 0 {
            return Err("digest.max_items must be at least 1".into());
        }
        Ok(())
    }
}

fn time_of_day<'de, D: Deserializer<'de>>(d: D) -> Result<NaiveTime, D::Error> {
    let text = String::deserialize(d)?;
    NaiveTime::parse_from_str(&text, "%H:%M")
        .map_err(|_| serde::de::Error::custom(format!("expected \"HH:MM\", got {text:?}")))
}

fn time_zone<'de, D: Deserializer<'de>>(d: D) -> Result<Tz, D::Error> {
    let text = String::deserialize(d)?;
    text.parse()
        .map_err(|_| serde::de::Error::custom(format!("unknown time zone {text:?}")))
}
