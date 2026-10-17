//! Authentication as a GitHub App.

use crate::auth::{Secret, TokenProvider};
use crate::{Error, Result, link};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Installation tokens live for an hour; renew them this long before.
const RENEW_BEFORE: Duration = Duration::minutes(5);
/// How long the installation list is trusted before it is fetched again.
const INSTALLATIONS_TTL: Duration = Duration::minutes(10);
/// Minimum age of the installation list before an unknown owner refreshes it.
const UNKNOWN_OWNER_RETRY: Duration = Duration::minutes(1);

#[derive(Serialize)]
struct Claims<'a> {
    iat: i64,
    exp: i64,
    iss: &'a str,
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
    account: Option<Account>,
}

/// A user or organization (`login`), or an enterprise (`slug`, no login).
#[derive(Deserialize)]
struct Account {
    login: Option<String>,
    slug: Option<String>,
}

/// Decodes a JSON body, keeping serde's explanation ("missing field
/// `login` at line 1 column 312") instead of reqwest's generic message.
async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let url = response.url().to_string();
    let body = response.bytes().await?;
    serde_json::from_slice(&body)
        .map_err(|e| Error::Auth(format!("unexpected response from {url}: {e}")))
}

#[derive(Deserialize)]
struct AccessToken {
    token: String,
    expires_at: DateTime<Utc>,
}

#[derive(Default)]
struct Cache {
    /// Lowercased account login to installation id, and when it was fetched.
    installations: Option<(DateTime<Utc>, HashMap<String, u64>)>,
    tokens: HashMap<u64, (Secret, DateTime<Utc>)>,
}

/// Issues installation tokens for whichever installation covers an owner.
///
/// Owners without an installation (typically external repositories) use the
/// fallback provider if one is set, and otherwise any installation's token,
/// which is enough to read public data.
pub struct AppProvider {
    http: reqwest::Client,
    api_url: String,
    app_id: String,
    key: EncodingKey,
    fallback: Option<Arc<dyn TokenProvider>>,
    cache: Mutex<Cache>,
}

impl AppProvider {
    /// `app_id` is the numeric App ID or the client ID (`Iv23…`); GitHub
    /// accepts either as JWT issuer. `private_key_pem` is the PKCS#1 or
    /// PKCS#8 PEM downloaded from the App settings.
    pub fn new(
        app_id: impl Into<String>,
        private_key_pem: &[u8],
        api_url: impl Into<String>,
        user_agent: &str,
    ) -> Result<Self> {
        let key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|e| Error::Auth(format!("invalid GitHub App private key: {e}")))?;
        let http = reqwest::Client::builder()
            .user_agent(user_agent)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http,
            api_url: api_url.into().trim_end_matches('/').to_owned(),
            app_id: app_id.into(),
            key,
            fallback: None,
            cache: Mutex::default(),
        })
    }

    /// Tokens for owners without an installation come from `fallback`.
    pub fn with_fallback(mut self, fallback: Arc<dyn TokenProvider>) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// A JWT identifying the App itself, valid for nine minutes. Issued a
    /// minute in the past to tolerate clock drift, as GitHub recommends.
    fn jwt(&self) -> Result<String> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            iat: now - 60,
            exp: now + 9 * 60,
            iss: &self.app_id,
        };
        jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.key)
            .map_err(|e| Error::Auth(format!("signing App JWT: {e}")))
    }

    async fn app_request(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let response = request
            .bearer_auth(self.jwt()?)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .send()
            .await?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let url = response.url().to_string();
        let body = response.text().await.unwrap_or_default();
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("message")?.as_str().map(str::to_owned))
            .unwrap_or(body);
        Err(Error::Status {
            status,
            url,
            message,
        })
    }

    async fn fetch_installations(&self) -> Result<HashMap<String, u64>> {
        let mut map = HashMap::new();
        let mut next = Some(format!("{}/app/installations?per_page=100", self.api_url));
        while let Some(url) = next {
            let response = self.app_request(self.http.get(&url)).await?;
            next = response
                .headers()
                .get(reqwest::header::LINK)
                .and_then(|v| v.to_str().ok())
                .and_then(|l| link::find_rel(l, "next"))
                .map(str::to_owned);
            for installation in decode::<Vec<Installation>>(response).await? {
                // Enterprise installations have no login and own no
                // repositories directly; their organizations install the
                // App themselves.
                match installation.account {
                    Some(Account {
                        login: Some(login), ..
                    }) => {
                        map.insert(login.to_lowercase(), installation.id);
                    }
                    Some(Account {
                        slug: Some(slug), ..
                    }) => {
                        tracing::debug!(%slug, "skipping enterprise installation");
                    }
                    _ => {}
                }
            }
        }
        tracing::info!(installations = map.len(), "loaded GitHub App installations");
        Ok(map)
    }

    async fn installation_token(&self, cache: &mut Cache, id: u64) -> Result<Secret> {
        if let Some((token, expires)) = cache.tokens.get(&id)
            && *expires - Utc::now() > RENEW_BEFORE
        {
            return Ok(token.clone());
        }
        let url = format!("{}/app/installations/{id}/access_tokens", self.api_url);
        let token: AccessToken = decode(self.app_request(self.http.post(&url)).await?).await?;
        let secret = Secret::new(token.token);
        cache.tokens.insert(id, (secret.clone(), token.expires_at));
        Ok(secret)
    }
}

#[async_trait]
impl TokenProvider for AppProvider {
    fn label(&self) -> &'static str {
        "GitHub App"
    }

    async fn token(&self, owner: &str) -> Result<Secret> {
        let mut cache = self.cache.lock().await;
        let owner = owner.to_lowercase();

        // Refresh when the list is missing or old. An unknown owner forces an
        // earlier refresh (the App may have just been installed there), but
        // at most once a minute, since external owners are always unknown.
        let refresh = match &cache.installations {
            None => true,
            Some((at, map)) => {
                let age = Utc::now() - *at;
                age > INSTALLATIONS_TTL || (!map.contains_key(&owner) && age > UNKNOWN_OWNER_RETRY)
            }
        };
        if refresh {
            let map = self.fetch_installations().await?;
            cache.installations = Some((Utc::now(), map));
        }

        let installations = &cache.installations.as_ref().expect("fetched above").1;
        let id = match installations.get(&owner) {
            Some(id) => *id,
            None => {
                if let Some(fallback) = &self.fallback {
                    return fallback.token(&owner).await;
                }
                // Any installation can read public data; take the oldest for
                // deterministic rate limit accounting.
                *installations
                    .values()
                    .min()
                    .ok_or_else(|| Error::Auth("the GitHub App has no installations".into()))?
            }
        };
        self.installation_token(&mut cache, id).await
    }
}
