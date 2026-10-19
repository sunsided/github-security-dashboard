//! An identity provider's discovery document and signing keys.

use anyhow::{Context, bail};
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

/// Signatures accepted on provider tokens. Never HMAC: with the provider's
/// public key as the "secret", anyone could forge tokens.
const ASYMMETRIC: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Unknown key IDs trigger a refetch (the provider rotated its keys), but
/// not more often than this, so garbage tokens can't hammer the provider.
const MIN_REFETCH: Duration = Duration::from_secs(30);

/// The parts of `/.well-known/openid-configuration` used here.
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

impl Metadata {
    pub async fn discover(http: &reqwest::Client, issuer: &str) -> anyhow::Result<Self> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let metadata: Self = http
            .get(&url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .with_context(|| format!("fetching {url}"))?
            .json()
            .await
            .with_context(|| format!("parsing {url}"))?;
        // A document claiming another issuer would let that issuer's tokens in.
        if metadata.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
            bail!(
                "{url} describes issuer {:?}, not {issuer:?}",
                metadata.issuer
            );
        }
        Ok(metadata)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    /// Malformed, badly signed, or for another issuer or audience.
    Invalid,
    Expired,
    /// The provider's keys couldn't be fetched.
    Unavailable,
}

pub struct KeySet {
    http: reqwest::Client,
    url: String,
    keys: RwLock<JwkSet>,
    /// When keys were last fetched. Held across the fetch, so concurrent
    /// tokens with an unknown key wait for one fetch instead of each
    /// starting their own, while tokens with known keys go on verifying.
    fetched: Mutex<Option<Instant>>,
}

impl KeySet {
    /// Keys are fetched on first use.
    pub fn new(http: reqwest::Client, url: impl Into<String>) -> Self {
        Self {
            http,
            url: url.into(),
            keys: RwLock::new(JwkSet { keys: Vec::new() }),
            fetched: Mutex::new(None),
        }
    }

    /// Verifies `token`'s signature, then the claims `validation` asks for.
    /// Its algorithms are ignored: the token's own is checked against the
    /// key and [`ASYMMETRIC`].
    pub async fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> Result<T, TokenError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| TokenError::Invalid)?;
        if !ASYMMETRIC.contains(&header.alg) {
            return Err(TokenError::Invalid);
        }
        let key = match self.key(header.kid.as_deref(), header.alg).await {
            Some(key) => key,
            None => {
                self.refetch().await?;
                self.key(header.kid.as_deref(), header.alg)
                    .await
                    .ok_or(TokenError::Invalid)?
            }
        };
        let mut validation = validation.clone();
        validation.algorithms = vec![header.alg];
        match jsonwebtoken::decode::<T>(token, &key, &validation) {
            Ok(data) => Ok(data.claims),
            Err(e) if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) => {
                Err(TokenError::Expired)
            }
            Err(e) => {
                tracing::debug!(error = %e, "rejected token");
                Err(TokenError::Invalid)
            }
        }
    }

    /// The key a token names, or the only one that fits if it names none.
    async fn key(&self, kid: Option<&str>, alg: Algorithm) -> Option<DecodingKey> {
        let keys = self.keys.read().await;
        let fits = |jwk: &&jsonwebtoken::jwk::Jwk| {
            !matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_))
                && jwk
                    .common
                    .key_algorithm
                    .is_none_or(|a| a == KeyAlgorithm::from(alg))
        };
        let jwk = match kid {
            Some(kid) => keys.find(kid).filter(|jwk| fits(jwk)),
            None => {
                let mut candidates = keys.keys.iter().filter(fits);
                candidates.next().filter(|_| candidates.next().is_none())
            }
        }?;
        DecodingKey::from_jwk(jwk).ok()
    }

    async fn refetch(&self) -> Result<(), TokenError> {
        let mut fetched = self.fetched.lock().await;
        if fetched.is_some_and(|at| at.elapsed() < MIN_REFETCH) {
            return Ok(());
        }
        *fetched = Some(Instant::now());
        let keys = async {
            self.http
                .get(&self.url)
                .send()
                .await?
                .error_for_status()?
                .json::<JwkSet>()
                .await
        }
        .await;
        match keys {
            Ok(keys) => {
                *self.keys.write().await = keys;
                Ok(())
            }
            Err(e) => {
                tracing::warn!(url = %self.url, error = %e, "fetching signing keys failed");
                Err(TokenError::Unavailable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;
    use jsonwebtoken::{EncodingKey, Header};
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const KEY: &str = include_str!("../../tests/fixtures/idp-key.pem");
    const JWKS: &str = include_str!("../../tests/fixtures/idp-jwks.json");

    fn sign(alg: Algorithm, kid: Option<&str>, claims: serde_json::Value) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_owned);
        jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(KEY.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn claims(exp_in: i64) -> serde_json::Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({ "iss": "https://idp", "aud": "dash", "sub": "u1", "exp": now + exp_in })
    }

    fn validation() -> Validation {
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&["https://idp"]);
        v.set_audience(&["dash"]);
        v.leeway = 0;
        v
    }

    async fn keys(server: &MockServer) -> KeySet {
        Mock::given(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(JWKS, "application/json"))
            .mount(server)
            .await;
        KeySet::new(reqwest::Client::new(), format!("{}/jwks", server.uri()))
    }

    #[tokio::test]
    async fn verifies_signature_issuer_audience_and_expiry() {
        let server = MockServer::start().await;
        let keys = keys(&server).await;
        let v = validation();

        let good = sign(Algorithm::RS256, Some("test-idp"), claims(60));
        let claims_out: serde_json::Value = keys.verify(&good, &v).await.unwrap();
        check!(claims_out["sub"] == "u1");

        let unnamed = sign(Algorithm::RS256, None, claims(60));
        check!(keys.verify::<serde_json::Value>(&unnamed, &v).await.is_ok());

        let expired = sign(Algorithm::RS256, Some("test-idp"), claims(-60));
        check!(keys.verify::<serde_json::Value>(&expired, &v).await == Err(TokenError::Expired));

        let mut other_aud = claims(60);
        other_aud["aud"] = "someone-else".into();
        let other_aud = sign(Algorithm::RS256, Some("test-idp"), other_aud);
        check!(keys.verify::<serde_json::Value>(&other_aud, &v).await == Err(TokenError::Invalid));
    }

    #[tokio::test]
    async fn rejects_hmac_and_unknown_keys() {
        let server = MockServer::start().await;
        let keys = keys(&server).await;
        let v = validation();

        // HS256 "signed" with the public JWKS as the secret.
        let forged = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims(60),
            &EncodingKey::from_secret(JWKS.as_bytes()),
        )
        .unwrap();
        check!(keys.verify::<serde_json::Value>(&forged, &v).await == Err(TokenError::Invalid));

        let unknown = sign(Algorithm::RS256, Some("rotated-away"), claims(60));
        check!(keys.verify::<serde_json::Value>(&unknown, &v).await == Err(TokenError::Invalid));
        check!(keys.verify::<serde_json::Value>("garbage", &v).await == Err(TokenError::Invalid));
    }

    #[tokio::test]
    async fn refetches_at_most_every_so_often() {
        let server = MockServer::start().await;
        Mock::given(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(JWKS, "application/json"))
            .expect(1)
            .mount(&server)
            .await;
        let keys = KeySet::new(reqwest::Client::new(), format!("{}/jwks", server.uri()));
        for kid in ["a", "b", "c"] {
            let token = sign(Algorithm::RS256, Some(kid), claims(60));
            let _ = keys
                .verify::<serde_json::Value>(&token, &validation())
                .await;
        }
    }

    #[tokio::test]
    async fn discovery_must_match_the_issuer() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let doc = |iss: &str| {
            serde_json::json!({
                "issuer": iss,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
            })
        };
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc(&issuer)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let http = reqwest::Client::new();
        let metadata = Metadata::discover(&http, &format!("{issuer}/"))
            .await
            .unwrap();
        check!(metadata.jwks_uri == format!("{issuer}/jwks"));

        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc("https://evil.example")))
            .mount(&server)
            .await;
        check!(Metadata::discover(&http, &issuer).await.is_err());
    }
}
