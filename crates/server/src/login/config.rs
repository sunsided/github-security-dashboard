//! `[login]` schema.

use anyhow::bail;
use ipnet::IpNet;
use serde::Deserialize;
use std::time::Duration;

/// Who may use the dashboard, and how they prove it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoginConfig {
    pub mode: Mode,
    /// Claim holding a user's groups in ID or access tokens.
    pub groups_claim: Option<String>,
    pub allow: Allow,
    pub proxy: Option<ProxyConfig>,
    pub oidc: Option<OidcConfig>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Anyone who can reach the server; for loopback or a trusted network.
    #[default]
    None,
    /// An authenticating proxy in front of the server vouches for the user.
    Proxy,
    /// The server signs users in itself, with OpenID Connect.
    Oidc,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Proxy => "proxy",
            Self::Oidc => "oidc",
        }
    }
}

/// Signed-in users the dashboard serves. With every list empty, that is
/// anyone the identity provider (or the proxy) lets through.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Allow {
    /// Email addresses, compared case-insensitively.
    pub emails: Vec<String>,
    /// Email domains, e.g. `example.org`.
    pub domains: Vec<String>,
    /// Groups from the token's groups claim or the proxy's groups header.
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyTrust {
    /// Verify the JWT the proxy passes along against the issuer's keys.
    #[default]
    Token,
    /// Believe the identity headers, as long as they come from a trusted
    /// proxy address. For proxies that pass no verifiable token.
    Headers,
    /// Read the token an Istio sidecar or waypoint has already verified
    /// (`RequestAuthentication`), without checking its signature again:
    /// only its form, expiry, and issuer and audience if configured.
    Istio,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    pub trust: ProxyTrust,
    /// Header carrying the token, with or without a `Bearer ` prefix.
    pub token_header: String,
    /// With `istio`: header carrying only the token's payload, as Istio's
    /// `outputPayloadToHeader` sets it. Read instead of `token_header`.
    pub payload_header: Option<String>,
    /// Expected `iss`; its discovery document names the signing keys.
    pub issuer: Option<String>,
    /// Accepted `aud` values; the proxy's client ID for ID tokens.
    pub audiences: Vec<String>,
    /// Signing keys, if the issuer has no discovery document.
    pub jwks_url: Option<String>,
    pub user_header: String,
    pub email_header: String,
    pub groups_header: String,
    /// Peer addresses requests must come from. Required to trust headers;
    /// with tokens, an additional restriction if set.
    pub trusted_proxies: Vec<IpNet>,
    /// The proxy's sign-out endpoint, linked from the UI.
    pub sign_out_url: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            trust: ProxyTrust::Token,
            token_header: "authorization".into(),
            payload_header: None,
            issuer: None,
            audiences: Vec::new(),
            jwks_url: None,
            user_header: "x-forwarded-user".into(),
            email_header: "x-forwarded-email".into(),
            groups_header: "x-forwarded-groups".into(),
            trusted_proxies: Vec::new(),
            sign_out_url: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Issuer URL; `/.well-known/openid-configuration` below it is fetched
    /// at start-up.
    pub issuer: String,
    pub client_id: String,
    /// Environment variable with the client secret. Without one, the server
    /// is a public client and relies on PKCE alone.
    pub client_secret_env: Option<String>,
    /// Public URL of `/auth/callback`, as registered with the provider.
    pub redirect_url: url::Url,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// How long a sign-in lasts.
    #[serde(default = "default_session_ttl", with = "humantime_serde")]
    pub session_ttl: Duration,
    /// Environment variable with the session signing key (32+ bytes).
    /// Without it, a random key per process: sessions end on restart, and
    /// replicas don't share them.
    pub session_key_env: Option<String>,
}

fn default_scopes() -> Vec<String> {
    ["openid", "email", "profile"].map(String::from).to_vec()
}

fn default_session_ttl() -> Duration {
    Duration::from_secs(8 * 60 * 60)
}

impl LoginConfig {
    /// Settings that parse but can't work.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self.mode {
            Mode::None => {}
            Mode::Proxy => {
                let Some(proxy) = &self.proxy else {
                    bail!("[login] mode = \"proxy\" needs a [login.proxy] section");
                };
                if proxy.payload_header.is_some() && proxy.trust != ProxyTrust::Istio {
                    bail!("[login.proxy] payload_header only applies to trust = \"istio\"");
                }
                match proxy.trust {
                    ProxyTrust::Token => {
                        if proxy.issuer.is_none() {
                            bail!("[login.proxy] needs the issuer of the forwarded tokens");
                        }
                        // Any token of the issuer would do otherwise, including
                        // ones it issued to unrelated applications.
                        if proxy.audiences.is_empty() {
                            bail!("[login.proxy] needs the audiences tokens must be issued for");
                        }
                    }
                    ProxyTrust::Istio => {}
                    ProxyTrust::Headers => {
                        if proxy.trusted_proxies.is_empty() {
                            bail!(
                                "[login.proxy] trust = \"headers\" needs trusted_proxies; \
                                 anyone could send the headers otherwise"
                            );
                        }
                    }
                }
            }
            Mode::Oidc => {
                let Some(oidc) = &self.oidc else {
                    bail!("[login] mode = \"oidc\" needs a [login.oidc] section");
                };
                if oidc.redirect_url.path() != crate::login::CALLBACK_PATH {
                    bail!(
                        "[login.oidc] redirect_url must end in {}",
                        crate::login::CALLBACK_PATH
                    );
                }
                if !oidc.scopes.iter().any(|s| s == "openid") {
                    bail!("[login.oidc] scopes must include \"openid\"");
                }
                if oidc.session_ttl < Duration::from_secs(60) {
                    bail!("[login.oidc] session_ttl must be at least one minute");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    fn parse(text: &str) -> anyhow::Result<LoginConfig> {
        let config: LoginConfig = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn defaults_to_no_login() {
        let config = parse("").unwrap();
        check!(config.mode == Mode::None);
    }

    #[test]
    fn proxy_tokens_need_issuer_and_audience() {
        check!(parse("mode = \"proxy\"").is_err());
        check!(parse("mode = \"proxy\"\n[proxy]\nissuer = \"https://idp\"").is_err());
        let ok =
            parse("mode = \"proxy\"\n[proxy]\nissuer = \"https://idp\"\naudiences = [\"dash\"]")
                .unwrap();
        let proxy = ok.proxy.unwrap();
        check!(proxy.trust == ProxyTrust::Token);
        check!(proxy.token_header == "authorization");
    }

    #[test]
    fn proxy_headers_need_trusted_proxies() {
        check!(parse("mode = \"proxy\"\n[proxy]\ntrust = \"headers\"").is_err());
        let ok = parse(
            "mode = \"proxy\"\n[proxy]\ntrust = \"headers\"\ntrusted_proxies = [\"10.0.0.0/8\", \"::1/128\"]",
        )
        .unwrap();
        check!(ok.proxy.unwrap().trusted_proxies.len() == 2);
        check!(
            parse("mode = \"proxy\"\n[proxy]\ntrust = \"headers\"\ntrusted_proxies = [\"10.0.0.300/8\"]")
                .is_err()
        );
    }

    #[test]
    fn istio_needs_nothing_but_takes_payload_headers() {
        let ok = parse("mode = \"proxy\"\n[proxy]\ntrust = \"istio\"").unwrap();
        check!(ok.proxy.unwrap().trust == ProxyTrust::Istio);
        check!(
            parse(
                "mode = \"proxy\"\n[proxy]\ntrust = \"istio\"\npayload_header = \"x-jwt-payload\""
            )
            .is_ok()
        );
        check!(
            parse("mode = \"proxy\"\n[proxy]\ntrust = \"headers\"\ntrusted_proxies = [\"10.0.0.0/8\"]\npayload_header = \"x\"")
                .is_err()
        );
    }

    #[test]
    fn oidc_checks_redirect_url_and_scopes() {
        let base = "mode = \"oidc\"\n[oidc]\nissuer = \"https://idp\"\nclient_id = \"dash\"\n";
        let ok = parse(&format!(
            "{base}redirect_url = \"https://dash.example/auth/callback\""
        ))
        .unwrap();
        let oidc = ok.oidc.unwrap();
        check!(oidc.scopes == ["openid", "email", "profile"]);
        check!(oidc.session_ttl == Duration::from_secs(8 * 3600));

        check!(parse("mode = \"oidc\"").is_err());
        check!(
            parse(&format!(
                "{base}redirect_url = \"https://dash.example/callback\""
            ))
            .is_err()
        );
        check!(
            parse(&format!(
                "{base}redirect_url = \"https://dash.example/auth/callback\"\nscopes = [\"email\"]"
            ))
            .is_err()
        );
    }
}
