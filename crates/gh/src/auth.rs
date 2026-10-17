//! Token acquisition.

use crate::Result;
use async_trait::async_trait;
use std::fmt;

/// Supplies an access token for requests concerning `owner`.
///
/// A personal access token ignores the owner; a GitHub App provider uses it to
/// pick the installation whose token covers that owner's repositories.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn token(&self, owner: &str) -> Result<Secret>;

    /// How the server authenticates, for status displays.
    fn label(&self) -> &'static str {
        "personal access token"
    }
}

/// A token that never shows up in `Debug` output or logs.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// A personal access token (classic or fine-grained).
#[derive(Debug, Clone)]
pub struct PatProvider {
    token: Secret,
}

impl PatProvider {
    pub fn new(token: Secret) -> Self {
        Self { token }
    }
}

#[async_trait]
impl TokenProvider for PatProvider {
    async fn token(&self, _owner: &str) -> Result<Secret> {
        Ok(self.token.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    #[test]
    fn secret_debug_is_redacted() {
        check!(format!("{:?}", Secret::new("ghp_abc")) == "Secret(***)");
    }
}
