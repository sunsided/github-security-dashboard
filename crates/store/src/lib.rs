//! Persistence for the GitHub security dashboard.
//!
//! The application only talks to the [`Store`] trait. Backends are selected by
//! URL scheme at runtime and compiled in via cargo features.

mod api;
#[cfg(feature = "sqlite")]
pub mod sqlite;

use std::sync::Arc;

pub use api::*;

/// Opens the backend matching `url` and applies pending migrations.
///
/// Supported schemes: `sqlite:` (feature `sqlite`).
pub async fn connect(url: &str) -> Result<Arc<dyn Store>> {
    #[cfg(feature = "sqlite")]
    if url.starts_with("sqlite:") {
        return Ok(Arc::new(sqlite::SqliteStore::connect(url).await?));
    }

    Err(StoreError::UnsupportedUrl(scheme_of(url).to_owned()))
}

/// The URL scheme only: everything after it may carry credentials, in the
/// userinfo part as well as in query parameters.
fn scheme_of(url: &str) -> &str {
    url.split_once(':').map_or("<none>", |(scheme, _)| scheme)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_shows_scheme_only() {
        assert_eq!(scheme_of("postgres://user:secret@db:5432/x"), "postgres");
        assert_eq!(scheme_of("mysql://db/x?password=secret"), "mysql");
        assert_eq!(scheme_of("no-scheme-here"), "<none>");
    }
}
