//! Persistence for the GitHub security dashboard.
//!
//! The application only talks to the [`Store`] trait. Backends are selected by
//! URL scheme at runtime and compiled in via cargo features.

/// A fieldless enum stored and serialized as fixed strings.
///
/// Variants are declared in order of precedence; the derived `Ord` follows
/// declaration order (e.g. `Severity::Critical < Severity::Low`).
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$vmeta:meta])* $variant:ident = $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord,
            serde::Serialize, serde::Deserialize,
        )]
        $vis enum $name {
            $($(#[$vmeta])* #[serde(rename = $value)] $variant),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::StoreError;

            fn from_str(s: &str) -> $crate::Result<Self> {
                match s {
                    $($value => Ok(Self::$variant),)+
                    other => Err($crate::StoreError::InvalidData(format!(
                        "{} {other:?}",
                        stringify!($name)
                    ))),
                }
            }
        }
    };
}
pub(crate) use string_enum;

mod alerts;
mod api;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

use std::sync::Arc;

pub use alerts::*;
pub use api::*;

/// Opens the backend matching `url` and applies pending migrations.
///
/// Supported schemes: `sqlite:` (feature `sqlite`), `postgres:` and
/// `postgresql:` (feature `postgres`).
pub async fn connect(url: &str) -> Result<Arc<dyn Store>> {
    #[cfg(feature = "sqlite")]
    if url.starts_with("sqlite:") {
        return Ok(Arc::new(sqlite::SqliteStore::connect(url).await?));
    }

    #[cfg(feature = "postgres")]
    if url.starts_with("postgres:") || url.starts_with("postgresql:") {
        return Ok(Arc::new(postgres::PostgresStore::connect(url).await?));
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
    use assert2::check;

    #[test]
    fn error_shows_scheme_only() {
        check!(scheme_of("postgres://user:secret@db:5432/x") == "postgres");
        check!(scheme_of("mysql://db/x?password=secret") == "mysql");
        check!(scheme_of("no-scheme-here") == "<none>");
    }
}
