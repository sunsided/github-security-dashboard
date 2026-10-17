//! Dependency graph export (SPDX SBOM).

use crate::Result;
use crate::client::GitHub;
use serde::Deserialize;

#[derive(Deserialize)]
struct SbomResponse {
    sbom: Sbom,
}

#[derive(Deserialize)]
struct Sbom {
    #[serde(default)]
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    #[serde(rename = "externalRefs", default)]
    external_refs: Vec<ExternalRef>,
}

#[derive(Deserialize)]
struct ExternalRef {
    #[serde(rename = "referenceType")]
    reference_type: String,
    #[serde(rename = "referenceLocator")]
    reference_locator: String,
}

impl GitHub {
    /// Package URLs (`pkg:npm/vite@6.0.1`) of every dependency in a
    /// repository's dependency graph. Works for public repositories without
    /// special permissions; deduplicated, in SBOM order.
    pub async fn dependency_purls(&self, owner: &str, repo: &str) -> Result<Vec<String>> {
        let url = self.api_url(&format!("/repos/{owner}/{repo}/dependency-graph/sbom"));
        let fetched = self.get_cached(owner, &url).await?;
        let response: SbomResponse = serde_json::from_slice(&fetched.body)?;
        let mut purls: Vec<String> = Vec::new();
        for package in response.sbom.packages {
            for reference in package.external_refs {
                if reference.reference_type == "purl"
                    && !purls.contains(&reference.reference_locator)
                {
                    purls.push(reference.reference_locator);
                }
            }
        }
        Ok(purls)
    }
}
