//! CVSS v3.x base scores, for advisories that carry a vector but no
//! severity label (e.g. RustSec entries in OSV).
//!
//! Implements the base metric equations of the CVSS v3.1 specification,
//! section 7.1, including its `Roundup` definition. v3.0 vectors use the
//! same metrics and are scored the same way.

/// Base score (0.0–10.0) of a `CVSS:3.x/AV:N/AC:L/...` vector, or `None`
/// if the vector is not CVSS 3 or lacks a base metric.
pub fn base_score(vector: &str) -> Option<f64> {
    if !vector.split('/').next()?.starts_with("CVSS:3") {
        return None;
    }
    let metric = |name: &str| -> Option<String> {
        vector
            .split('/')
            .find_map(|p| p.strip_prefix(name)?.strip_prefix(':').map(str::to_owned))
    };

    let scope_changed = match metric("S")?.as_str() {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match metric("AV")?.as_str() {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match metric("AC")?.as_str() {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (metric("PR")?.as_str(), scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match metric("UI")?.as_str() {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |name: &str| -> Option<f64> {
        match metric(name)?.as_str() {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;

    if impact <= 0.0 {
        return Some(0.0);
    }
    let raw = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    Some(roundup(raw.min(10.0)))
}

/// The specification's `Roundup`: the smallest number with one decimal
/// that is at least the input, robust against floating point noise.
fn roundup(value: f64) -> f64 {
    let scaled = (value * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    #[test]
    fn known_scores() {
        // Reference values from the NVD calculator.
        check!(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == Some(9.8));
        check!(base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H") == Some(7.2));
        check!(base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N") == Some(5.9));
        check!(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == Some(6.1));
        check!(base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H") == Some(9.9));
        check!(base_score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H") == Some(5.5));
        check!(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == Some(0.0));
    }

    #[test]
    fn rejects_other_versions_and_incomplete_vectors() {
        check!(
            base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == None
        );
        check!(base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") == None);
        check!(base_score("CVSS:3.1/AV:N/AC:L") == None);
        check!(base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == None);
    }

    #[test]
    fn roundup_ignores_floating_point_noise() {
        check!(roundup(4.000_000_1) == 4.0);
        check!(roundup(4.02) == 4.1);
    }
}
