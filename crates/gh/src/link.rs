//! `Link` header parsing (RFC 8288, as far as GitHub uses it).

/// Returns the URL with relation `rel`, if present.
pub fn find_rel<'a>(header: &'a str, rel: &str) -> Option<&'a str> {
    header.split(',').find_map(|part| {
        let mut pieces = part.split(';');
        let url = pieces.next()?.trim().strip_prefix('<')?.strip_suffix('>')?;
        pieces
            .any(|p| {
                p.trim()
                    .strip_prefix("rel=")
                    .map(|v| v.trim_matches('"').split_whitespace().any(|r| r == rel))
                    .unwrap_or(false)
            })
            .then_some(url)
    })
}

/// Extracts the `page` query parameter of the `rel="last"` link.
///
/// Requesting a list with `per_page=1` makes this the total item count.
pub fn last_page(header: &str) -> Option<u64> {
    let url = find_rel(header, "last")?;
    let query = url.split_once('?')?.1;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix("page="))
        .and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = r#"<https://api.github.com/repositories/1/contributors?per_page=1&anon=1&page=2>; rel="next", <https://api.github.com/repositories/1/contributors?per_page=1&anon=1&page=137>; rel="last""#;

    #[test]
    fn finds_relations() {
        assert_eq!(
            find_rel(HEADER, "next"),
            Some("https://api.github.com/repositories/1/contributors?per_page=1&anon=1&page=2")
        );
        assert_eq!(find_rel(HEADER, "prev"), None);
    }

    #[test]
    fn last_page_is_the_count() {
        assert_eq!(last_page(HEADER), Some(137));
        assert_eq!(last_page(r#"<https://x/y?page=2>; rel="next""#), None);
        assert_eq!(last_page(""), None);
    }

    #[test]
    fn page_param_is_not_confused_with_per_page() {
        assert_eq!(
            last_page(r#"<https://x/y?per_page=1&page=9>; rel="last""#),
            Some(9)
        );
    }
}
