//! Request bodies per target kind.

use crate::content::{Digest, Item};
use chrono_tz::Tz;
use serde_json::{Value, json};
use store::{AlertSource, Severity};

/// Version of the JSON body; bump on incompatible changes.
pub const JSON_SCHEMA_VERSION: u32 = 1;

/// Slack rejects section texts over 3000 characters.
const SLACK_SECTION_LIMIT: usize = 2900;

pub fn json(digest: &Digest) -> Value {
    let mut value = serde_json::to_value(digest).expect("digest serializes");
    value["schema_version"] = json!(JSON_SCHEMA_VERSION);
    value["headline"] = json!(digest.headline());
    value
}

/// Slack requires `&`, `<` and `>` escaped in text; everything else is
/// left alone.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn glyph(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "◆",
        Severity::High => "▲",
        Severity::Medium => "■",
        Severity::Low => "●",
    }
}

fn source_label(source: AlertSource) -> &'static str {
    match source {
        AlertSource::Dependabot => "Dependabot",
        AlertSource::CodeScanning => "Code scanning",
        AlertSource::SecretScanning => "Secret scanning",
        AlertSource::Osv => "OSV estimate",
    }
}

/// A URL safe to put into Slack's `<url|text>` link syntax: http(s) only,
/// and nothing that could end the link early (`|`, `>`) or start a new one.
fn slack_link_target(url: &str) -> Option<&str> {
    let allowed_scheme = url.starts_with("https://") || url.starts_with("http://");
    let clean = !url
        .chars()
        .any(|c| matches!(c, '<' | '>' | '|') || c.is_whitespace() || c.is_control());
    (allowed_scheme && clean).then_some(url)
}

fn line(item: &Item) -> String {
    let change = if item.change == "opened" {
        String::new()
    } else {
        format!(" · {}", item.change)
    };
    let repository = escape(&item.repository);
    let target = match slack_link_target(&item.url) {
        Some(url) => format!("<{url}|{repository}>"),
        None => repository,
    };
    format!(
        "{} *{}* {target}: {} _({}{})_",
        glyph(item.severity),
        item.severity,
        escape(&item.title),
        source_label(item.source),
        change
    )
}

/// A section listing up to `max_items` lines, staying under Slack's limit.
fn list_section(title: &str, items: &[Item], max_items: usize) -> Option<Value> {
    if items.is_empty() {
        return None;
    }
    let mut text = format!("*{title}*");
    let mut shown = 0;
    for item in items.iter().take(max_items) {
        let next = line(item);
        if text.len() + next.len() + 40 > SLACK_SECTION_LIMIT {
            break;
        }
        text.push('\n');
        text.push_str(&next);
        shown += 1;
    }
    if shown < items.len() {
        text.push_str(&format!("\n…and {} more", items.len() - shown));
    }
    Some(json!({ "type": "section", "text": { "type": "mrkdwn", "text": text } }))
}

pub fn slack(digest: &Digest, timezone: Tz, max_items: usize) -> Value {
    let period = format!(
        "{} – {}",
        digest
            .period_start
            .with_timezone(&timezone)
            .format("%-d %b %H:%M"),
        digest
            .period_end
            .with_timezone(&timezone)
            .format("%-d %b %H:%M %Z"),
    );
    let mut blocks = vec![
        json!({ "type": "header", "text": { "type": "plain_text", "text": "Security digest" } }),
        json!({ "type": "section", "text": { "type": "mrkdwn",
            "text": format!("*{}*\n_{}_", escape(&digest.headline()), period) } }),
    ];
    blocks.extend(list_section("New", &digest.new, max_items));
    blocks.extend(list_section(
        "Severity raised",
        &digest.escalated,
        max_items,
    ));

    let open = &digest.totals.open_alerts;
    let closed = &digest.closed;
    let mut context = vec![format!(
        "Open now: {} critical, {} high, {} medium, {} low in {} repositories",
        open.critical, open.high, open.medium, open.low, digest.totals.repositories_with_alerts
    )];
    if closed.fixed + closed.dismissed + closed.gone > 0 {
        context.insert(
            0,
            format!(
                "Closed: {} fixed, {} dismissed, {} gone",
                closed.fixed, closed.dismissed, closed.gone
            ),
        );
    }
    blocks.push(json!({ "type": "context", "elements": [
        { "type": "mrkdwn", "text": context.join(" · ") }
    ]}));
    if let Some(url) = &digest.dashboard_url {
        blocks.push(json!({ "type": "actions", "elements": [{
            "type": "button",
            "text": { "type": "plain_text", "text": "Open dashboard" },
            "url": url
        }]}));
    }

    json!({
        // Shown in notifications and by clients without block support.
        "text": format!("Security digest: {}", digest.headline()),
        "blocks": blocks
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::tests::{event, totals};
    use assert2::check;
    use store::EventKind;

    fn digest(events: &[store::AlertEvent]) -> Digest {
        Digest::build(
            events,
            "2026-10-16T06:00:00Z".parse().unwrap(),
            "2026-10-17T06:00:00Z".parse().unwrap(),
            totals(),
            Some("https://dashboard.example".into()),
        )
        .unwrap()
    }

    #[test]
    fn slack_message_lists_alerts_and_escapes_text() {
        let mut opened = event(
            1,
            EventKind::Opened,
            Severity::Critical,
            None,
            Some("critical"),
        );
        opened.title = "Use <after> free & co".into();
        let message = slack(&digest(&[opened]), chrono_tz::Europe::Berlin, 15);

        check!(message["text"] == "Security digest: 1 new alert (1 critical)");
        let blocks = message["blocks"].as_array().unwrap();
        let period = blocks[1]["text"]["text"].as_str().unwrap();
        check!(
            period.contains("16 Oct 08:00 – 17 Oct 08:00 CEST"),
            "{period}"
        );
        let new = blocks[2]["text"]["text"].as_str().unwrap();
        check!(new.starts_with(
            "*New*\n◆ *critical* <https://github.com/acme/api/security/dependabot/1|acme/api>"
        ));
        check!(new.contains("Use &lt;after&gt; free &amp; co"));
        check!(blocks.last().unwrap()["elements"][0]["url"] == "https://dashboard.example");
    }

    #[test]
    fn suspicious_urls_are_not_linked() {
        let mut injected = event(1, EventKind::Opened, Severity::High, None, Some("high"));
        injected.html_url = "https://osv.dev/vulnerability/X|<!channel>".into();
        let mut scheme = event(2, EventKind::Opened, Severity::High, None, Some("high"));
        scheme.html_url = "javascript:alert(1)".into();
        let message = slack(&digest(&[injected, scheme]), chrono_tz::UTC, 15);
        let new = message["blocks"][2]["text"]["text"].as_str().unwrap();
        check!(!new.contains("<!channel>"));
        check!(!new.contains("javascript:"));
        check!(new.contains("▲ *high* acme/api: advisory 1"), "{new}");
    }

    #[test]
    fn long_lists_are_cut_with_a_count() {
        let events: Vec<_> = (1..=40)
            .map(|i| event(i, EventKind::Opened, Severity::Medium, None, Some("medium")))
            .collect();
        let message = slack(&digest(&events), chrono_tz::UTC, 15);
        let new = message["blocks"][2]["text"]["text"].as_str().unwrap();
        check!(new.lines().count() == 1 + 15 + 1);
        check!(new.ends_with("…and 25 more"));
    }

    #[test]
    fn json_body_is_the_digest_with_a_version() {
        let body = json(&digest(&[event(
            3,
            EventKind::Fixed,
            Severity::High,
            None,
            None,
        )]));
        check!(body["schema_version"] == 1);
        check!(body["headline"] == "1 closed");
        check!(body["closed"]["fixed"] == 1);
        check!(body["first_event_id"] == 3);
        check!(body["totals"]["open_alerts"]["critical"] == 1);
    }
}
