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

/// A URL safe to put into a chat link: http(s) only, and nothing that
/// could end Slack's `<url|text>` or Markdown's `[text](url)` early.
fn link_target(url: &str) -> Option<&str> {
    let allowed_scheme = url.starts_with("https://") || url.starts_with("http://");
    let clean = !url
        .chars()
        .any(|c| matches!(c, '<' | '>' | '|' | '(' | ')') || c.is_whitespace() || c.is_control());
    (allowed_scheme && clean).then_some(url)
}

fn line(item: &Item) -> String {
    let change = if item.change == "opened" {
        String::new()
    } else {
        format!(" · {}", item.change)
    };
    let repository = escape(&item.repository);
    let target = match link_target(&item.url) {
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
        // +1 for the newline before the line, 40 for "…and N more".
        if text.len() + 1 + next.len() + 40 > SLACK_SECTION_LIMIT {
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

/// Text for Adaptive Card Markdown: brackets would start a link of their
/// own, emphasis markers are harmless and kept.
fn card_text(text: &str) -> String {
    text.replace('[', "(").replace(']', ")")
}

fn card_line(item: &Item) -> String {
    let change = if item.change == "opened" {
        String::new()
    } else {
        format!(" · {}", item.change)
    };
    let repository = card_text(&item.repository);
    let target = match link_target(&item.url) {
        Some(url) => format!("[{repository}]({url})"),
        None => repository,
    };
    format!(
        "{} **{}** {target}: {} _({}{})_",
        glyph(item.severity),
        item.severity,
        card_text(&item.title),
        source_label(item.source),
        change
    )
}

fn text_block(text: String) -> Value {
    json!({ "type": "TextBlock", "text": text, "wrap": true })
}

fn card_section(title: &str, items: &[Item], max_items: usize) -> Vec<Value> {
    if items.is_empty() {
        return Vec::new();
    }
    let mut blocks = vec![json!({
        "type": "TextBlock", "text": title, "weight": "Bolder", "spacing": "Medium", "wrap": true
    })];
    blocks.extend(items.iter().take(max_items).map(|i| {
        let mut block = text_block(card_line(i));
        block["spacing"] = json!("Small");
        block
    }));
    if items.len() > max_items {
        blocks.push(text_block(format!("…and {} more", items.len() - max_items)));
    }
    blocks
}

/// A Microsoft Teams message with an Adaptive Card, as the Workflows
/// template "Post to a channel when a webhook request is received" expects.
pub fn teams(digest: &Digest, timezone: Tz, max_items: usize) -> Value {
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
    let mut body = vec![
        json!({ "type": "TextBlock", "text": "Security digest", "size": "Large", "weight": "Bolder" }),
        json!({ "type": "TextBlock", "text": card_text(&digest.headline()), "weight": "Bolder", "wrap": true }),
        json!({ "type": "TextBlock", "text": period, "isSubtle": true, "spacing": "None", "wrap": true }),
    ];
    body.extend(card_section("New", &digest.new, max_items));
    body.extend(card_section(
        "Severity raised",
        &digest.escalated,
        max_items,
    ));

    let open = &digest.totals.open_alerts;
    let closed = &digest.closed;
    let mut facts = Vec::new();
    if closed.fixed + closed.dismissed + closed.gone > 0 {
        facts.push(json!({ "title": "Closed", "value": format!(
            "{} fixed, {} dismissed, {} gone", closed.fixed, closed.dismissed, closed.gone) }));
    }
    facts.push(json!({ "title": "Open now", "value": format!(
        "{} critical, {} high, {} medium, {} low in {} repositories",
        open.critical, open.high, open.medium, open.low, digest.totals.repositories_with_alerts) }));
    body.push(json!({ "type": "FactSet", "facts": facts, "spacing": "Medium" }));

    let mut card = json!({
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    });
    if let Some(url) = digest.dashboard_url.as_deref().and_then(link_target) {
        card["actions"] =
            json!([{ "type": "Action.OpenUrl", "title": "Open dashboard", "url": url }]);
    }
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": card
        }]
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
    fn teams_message_wraps_an_adaptive_card() {
        let mut opened = event(
            1,
            EventKind::Opened,
            Severity::Critical,
            None,
            Some("critical"),
        );
        opened.title = "Link [bait](https://evil.example)".into();
        let mut odd = event(2, EventKind::Opened, Severity::Low, None, Some("low"));
        odd.html_url = "https://example.org/a)b".into();
        let message = teams(&digest(&[opened, odd]), chrono_tz::Europe::Berlin, 15);

        check!(message["type"] == "message");
        let attachment = &message["attachments"][0];
        check!(attachment["contentType"] == "application/vnd.microsoft.card.adaptive");
        let card = &attachment["content"];
        check!(card["type"] == "AdaptiveCard");
        check!(card["version"] == "1.4");
        let texts: Vec<&str> = card["body"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|b| b["text"].as_str())
            .collect();
        check!(texts.contains(&"2 new alerts (1 critical)"));
        check!(texts.iter().any(|t| t.starts_with(
            "◆ **critical** [acme/api](https://github.com/acme/api/security/dependabot/1): Link (bait)(https://evil.example)"
        )), "{texts:?}");
        check!(
            texts
                .iter()
                .any(|t| t.starts_with("● **low** acme/api: advisory 2")),
            "unsafe URLs aren't linked"
        );
        check!(card["actions"][0]["url"] == "https://dashboard.example");
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
