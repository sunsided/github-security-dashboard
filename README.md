# GitHub Security Dashboard

[![CI](https://github.com/sunsided/github-security-dashboard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sunsided/github-security-dashboard/actions/workflows/ci.yml)

A self-hosted dashboard that collects security alerts and repository health data from the GitHub API and puts every repository I care about on one ranked page.

This exists because GitHub shows Dependabot, code scanning and secret scanning alerts per repository, in that repository's Security tab, and nowhere else I was looking. With a handful of repositories in an enterprise organization, a number of my own under [sunsided](https://github.com/sunsided) and some external ones I depend on, "open each Security tab and squint" stopped being a process. The alert emails I expected never showed up either (that one is probably a notification setting, but the point stands).

The idea is simple: a small Rust server polls the GitHub API on a schedule, normalizes alerts into critical, high, medium and low, keeps snapshots in a database, and serves a SvelteKit UI that sorts repositories by how much attention they need. Next to the alerts it records the usual health signals: open issues and pull requests, contributors, commit count, tags and releases, and how long ago anyone last committed.

## Getting started

You'll need Rust (1.88 or newer), Node.js with corepack enabled (`corepack enable`, which provides the pinned Yarn 4) and [Task](https://taskfile.dev). Then:

```sh
task setup     # creates config.toml and .env from their examples, installs UI dependencies
$EDITOR config.toml .env
task dev       # server on :8080, Vite dev server with hot reload on :5173
```

`config.toml` lists the owners (organizations or users) whose repositories are tracked, plus any external repositories as `owner/name`. The GitHub token goes into `.env` as `GITHUB_TOKEN`; the config file only names the variable, so it can be shared without leaking anything. Which permissions the token needs, and how to use a GitHub App instead, is described under [Authentication](#authentication).

Other tasks worth knowing (`task` alone lists all of them):

| Task | What it does |
|---|---|
| `task run` | Server only, serving the last UI build |
| `task collect` | One collector run, then exit |
| `task build:release` | Builds the UI and a single `target/release/server` binary with the UI embedded |
| `task test` | Rust and UI tests |
| `task check` | Formatting, clippy, ESLint, svelte-check |
| `task ci` | `check`, `test` and the UI build, as CI would run them |
| `task db:up` | A development PostgreSQL on `127.0.0.1:54329` (Docker Compose) |
| `task test:postgres` | The storage contract tests against that PostgreSQL |

For a sense of scale: the first run against my own account (718 repositories, plus two external ones) takes about three minutes and some 700 requests, most of them contributor counts. Later runs reuse ETags where GitHub supports them, and those don't count against the quota.

Alerts are cheap for organizations (one request per source covers every repository, provided the token belongs to an owner or security manager) and comparatively expensive for user accounts, where every repository needs three requests of its own. That is why archived repositories and forks are skipped by default (`collector.alerts.skip_archived`, `skip_forks`). With those defaults, a full run over my account, alerts included, takes a little under four minutes. The resulting numbers match what GitHub's Security tab shows, down to repositories with a couple of hundred open Dependabot alerts.

Every alert state change is written to an append-only log, which the Activity page shows. "Fixed" and "dismissed" are told apart by looking up alerts individually once they drop out of the open list; a source that couldn't be read in a run never closes anything, so a flaky 503 doesn't rewrite history.

## Authentication

There are two ways in, and they combine.

A **personal access token** is the quick start: put it into `.env` as `GITHUB_TOKEN` and you're done. A fine-grained token needs read-only access to Metadata, Contents, Issues, Pull requests, Dependabot alerts, Code scanning alerts and Secret scanning alerts. The catch is that it acts as you, sees what you see, and shares your hourly quota with everything else you do on GitHub.

A **GitHub App** is the better fit for anything that runs unattended. It isn't tied to a person, its installation tokens expire after an hour, and each installation gets its own rate limit. Setting one up takes a few minutes:

1. Create the App under *Settings → Developer settings → GitHub Apps* (or in the organization's settings). It needs no webhook, so untick *Active* there, and no callback URL.
2. Grant the same read-only repository permissions as listed for the token above.
3. Install it on each organization and on your own account, for all repositories or a selection.
4. Generate a private key and save the PEM next to `config.toml` (`*.pem` is gitignored).
5. Point the config at it:

   ```toml
   [auth.app]
   app_id = 123456                     # or the client ID, "Iv23..."
   private_key_path = "github-app.pem" # relative to config.toml
   ```

Owners without an installation, typically external repositories, still need a token from somewhere. If `GITHUB_TOKEN` is set, it is used for those; otherwise the server borrows the oldest installation's token, which is enough to read public repositories. Alerts of repositories you don't administer are out of reach either way; that's what the planned OSV estimate is for.

## Estimated alerts for external repositories

GitHub shows a repository's security alerts only to the people who administer it, so for the projects I depend on but don't own, the Security tab is simply not mine to read. Their dependency graph is public, though. For those repositories the collector downloads GitHub's SBOM export, queries [OSV](https://osv.dev) for every dependency with an exact version, and records each hit as an alert flagged *estimated*.

Estimates are not alerts, and the dashboard doesn't pretend otherwise:

- Dependencies without a concrete version are skipped and counted. Lockfiles resolve versions, manifests often don't, and pnpm's `catalog:` references don't either; asking OSV about a package without a version would return every advisory ever published for it.
- Severity comes from GitHub's own label where the advisory was reviewed by GitHub, so it matches what Dependabot would say. Otherwise it's the CVSS v3 base score, computed with the formula from the 3.1 specification, and failing that, medium. Each estimate notes which of the three it was.
- OSV often lists the same issue twice, as a RustSec entry and as its GitHub advisory twin. Those count once, under the GitHub one. RustSec's maintenance notices ("crate X is unmaintained") are left out, as Dependabot does; unsoundness reports stay, since they are about memory safety.
- An estimate is fixed when a later SBOM no longer contains an affected version. Whether the project shipped a release with that fix is another question that the SBOM can't answer.

By default this covers external repositories only; `collector.osv.scope = "without_dependabot"` extends it to tracked repositories with Dependabot disabled.

## Daily digest

The dashboard is only useful if someone looks at it, and the reason this project exists is that nobody was telling me about new alerts. So once a day the server sends a digest of what changed: alerts opened or reopened (most severe first, with links), severities that went up, alerts that were fixed or dismissed, and the totals as they stand. A day without changes sends nothing.

Targets are Slack incoming webhooks, Microsoft Teams Workflows webhooks (the template "Post to a channel when a webhook request is received", which takes an Adaptive Card), and plain JSON webhooks:

```toml
[digest]
enabled = true
at = "08:00"
timezone = "Europe/Berlin"

[[digest.targets]]
name = "slack"
kind = "slack"
url_env = "SLACK_WEBHOOK_URL"

[[digest.targets]]
name = "events"
kind = "json"
url_env = "DIGEST_WEBHOOK_URL"
```

Every request is a [CloudEvent](https://cloudevents.io) in binary content mode, with the `ce-*` attributes as headers and the payload as body, so it can go straight into Knative Eventing or any other CloudEvents consumer. JSON targets get `ce-type: <prefix>.digest.v1` with the digest as versioned JSON; Slack gets `<prefix>.digest.slack.v1` with a Block Kit message, Teams `<prefix>.digest.teams.v1` with an Adaptive Card (both ignore the headers). The `ce-id` is derived from the target and the range of events covered, so a retried delivery can be recognized as the same event.

Each target keeps its own watermark in the database. A failed delivery leaves its events for the next digest, a newly added target starts with the last 24 hours rather than the whole history, and a server that was down at digest time catches up when it starts. `task digest:send` sends a digest right away, which is the quickest way to see whether a webhook works; `GET /api/digest/preview` shows what the next one would contain without sending anything.

## Live updates

The UI keeps itself current: when a run starts or finishes, alerts change or a digest goes out, the server says so over a WebSocket and the open pages reload what's affected. The header shows whether the connection is live.

The connection is authenticated with a short-lived token that the UI fetches from `POST /api/realtime/token` and sends as its first message; a socket without a valid token in time is closed. Browsers can't set headers on WebSocket connections, which is why the token travels inside the protocol, and why authentication can later be added in front of the token endpoint without the live connection noticing. The tokens are HS256 JWTs in [Centrifugo](https://centrifugal.dev)'s connection-token format, so swapping in a real Centrifugo later is a server-side change. With `[realtime] signing_key_env` the key can be shared with it; without, a random key is generated at start-up and clients simply fetch a new token after a restart.

## Status

Work in progress. The plan, roughly in order:

1. ~~Workspace scaffold, configuration, personal access token auth, repository stats via GraphQL, pluggable storage with an SQLite backend, and a minimal table UI.~~ Done.
2. ~~Alerts from Dependabot, code scanning and secret scanning (organization-wide endpoints where possible, per repository otherwise), severity scoring and a detail page.~~ Done.
3. ~~GitHub App authentication.~~ Done.
4. ~~External repositories: when I can't read their alerts (GitHub only shows them to admins and security managers), the server pulls the dependency SBOM and matches it against [OSV](https://osv.dev). Those numbers are labeled as estimates, because that's what they are.~~ Done.
5. ~~A PostgreSQL backend for keeping the audit history long term.~~ Done.
6. ~~A digest of newly opened alerts by email or Slack.~~ Done, as a daily digest to Slack and CloudEvents webhooks.

## Design notes

- **Storage is pluggable.** The application talks to a `Store` trait; SQLite is the default, PostgreSQL the choice for keeping the audit history somewhere with backups and a retention policy. `storage.url` decides (`sqlite://dashboard.db` or `postgres://…`), and both backends pass the same contract test suite. Snapshots and alert state changes are append-only, enforced by triggers in both databases (PostgreSQL also refuses `TRUNCATE`), so "what was open on March 3rd" stays answerable.
- **Rate limits are respected.** The client honors `x-ratelimit-*` and `retry-after` headers and uses conditional requests where GitHub supports them.
- **No authentication in v1.** The server binds to `127.0.0.1` by default. The data it holds is a list of your weak spots, so please don't expose it as-is.

## License

Licensed under the [European Union Public Licence v. 1.2](LICENSE) (EUPL-1.2).
