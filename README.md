# GitHub Security Dashboard

[![CI](https://github.com/sunsided/github-security-dashboard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sunsided/github-security-dashboard/actions/workflows/ci.yml)

A self-hosted dashboard that collects security alerts and repository health data from the GitHub API and puts every repository I care about on one ranked page.

This exists because GitHub shows Dependabot, code scanning and secret scanning alerts per repository, in that repository's Security tab, and nowhere else I was looking. With a handful of repositories in an enterprise organization, a number of my own under [sunsided](https://github.com/sunsided) and some external ones I depend on, "open each Security tab and squint" stopped being a process. The alert emails I expected never showed up either (that one is probably a notification setting, but the point stands).

The idea is simple: a small Rust server polls the GitHub API on a schedule, normalizes alerts into critical, high, medium and low, keeps snapshots in a database, and serves a SvelteKit UI that sorts repositories by how much attention they need. Next to the alerts it records the usual health signals: open issues and pull requests, contributors, commit count, tags and releases, and how long ago anyone last committed.

## Before you run it

The dashboard knows exactly where your repositories are weakest, and out of the box it doesn't ask who's looking: with `[login] mode = "none"`, the default, the API and the UI answer anyone who can reach them. What they always guard against is other websites, through a host allowlist, a request header browsers won't send cross-site, and an origin check on the live-update socket.

That's fine on `localhost`, which is where the server listens by default. Anywhere else, turn on sign-in, either by letting an authenticating proxy vouch for users or by having the server sign them in itself with OpenID Connect (see [Signing in](#signing-in)), and add the public hostname to `allowed_hosts`.

On the GitHub side it only ever reads: a token or App with the read-only permissions listed under [Authentication](#authentication) is all it gets.

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
| `task docker:build` | The container image, see [Running in a container](#running-in-a-container) |

For a sense of scale: the first run against my own account (718 repositories, plus two external ones) takes about three minutes and some 700 requests, most of them contributor counts. Later runs reuse ETags where GitHub supports them, and those don't count against the quota.

Alerts are cheap for organizations (one request per source covers every repository, provided the token belongs to an owner or security manager) and comparatively expensive for user accounts, where every repository needs three requests of its own. That is why archived repositories and forks are skipped by default (`collector.alerts.skip_archived`, `skip_forks`). With those defaults, a full run over my account, alerts included, takes a little under four minutes. The resulting numbers match what GitHub's Security tab shows, down to repositories with a couple of hundred open Dependabot alerts.

Every alert state change is written to an append-only log, which the Activity page shows. "Fixed" and "dismissed" are told apart by looking up alerts individually once they drop out of the open list; a source that couldn't be read in a run never closes anything, so a flaky 503 doesn't rewrite history.

## Running in a container

Version tags (and manual runs of the Release workflow) publish an image to `ghcr.io/sunsided/github-security-dashboard`. It is built `FROM scratch`: a statically linked (musl) server with the UI embedded, the CA certificates it needs to reach GitHub, and its CycloneDX SBOM at `/server.cdx.json`. There is no shell, package manager or libc in it, and it runs as user `65532`.

Every published image comes with a build provenance attestation and an SBOM attestation, both signed with the workflow's identity. To check an image before running it:

```sh
gh attestation verify oci://ghcr.io/sunsided/github-security-dashboard:1.2.3 --owner sunsided
```

The server reads its configuration from `/config/config.toml` (`DASHBOARD_CONFIG`) and works in `/data`, where the default SQLite database ends up; mount a volume there, or point `storage.url` at PostgreSQL. Inside a container the loopback default for `listen` is unreachable from outside, so the mounted config needs `listen = "0.0.0.0:8080"`, the hostname under `allowed_hosts`, and, per [Before you run it](#before-you-run-it), sign-in. Secrets come in as environment variables, as everywhere else:

```sh
docker run -p 8080:8080 --env-file .env \
  -v ./config.toml:/config/config.toml:ro -v dashboard-data:/data \
  ghcr.io/sunsided/github-security-dashboard:1.2.3
```

Kubernetes probes can use `GET /healthz`, which answers regardless of `Host`. `task docker:build` builds the image locally, `task docker:sbom` writes just the SBOM to `sbom/`.

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

## Signing in

`[login] mode` picks one of three ways to decide who gets in. The first, `none`, is no sign-in at all. The other two put a guard in front of everything except the sign-in flow itself and `/healthz` (for liveness probes): API calls without a signed-in user get `401`, and `[login.allow]` narrows the signed-in users down further by email address, email domain or group. Only addresses the identity provider marks as verified count there, since some providers let users enter whatever address they like.

**`proxy`: someone in front already checked.** This is the setup I had in mind for Kubernetes, with [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) or an ingress with single sign-on in front of the pod. By default the server doesn't take the proxy's word for it, but verifies the token the proxy passes along: with oauth2-proxy and `--pass-authorization-header`, that's the user's ID token in the `Authorization` header. The server fetches the issuer's discovery document at start-up, checks the signature against its published keys, and requires the configured issuer and audience (for ID tokens, the proxy's client ID; without an audience, any token the provider ever issued to any application would do). Only asymmetric signatures are accepted.

```toml
[login]
mode = "proxy"

[login.proxy]
issuer = "https://accounts.example.org"
audiences = ["oauth2-proxy"]
sign_out_url = "/oauth2/sign_out"
```

Not every proxy has a token worth verifying: oauth2-proxy with the GitHub provider forwards an opaque GitHub token. For those, `trust = "headers"` believes `X-Forwarded-User`, `X-Forwarded-Email` and `X-Forwarded-Groups` instead, but only from the addresses in `trusted_proxies`, and the server refuses to start without them. In a cluster that means the pod network of the proxy, plus a `NetworkPolicy` so nothing else can talk to the dashboard directly; anyone who can, can claim to be anyone.

In an Istio mesh the sidecar (or waypoint) has usually checked the token already, through a `RequestAuthentication`, and checking the signature a second time only adds a dependency on the identity provider. `trust = "istio"` skips it: the server still insists on a well-formed, unexpired token from the configured `issuer` for one of the configured `audiences` (both required, since the mesh may accept tokens from more than one issuer or for other applications), but believes the signature. Istio removes the token after checking it unless `forwardOriginalToken` is set; alternatively, point `payload_header` at the header `outputPayloadToHeader` fills, and the server reads the claims from there.

```yaml
apiVersion: security.istio.io/v1
kind: RequestAuthentication
metadata:
  name: security-dashboard
spec:
  selector:
    matchLabels:
      app: security-dashboard
  jwtRules:
    - issuer: https://accounts.example.org
      jwksUri: https://accounts.example.org/.well-known/jwks.json
      audiences: [security-dashboard]
      forwardOriginalToken: true
---
# RequestAuthentication only rejects invalid tokens; requests without one
# pass. This makes a valid token mandatory, except for the probe endpoint.
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: security-dashboard
spec:
  selector:
    matchLabels:
      app: security-dashboard
  action: ALLOW
  rules:
    - from:
        - source:
            requestPrincipals: ["*"]
    - to:
        - operation:
            paths: ["/healthz"]
```

```toml
[login.proxy]
trust = "istio"
issuer = "https://accounts.example.org"
audiences = ["security-dashboard"]
```

The `AuthorizationPolicy` is not optional here. Without it, a request without a token reaches the server untouched, and with `payload_header` that includes a payload header the client made up itself. The same goes for any path to the pod that doesn't pass through the mesh (an excluded port, `kubectl port-forward`): the server can't tell a forged token from a real one in this mode, and says so in its log at start-up.

With sidecars, there is one more lock worth adding. The sidecar hands inbound requests to the application from `127.0.0.6`, so `trusted_proxies = ["127.0.0.6/32"]` turns away anything that reached the port without going through it. This doesn't carry over to ambient mode: there the application sees the original client's address, and the `AuthorizationPolicy` (enforced by ztunnel or a waypoint) is the guard.

**`oidc`: the server signs users in itself.** For when there is no proxy, the server is an OpenID Connect client of its own. It uses the authorization code flow with PKCE (S256), state and nonce, which is what OAuth 2.1 leaves standing, verifies the ID token like above, and keeps the user in a signed, `HttpOnly`, `SameSite=Lax` session cookie (with the `__Host-` prefix and `Secure` on HTTPS). Register `https://<your host>/auth/callback` as the redirect URL with the provider; the client secret and the session key come from environment variables, like every other secret here:

```toml
[login]
mode = "oidc"

[login.oidc]
issuer = "https://accounts.example.org"
client_id = "security-dashboard"
client_secret_env = "OIDC_CLIENT_SECRET"
redirect_url = "https://security.example.org/auth/callback"
session_key_env = "SESSION_KEY"   # 32+ bytes; shared by all replicas

[login.allow]
domains = ["example.org"]
```

Without `client_secret_env` the server acts as a public client and relies on PKCE alone. Without `session_key_env` it picks a random key at start-up, which works for a single instance but signs everyone out on every restart. Sessions last `session_ttl` (8 hours by default) and aren't refreshed; when one runs out, the UI sends the browser through the provider again, which usually doesn't ask for anything. Signing out ends the dashboard's session only, not the one at the provider.

Either way, the UI shows who is signed in, and the live-update tokens carry that user's ID as their `sub`. Both modes depend on the identity provider being reachable at start-up, so a typo in the issuer fails right away rather than at the first sign-in.

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

The connection is authenticated with a short-lived token that the UI fetches from `POST /api/realtime/token` and sends as its first message; a socket without a valid token in time is closed. Browsers can't set headers on WebSocket connections, which is why the token travels inside the protocol; since the token endpoint sits behind sign-in like the rest of the API, so does the live connection. The tokens are HS256 JWTs in [Centrifugo](https://centrifugal.dev)'s connection-token format, so swapping in a real Centrifugo later is a server-side change. With `[realtime] signing_key_env` the key can be shared with it; without, a random key is generated at start-up and clients simply fetch a new token after a restart.

## Status

Work in progress. The plan, roughly in order:

1. ~~Workspace scaffold, configuration, personal access token auth, repository stats via GraphQL, pluggable storage with an SQLite backend, and a minimal table UI.~~ Done.
2. ~~Alerts from Dependabot, code scanning and secret scanning (organization-wide endpoints where possible, per repository otherwise), severity scoring and a detail page.~~ Done.
3. ~~GitHub App authentication.~~ Done.
4. ~~External repositories: when I can't read their alerts (GitHub only shows them to admins and security managers), the server pulls the dependency SBOM and matches it against [OSV](https://osv.dev). Those numbers are labeled as estimates, because that's what they are.~~ Done.
5. ~~A PostgreSQL backend for keeping the audit history long term.~~ Done.
6. ~~A digest of newly opened alerts by email or Slack.~~ Done, as a daily digest to Slack and CloudEvents webhooks.
7. ~~Signing in, behind an authenticating proxy or with OpenID Connect.~~ Done.

## Design notes

- **Storage is pluggable.** The application talks to a `Store` trait; SQLite is the default, PostgreSQL the choice for keeping the audit history somewhere with backups and a retention policy. `storage.url` decides (`sqlite://dashboard.db` or `postgres://…`), and both backends pass the same contract test suite. Snapshots and alert state changes are append-only, enforced by triggers in both databases (PostgreSQL also refuses `TRUNCATE`), so "what was open on March 3rd" stays answerable.
- **Rate limits are respected.** The client honors `x-ratelimit-*` and `retry-after` headers and uses conditional requests where GitHub supports them.
- **Sign-in is optional.** The server binds to `127.0.0.1` and has no sign-in by default; see [Signing in](#signing-in) for running it anywhere else.

## Contributing

This is a personal project that grew out of my own itch, built in the open because others seem to have the same one. Issues and pull requests are welcome; answers may take a while, and there are no promises about features or timelines. Security problems in the dashboard itself go through [SECURITY.md](SECURITY.md), not the issue tracker.

## License

Licensed under the [European Union Public Licence v. 1.2](LICENSE) (EUPL-1.2).
