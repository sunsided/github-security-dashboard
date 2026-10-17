# GitHub Security Dashboard

A self-hosted dashboard that collects security alerts and repository health data from the GitHub API and puts every repository I care about on one ranked page.

This exists because GitHub shows Dependabot, code scanning and secret scanning alerts per repository, in that repository's Security tab, and nowhere else I was looking. With a handful of repositories in an enterprise organization, a number of my own under [sunsided](https://github.com/sunsided) and some external ones I depend on, "open each Security tab and squint" stopped being a process. The alert emails I expected never showed up either (that one is probably a notification setting, but the point stands).

The idea is simple: a small Rust server polls the GitHub API on a schedule, normalizes alerts into critical, high, medium and low, keeps snapshots in a database, and serves a SvelteKit UI that sorts repositories by how much attention they need. Next to the alerts it records the usual health signals: open issues and pull requests, contributors, commit count, tags and releases, and how long ago anyone last committed.

## Status

Work in progress. The plan, roughly in order:

1. Workspace scaffold, configuration, personal access token auth, repository stats via GraphQL, pluggable storage with an SQLite backend, and a minimal table UI.
2. Alerts from Dependabot, code scanning and secret scanning (organization-wide endpoints where possible, per repository otherwise), severity scoring and a detail page.
3. GitHub App authentication.
4. External repositories: when I can't read their alerts (GitHub only shows them to admins and security managers), the server pulls the dependency SBOM and matches it against [OSV](https://osv.dev). Those numbers are labeled as estimates, because that's what they are.
5. A PostgreSQL backend for keeping the audit history long term.
6. A digest of newly opened alerts by email or Slack.

## Design notes

- **Storage is pluggable.** The application talks to a `Store` trait; SQLite is the default, PostgreSQL is planned for audit-grade retention. Snapshots and alert state changes are append-only, so "what was open on March 3rd" stays answerable.
- **Rate limits are respected.** The client honors `x-ratelimit-*` and `retry-after` headers and uses conditional requests where GitHub supports them.
- **No authentication in v1.** The server binds to `127.0.0.1` by default. The data it holds is a list of your weak spots, so please don't expose it as-is.

## License

Licensed under the [European Union Public Licence v. 1.2](LICENSE) (EUPL-1.2).
