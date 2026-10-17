# Security policy

## Reporting a vulnerability

Please don't open a public issue for a vulnerability in the dashboard itself. Use GitHub's private vulnerability reporting instead: the repository's **Security** tab, then **Report a vulnerability**. That keeps the details between us until a fix is out.

A useful report says what is affected, how to reproduce it, and what an attacker gains. This is a personal project, so a reply can take a few days; I'll confirm that I've seen it and keep you posted while I work on a fix. If you want to be credited in the fix, say so.

## Supported versions

There are no releases yet. Fixes go to `main`; please test against it.

## Scope

In scope:

- the server: REST API, live-update WebSocket and its tokens, collector, digest delivery
- the web UI
- the defaults in `config.example.toml`

Known and documented, so no report needed:

- **No login.** Anyone who can reach the API can read it. The server binds to `127.0.0.1` by default, and the README asks for an authenticating proxy anywhere else.
- **The key pair in `crates/gh/tests/fixtures/`** is a throwaway for tests and grants access to nothing.

Out of scope:

- alerts the dashboard shows about the repositories it monitors; those belong to the repositories in question
- vulnerabilities in dependencies that have no demonstrated impact on the dashboard

## What the dashboard already does

For orientation when assessing an issue:

- GitHub tokens, App private keys and webhook URLs come from environment variables or files, never from `config.toml`, and stay out of logs and error messages.
- Requests are only answered for `localhost`, `127.0.0.1`, `[::1]` and hostnames listed in `allowed_hosts` (DNS rebinding).
- Requests that change anything require a custom header that browsers only send after a CORS preflight, which the server never grants (CSRF).
- The live-update socket refuses foreign origins before upgrading, and delivers nothing until it receives a valid, unexpired token signed by the server.
- Alert history and repository snapshots are append-only; the databases reject updates and deletes on those tables.
- On GitHub, the dashboard only reads.
