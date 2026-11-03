# Changelog

Format: Keep a Changelog. Versions follow SemVer. The CLI, daemon, and tray ship together.

## [Unreleased]

## [0.1.0-alpha] - 2026-11-03

First public release. The CLI, daemon, and tray ship as one version; desktop bundles are unsigned and installed by hand.

### Added

- Host daemon with a built-in HTTPS edge, on-demand leaf certificates, and an HTTP/1.1 proxy; no Caddy in the runtime path
- `.test` names served by a built-in DNS server with lazy OS resolver setup on macOS, Linux, and Windows; the TLD is fixed
- Access by request on first run: a leaf without a credential asks the host, the operator approves or denies with `testd requests`, `testd approve`, `testd deny`, or the dashboard, and the tray raises a notification while a request waits
- Per-name grants: a token covers exactly the names the operator approved, and publishing another name raises its own request
- `testd run` with `name:port` entries, token auth, reconnect, and process wrapping
- Named profiles in `~/.config/testd/leaf.toml` and one-off `--host`/`--hosts` selection
- Loopback dashboard with live names, shares, quick launches, access requests, issued tokens, and certificate controls; `testd dashboard` prints its authenticated URL, and tray and CLI links carry the per-run token
- Supervised quick launches: probe before registering, detect the child's listening port, rebind live, and stop the process group
- Tray app with a setup wizard, health notices, quick launches, certificate management, and launch at login; its menu lists live names with open and stop beneath each, and saved quick launches with start or stop
- `testd share` through spawned `cloudflared`, `ngrok`, or `tailscale serve`; the daemon owns the tunnel for the registration's lifetime
- `testd init`, `doctor [--json] [--fix]`, `url`, `uninstall`, and `export-caddyfile`
- `doctor` checks the resolver, the root trust, and the edge, repairs them with `--fix` (macOS DNS cache and mDNSResponder, Windows NRPT rules and the machine root store), and reports when an external front owns TLS
- Host opt-ins: `[host] allow_remote_targets` for explicit remote targets, `[host] trust_forwarded_for` for a trusted front proxy, and `[host] edge_enabled = false` to drop only the built-in TLS listener while plain HTTP routing stays up
- Homebrew formula and architecture-aware cask, launchd and systemd units, and an NSIS installer; building from source needs Rust 1.89, or 1.90 for the tray
- Tag-triggered release automation: CLI archives, tray bundles, workspace SBOMs, generated Homebrew definitions, checksums, and a draft GitHub release
- Cross-platform release validation for the host, browser, desktop, and artifact suites, including fixture self-tests for the privileged resolver and trust integration

### Security

- One operator secret admits registrations; issued leaf tokens are stored with mode `0600`, shown only by ID, and revocable, and revoking one closes the connections it admitted and releases its names
- Secret files use `0600` from creation and `O_NOFOLLOW`; root CA installation never stages a certificate in a user-writable temp file, and Windows embeds the audited helper instead of writing a mutable script
- The HTTPS edge mints certificates only for registered names and the `testd` dashboard name, not arbitrary SNI values
- Edge connections are bounded per source, the TLS handshake is timed out, and the certificate cache is bounded; intake frames, HTTP headers, and setup reads and writes have limits
- Remote leaves can only target their own address unless `[host] allow_remote_targets` is set, and client-supplied `X-Forwarded-For` is ignored unless a front proxy is trusted
- The dashboard binds to loopback only, and its mutations and `/api/local/*` require the per-run control token
- Remote registration is plain TCP and desktop bundles are unsigned: use a trusted network or a separately secured transport, and verify `SHA256SUMS` before installing
