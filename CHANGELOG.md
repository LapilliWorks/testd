# Changelog

Format: Keep a Changelog. Versions follow SemVer. The CLI, daemon, and tray ship together.

## [Unreleased]

### Added

- `tests/release/system_state.py --self-test` snapshots, installs a fixture, restores, and verifies the real resolver and trust artifacts on a disposable host; CI runs it on Linux, macOS, and Windows
- Gated `host-system` CI job for the full privileged host suite, enabled per dispatch or with the `TESTD_CI_HOST_SYSTEM` repository variable

### Changed

- `tests/release/run.py host --system` snapshots the resolver and trust integration it changes and restores it afterwards instead of refusing to run on a host that already has testd integration; `--restore-report` recovers a report after a hard kill
- CLI/daemon MSRV raised to Rust 1.89; tray MSRV remains Rust 1.90

### Fixed

- Windows host checks capture expected failures through one helper that relaxes the error preference for the call, so PowerShell 5.1 does not turn their redirected stderr into a terminating error
- `host --system` runs the platform script on the operator's terminal, so its own sudo check and `doctor --fix` find the cached ticket
- Windows host checks read the expected 404s as status codes instead of letting `curl --fail` write to stderr, which PowerShell 5.1 turns into a terminating error
- System restore reloads a consumer only when its file changed, follows the Debian/Ubuntu or Fedora/RHEL CA anchor, and times out a privileged command instead of stalling silently
- The hosts helper replaces its managed block in the shell instead of awk, and its host check uses a fixed hosts file instead of the system one
- Linux and macOS host checks probe the cached sudo credential through the operator's terminal, so a ticket from `sudo -v` in the same shell is recognised
- Windows system-state checks read the machine root store through .NET instead of the `Cert:` provider, which `-Command` does not always load, and the restore fixture imports that module before using its path
- Windows release checks stay readable on a non-English console: PowerShell children and the host scripts emit UTF-8, captured streams, logs, and reports decode and write as UTF-8, redirected runner output uses the console code page, and the NRPT comparison message parses under PowerShell 5.1
- Windows clippy no longer sees the Unix-only share exposure import
- Restored notify-rust 4.18 so macOS and Windows notification action callbacks compile
- Windows supervisor test fixtures use noninteractive sleep instead of timeout, which exits with redirected stdin
- Edge tests allow delayed Windows connection refusal while keeping the 502 and 504 assertions distinct
- Explicit, documented exceptions for the three informational zbus merger advisories; vulnerability checks remain enforced

## [0.1.0] - 2026-11-01

### Added

- Host daemon with a built-in HTTPS edge, on-demand leaf certificates, and an HTTP/1.1 proxy; no Caddy in the runtime path
- `.test` names served by a built-in DNS server, with lazy OS resolver setup and a `*.localhost` mode that needs no resolver
- `testd run` with `name:port` entries, token auth, reconnect, and process wrapping
- Named profiles in `~/.config/testd/leaf.toml` and one-off `--host`/`--hosts` selection
- Loopback dashboard with live names, quick launches, shares, and certificate controls
- `testd share` through spawned `cloudflared`, `ngrok`, or `tailscale serve`; the daemon owns the tunnel for the registration's lifetime
- Supervised quick launches: probe before registering, detect the child's listening port, rebind live, and stop the process group
- Tray app with setup wizard, health notices, quick launches, certificate management, and launch at login
- Request-on-first-run: a leaf with no credential asks the host for a token; `testd requests`, `testd approve`, `testd deny`, `testd tokens`, and the dashboard's Access card decide it
- Per-name grants: a token covers the names the operator approved, and publishing any other name raises its own approval request
- Tray notification and a light-blue icon while a leaf token request is waiting
- `testd init`, `testd doctor [--json] [--fix]`, `testd url`, `testd uninstall`, and `testd export-caddyfile`
- Homebrew formula and architecture-aware cask generated with real release digests, launchd and systemd units, NSIS-only Windows bundle, and host test harness
- Tag-triggered public release CI: CLI archives, tray bundles, workspace SBOMs, checksums, and a draft GitHub release
- Cross-platform release-validation runner with host, browser, desktop, and artifact suites
- CLI `--version` and local PKI validity checks in `doctor`

### Changed

- Redesigned the loopback dashboard with light and dark themes, a footer, and a free-version label
- Quick launches in the dashboard use the daemon's saved-launch shape; the previous form sent fields the daemon rejected
- Dashboard names now offer **stop** (end the leaf, keep its grants) and **delete** (remove that one name's grant, behind a confirmation); the leaf must request the name again, while its other names keep running
- Revoking a token now closes the connections admitted with it, releases all of its names, and leaves the leaf asking for a new grant on its next run

### Fixed

- Token revocation reconciles all live connections even when many revocations arrive together; closure bypasses full reply queues and stalled writers
- Additional-name requests are cancelled on disconnect, including pipelined connections; partial frames survive approval
- Access ids beginning with a hyphen are accepted by the CLI and host-test harness
- Sharing still follows name removal when a registration-event subscriber falls behind
- Expiring local intermediates renew without changing root trust; their previous certificate and key are backed up before replacement

### Security

- One operator secret admits registrations; the secret is generated by `testd init` and presented as `TESTD_TOKEN`
- Issued leaf tokens are stored on the node with mode `0600`, shown only by id, and revocable; the operator secret is never handed to a remote leaf
- The dashboard binds to loopback only and requires a custom request header for mutations
- Leaf certificates are minted on demand and cached for 75% of their 24-hour lifetime
- Intake connections, NDJSON frames, HTTP headers, setup reads, and writes have resource limits; idle registered leaves remain connected
- Remote registration uses plain TCP: use a trusted network or a separately secured transport
