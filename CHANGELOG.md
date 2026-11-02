# Changelog

Format: Keep a Changelog. Versions follow SemVer. The CLI, daemon, and tray ship together.

## [Unreleased]

### Added

- Release self-test fixtures use `CN=testd root testing`, so they cannot be mistaken for a real host root during snapshot and restore
- `tests/release/macos-resolver-probe.sh` snapshots, configures, checks, removes, and restores a macOS `/etc/resolver` route with evidence kept on disk
- `tests/release/system_state.py --self-test` snapshots, installs a fixture, restores, and verifies the real resolver and trust artifacts on a disposable host; CI runs it on Linux, macOS, and Windows
- Gated `host-system` CI job for the full privileged host suite, enabled per dispatch or with the `TESTD_CI_HOST_SYSTEM` repository variable
- `testd dashboard` prints the authenticated loopback dashboard URL; tray and CLI links carry the per-run dashboard token
- `[host] allow_remote_targets` and `[host] trust_forwarded_for` opt-ins for explicit remote targets and a trusted front proxy
- Bounded edge connections, per-source connection limits, a TLS handshake timeout, and a bounded on-demand certificate cache

### Changed

- The loopback dashboard is live: it reads a token-authenticated event stream, and name, share, launch, request, and token changes are pushed to the page instead of polled
- The tray menu lists live names with open and stop beneath each one, and saved quick launches with a disabled heading plus start or stop, instead of only opening the dashboard section
- New root certificates include a random pronounceable covo name in the common name, so multiple installations are distinguishable in the keychain; legacy `testd root` names are still recognised
- `tests/release/run.py host --system` snapshots the resolver and trust integration it changes and restores it afterwards instead of refusing to run on a host that already has testd integration; `--restore-report` recovers a report after a hard kill
- CLI/daemon MSRV raised to Rust 1.89; tray MSRV remains Rust 1.90
- The host TLD is fixed to `.test`; `init --tld`, `TESTD_TLD`, the `[host] tld` key, and the `*.localhost` mode are removed, and an old configured `tld` value is ignored

### Fixed

- `[host] edge_enabled = false` disables only the built-in TLS listener; the plain HTTP routing listener still starts for an external front or a `tailscale` share, and `doctor` reports that the external front owns TLS trust instead of requiring the testd root
- The dead-upstream edge test closes its probe port before the request: macOS drops the SYN for a socket that is bound but never listens, so the test received a timeout instead of the refusal it asserts
- The browser release suite starts a headless host when none is listening and stops only a host it started, so the suite no longer leaves the fixture retrying for an hour; a host with another TLD is refused
- The browser page can restart a host the suite started and reports the result back to the page, so the certificate-renewal check no longer needs a separate terminal; a pre-started host is left alone
- The HTTPS edge keeps the WebSocket handshake response headers, including `Sec-WebSocket-Accept`, so upgrades through the edge work in browsers again
- macOS resolver setup and teardown flush the DNS cache and reload mDNSResponder, so a new or removed `/etc/resolver/<tld>` route takes effect without a stale negative cache; `doctor --fix` also rewrites the route when resolution still fails
- `doctor` answers `testd.<tld>` from a temporary DNS server when the host is not running, so the resolution check tests the OS route instead of requiring `testd host`
- macOS root trust is keyed by every certificate's SHA-1 rather than the common name, so duplicate `testd root` certificates from failed runs are replaced or removed and `doctor --fix` refreshes the exact root
- macOS root cleanup reads the certificate list before hashing every entry itself and deletes each SHA-1 with `-t`, so a failed run cannot leave duplicate `testd root` entries or their trust settings behind
- The browser suite checks the OS resolver through `testd doctor --json` before opening the page, and the page can save a failing report with its observations unchecked instead of forcing a false confirmation
- The Windows NRPT snapshot compares and re-adds namespaces and name servers as canonical, duplicate-free values, so a rule whose lists hold more than one entry, including the duplication an earlier restore left behind, no longer reports a matching rule as missing
- The Windows NRPT snapshot enumerates the JSON array before filtering, so restoring two or more rules no longer nests them into a single element
- Windows quick-launch checks hand curl its JSON body through a temporary file, because PowerShell 5.1 breaks a native argument that holds both spaces and quotes
- Windows system checks look the installed root up in the certificate store instead of parsing certutil's localized text, the restore keeps an empty NRPT set an array so strict mode does not abort it, and it reports only meaningful properties it could not recreate
- The Windows system-state restore and the elevated helper remove NRPT rules with the cmdlet's own `-Force`, the only switch that suppresses its confirmation, fail loudly when a removal does not work, and force `certutil -delstore`
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
- Dashboard mutations and `/api/local/*` now require the per-run control token; a bare dashboard page is read-only
- The HTTPS edge only mints certificates for registered names and the `testd` dashboard name, not arbitrary SNI values
- Remote leaves can only target their own address unless `[host] allow_remote_targets` is enabled; client-supplied `X-Forwarded-For` is ignored unless a front proxy is explicitly trusted
- Root CA installation no longer stages the certificate in a user-writable temp file; Windows embeds the audited helper source instead of writing a mutable script
- The hosts helper only writes `/etc/hosts` when run as root, and `init` merges host config instead of replacing user settings; uninstall keeps local state when system cleanup fails
- Secret files use `0600` from creation and `O_NOFOLLOW`; tailscale share shutdown preserves unrelated serve handlers

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
