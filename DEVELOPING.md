# Developing

## Prerequisites

- Rust toolchain from `rust-toolchain.toml`; CLI/daemon MSRV 1.89, tray MSRV 1.90
- Python 3.12 or newer for release tooling and reports; Bun for browser fixtures
- `cargo-cyclonedx` for workspace SBOM generation
- `cargo-nextest` for tests and `cargo-deny` for dependency checks
- `cargo-tauri` and the platform's Tauri prerequisites for the tray app: Xcode command-line tools on macOS, WebKitGTK/GTK on Linux, MSVC on Windows

## Build

From the repository root:

```sh
cargo build --release -p testd   # CLI and daemon
cargo tauri build                # tray app
```

The workspace includes `testd-gui`. On a machine without GTK/WebKit, add `--exclude testd-gui` to workspace test and clippy commands. CI installs the Tauri system prerequisites and checks the full workspace.

## Test

```sh
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo deny check
```

## Release validation

Run against the release candidate on each supported host. Child stdout and stderr are streamed live to the matching terminal streams and retained together in each command's log. Reports, logs, OS information, and the commit id are saved under `~/.local/share/testd/release-checks/` (`%LOCALAPPDATA%/testd/release-checks/` on Windows). Use Python 3.12 or newer; on Windows replace `python3` with `python` or `py -3`.

```sh
# Automated code/dependency/MSRV checks; omit --gui if Tauri prerequisites are absent
python3 tests/release/run.py core --strict --gui

# OS integration: sudo -v first on macOS/Linux, or use an elevated shell on
# Windows. The suite snapshots the integration `doctor --fix` changes and
# restores it afterwards. No testd daemon may be running.
python3 tests/release/run.py host --system --service

# Download the candidate CLI archive, SHA256SUMS, and desired bundles into one directory
python3 tests/release/run.py artifacts --artifacts ~/Downloads/testd-candidate \
  --require-checksums --host --system --service
# Optional upgrade check: add --previous-bin /path/to/previous/testd

# Real browser checks; starts a headless host if none is running
python3 tests/release/run.py browser --tld test
python3 tests/release/run.py browser --tld localhost

# Interactive desktop checklist, for example on macOS
python3 tests/release/run.py desktop --app /Applications/Testd.app
```

Reports contain local PKI and test credentials and are private by default. Do not attach the entire report directory to a public issue; share only reviewed logs/JSON, never private keys or credentials.

The browser suite uses Bun fixtures and publishes `app.releasecheck`, `api.releasecheck`, and a dead-upstream name. It checks HTTPS, WebSocket idle survival, streamed SSE, a 100 MiB upload, and project-cookie scope. It starts a headless host when none is listening and stops only a host it started; initialize the host with `testd init` first. For a non-localhost TLD it checks `testd doctor --json` first, so a missing OS resolver route fails before the browser opens. When the suite started the host, the page's restart button replaces the manual daemon restart for the renewal check; a pre-started host is left alone and must be restarted manually. Run it in every supported browser, complete the certificate and error-response observations, and save the JSON report from the page. A failed run can still be saved with the observations unchecked; the report records it as a failure. Ctrl+C removes only the fixture processes and registrations. For localhost mode, initialize the test host with `testd init --tld localhost`; for a high edge port, pass `--edge-port 8443`. The suite does not install trust or change the resolver.

The `service` suite (also available as `host --service` or `artifacts --service`) exercises the real launchd/systemd user-session supervisor: start, TLS, forced-crash restart, and stop. It stages a uniquely named service with an isolated home and high ports, retains the generated unit/plist in the report, and removes only that new service when done. Run in a real user session with a working `systemctl --user` or launchd GUI domain; Windows CLI services are not shipped, so Windows supervision is covered by the tray login checks.

The desktop suite launches the supplied app/installer and records each existing GUI checklist item as pass, fail, or not applicable with evidence. Use a clean disposable machine for first-install, setup, actual login, upgrade, and uninstall checks; the runner restores any integration the session installs, but not a pre-existing installation. Padlocks, UAC, tray behavior, and login cannot be proven by an HTTP-only script. Skips and unanswered checks remain visible in `report.json`; they are not counted as passes. An interrupted desktop checklist or browser run without a saved report exits `2` (incomplete); failed checks exit `1`.

`host --system` snapshots the integration `doctor --fix` will change, runs the checks, then restores and verifies that snapshot. Nothing outside the throwaway TLD and the `testd root` and `testd root testing` names is touched, so the suite does not require a clean machine; it requires that no testd daemon is running. See [System integration](#system-integration) for the recorded artifacts and the recovery path. Plain `host` does not change system integration. `--bin /path/to/testd` runs a candidate CLI without rebuilding it.

## Contents

- [Quickstart](docs/quickstart.md) for using the installed tool
- [Host testing](#host-testing) for checks that need real machines
- [Browser validation](#browser-validation) for manual checks in real browsers
- [Release](#release) for the release checklist and artifacts
- [Homebrew](#homebrew) for the formula and cask
- [Signing and notarization](#signing-and-notarization) for macOS notarization and Windows Authenticode

## Host testing

The container suite covers the protocol, the edge, registration ownership, DNS answers, CLI behavior, sharing, and the standalone operator secret. The checks below cover OS resolver integration, trust stores, privileged ports, packaging, code signing, and the tray.

Run them on real machines, not inside the dev container. A macOS, Linux, and Windows host are needed for full coverage. Use a dedicated test machine or a VM: the optional system checks change the OS resolver and trust store.

### What the scripts cover

| Script | Checks |
|---|---|
| `tests/host/linux.sh` | resolver route, CA trust, edge TLS, loopback dashboard, DNS A records, token requests, issued tokens, local registration, sharing, quick launches, URL actions, doctor state checks, launch-at-login entry, hosts helper, systemd unit |
| `tests/host/macos.sh` | resolver file, CA trust, edge, loopback dashboard, DNS, token requests, issued tokens, local registration, sharing, quick launches, URL actions, doctor state checks, launch-at-login entry, launchd plist |
| `tests/host/windows.ps1` | edge and proxy without system trust, loopback dashboard, NRPT and root trust when elevated, DNS on port 53, token requests, issued tokens, local registration, sharing, quick launches, URL actions, launch-at-login entry |
| `tests/host/gui-checklist.md` | setup wizard, tray, dashboard, click-to-open, single instance, quick launches, certificate controls, URL actions, packaging/signing |

The Linux and macOS scripts share their core checks in `tests/host/common.sh` and their helpers in `tests/host/lib.sh`; the platform scripts add the resolver, trust, and init-system sections.

The sharing checks start the daemon with `TESTD_TUNNEL` pointing at a fake provider, so they need no provider installed: start, list, refuse a second share, stop, refuse an unknown provider, and refuse a name that is no longer registered. The provider shapes themselves (cloudflared, ngrok, tailscale) are covered by `cargo test -p testd-daemon --test share`, which the Windows script cannot do because a PowerShell script is not a spawnable provider binary.

Local registration uses the operator secret that `testd init` writes into `[host] secret`; the standalone host has no accounts or roster. The scripts run the client on the node itself, where the default loopback profile uses that secret automatically; no `TESTD_TOKEN` is exported. A separate named profile with no credential requests a token, which the script approves and then revokes through `testd requests`, `testd approve`, and `testd tokens`.

The quick launch checks need `python3` (or `python` on Windows) to start a local HTTP server. They save a launch through the loopback dashboard, start it, check the name through the edge and DNS, stop it, and delete it.

Each script uses:

- a throwaway `HOME`/`%APPDATA%` retained under the persisted report directory,
- a throwaway TLD (`testdcheck` by default) so it does not collide with a real `.test` setup,
- a high HTTPS port (`8443`) so it does not need root for the edge,
- dedicated upstream ports for registration (`18080`) and quick launches (`18081`).

The scripts do **not** call sudo themselves. On Linux and macOS they use `--cacert` for HTTPS; on Windows they use `--insecure` for the edge and proxy checks because Schannel does not treat `--cacert` like OpenSSL. To also test the OS resolver and trust store, use `python3 tests/release/run.py host --system` with a cached sudo credential (Linux/macOS) or an elevated shell (Windows). The platform scripts refuse privileged checks without the runner's snapshot.

### Linux

Prerequisites: `bash`, `curl`, `python3`, `resolvectl` (for the optional system
check), `systemd-analyze` (optional). `sudo` must be available if
`TESTD_HOST_TEST_SYSTEM=1`.

```sh
cd testd
cargo build --release -p testd

# Core checks, no system changes
tests/host/linux.sh

# Optional: resolver + trust store; restored automatically afterwards
sudo -v
python3 tests/release/run.py host --system

# Same against an existing candidate binary
python3 tests/release/run.py host --system --bin target/release/testd
```

The system check writes `/etc/systemd/resolved.conf.d/90-testd.conf` and the
distro's CA anchor: `/usr/local/share/ca-certificates/testd-root.crt` with
`update-ca-certificates` on Debian and Ubuntu, or
`/etc/pki/ca-trust/source/anchors/testd-root.crt` with `update-ca-trust extract`
on Fedora and RHEL. Both are the same changes a real `testd doctor --fix` makes,
and both are restored from the snapshot.

### macOS

Prerequisites: `bash`, `curl`, `python3`, `plutil`, `dscacheutil`. Xcode
command-line tools are needed to build. `sudo` must be available if
`TESTD_HOST_TEST_SYSTEM=1`.

```sh
cd testd
cargo build --release -p testd

tests/host/macos.sh

sudo -v
python3 tests/release/run.py host --system
```

The system check writes `/etc/resolver/testdcheck` and installs the test root
into `/Library/Keychains/System.keychain`. Both are restored from the snapshot;
the upstream root is identified by its SHA-1, not by name, so an unrelated
`testd root` certificate is never deleted.

To probe only the `/etc/resolver` configure and unconfigure path, run:

```sh
tests/release/macos-resolver-probe.sh
```

It snapshots the current route, runs `doctor --fix`, checks `dscacheutil`,
`getaddrinfo`, `scutil --dns`, and the DNS server directly, removes the route
with `uninstall --keep-certificate`, checks again, then restores the original
file and mode. Evidence stays under `~/Library/Application Support/testd/resolver-probes/`.

### Windows

Prerequisites: PowerShell 5.1 or later, `curl.exe` (included with Windows 10
1803+), and a free port 53. The daemon uses port 53 for NRPT; if another
service owns it, the script fails at the DNS check.

Verified on Windows 10 22H2, build 19045.7807, with both the non-elevated and
elevated paths. Windows 11 is not yet verified; the NRPT, `certutil`, and
`curl.exe` paths are expected to be the same, but leave it to CI or another
tester before claiming Windows 11 support. The script prints the OS caption,
version, build, and architecture at the start of every run.

CI's `windows-latest` runner is Windows Server, not a desktop Windows 11 host.
It is useful for compilation and the CLI tests, but it does not replace the
NRPT and trust-store checks above.

```powershell
cd testd
cargo build --release -p testd

# Core checks: edge and proxy without system trust
powershell -NoProfile -ExecutionPolicy Bypass -File tests\host\windows.ps1

# Optional: NRPT + root trust. Open PowerShell with "Run as Administrator",
# then set the flag in that elevated session.
python tests\release\run.py host --system
```

The non-elevated run intentionally uses `curl --insecure --ssl-no-revoke` for
the edge and proxy checks. That validates routing and TLS minting without
requiring a trust-store change. The elevated run then calls
`testd doctor --fix`, checks the NRPT rule and the machine root store, and
repeats a request to `https://testd.<tld>/` without `--insecure` to prove the OS
trust path. The edge answers that name with 404 because the dashboard is not
proxied; any HTTP status means Schannel accepted the chain.

`testd init` and `testd doctor --fix` no longer need the whole process elevated
on Windows. Privileged actions are delegated to
`scripts/testd-elevated.ps1`, a closed-action helper that validates the TLD,
IPv4 address, certificate thumbprint, and CA constraints. If testd is not
elevated, Windows shows one UAC prompt for that helper only.

Cleanup is automatic: the snapshot taken before the checks removes the NRPT rule
for `.testdcheck` and the test root by thumbprint. Recovery after a hard kill:

```powershell
python tests\release\run.py --restore-report $env:LOCALAPPDATA\testd\release-checks\<stamp>-<id>
```

Windows NRPT rules cannot specify a port, which is why the daemon binds `:53`
there. If port 53 is occupied, stop the other service before running the test.

### Launch at login

The tray enables launch at login once, on its first start, through
`tauri-plugin-autostart`, and then exposes a **Launch at login** checkbox. The
checkbox asks the plugin for the current state after every click, so a failed
enable or disable corrects itself on the rebuild rather than drifting from the
OS.

| OS | Artifact | Check |
|---|---|---|
| macOS | `~/Library/LaunchAgents/dev.testd.host.plist` | `plutil -lint`, and `launchctl print gui/$(id -u)/dev.testd.host` |
| Linux | `~/.config/autostart/dev.testd.host.desktop` | has an `Exec=` line pointing at the tray binary |
| Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `dev.testd.host` | `Get-ItemProperty` returns a command line naming the tray |

The host scripts check the artifact when it exists and skip with the expected
path when it does not, because the tray has not run in a CLI-only session. The GUI
checklist covers the run and the toggle.

### Browser validation

The [Browser validation](#browser-validation) section holds the per-browser script: trust stores, padlock
and certificate expectations, WebSocket and SSE behaviour, cookie scope across
`app.example.test` and `api.example.test`, and the `*.localhost` mode. The host
scripts stop at the HTTP layer on purpose; they cannot judge a padlock.

### GUI

The tray is a public source build and an optional free release artifact. Run `python3 tests/release/run.py desktop --app <candidate>` to execute and record `tests/host/gui-checklist.md` against the same commit as the CLI. Attach/detach of existing processes is deferred and does not gate this release.

### Packaging and signing

These require credentials and hardware that do not belong in this repository:

- **macOS:** Developer ID certificate, notarization credentials, `codesign`,
  `spctl`, `xcrun stapler`.
- **Windows:** Authenticode certificate and SmartScreen reputation; verify with
  `Get-AuthenticodeSignature`.
- **Linux:** unsigned `.deb`, AppImage, and tarball; verify with `dpkg-deb -I`
  and an AppImage smoke run.

See [Release](#release) for the release checklist and `tests/host/gui-checklist.md`
for the per-artifact commands.

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `TESTD_BIN` | `target/release/testd` | Binary to test |
| `TESTD_HOST_TLD` | `testdcheck` | Throwaway TLD; must be 1 to 10 lowercase alphanumeric chars |
| `TESTD_HOST_EDGE_PORT` | `8443` | HTTPS edge port |
| `TESTD_HOST_APP_PORT` | `18080` | Test upstream port |
| `TESTD_HOST_LAUNCH_PORT` | `18081` | Quick-launch upstream port |
| `TESTD_HOST_TEST_SYSTEM` | `0` | Allow resolver and trust changes |
| `TESTD_HOST_SNAPSHOT` | unset | Snapshot directory written by `run.py --system` |

### System integration

`host --system` assumes no testd daemon is running and that the host's own
integration comes back afterwards. Before the checks run, `run.py` records every
artifact `doctor --fix` can change in `<report>/system-before/`:

| Platform | Artifacts | Reload |
|---|---|---|
| Linux (Debian, Ubuntu) | `/etc/systemd/resolved.conf.d/90-testd.conf`, `/usr/local/share/ca-certificates/testd-root.crt` | `systemctl reload systemd-resolved`, `update-ca-certificates` |
| Linux (Fedora, RHEL) | `/etc/systemd/resolved.conf.d/90-testd.conf`, `/etc/pki/ca-trust/source/anchors/testd-root.crt` | `systemctl reload systemd-resolved`, `update-ca-trust extract` |
| macOS | `/etc/resolver/<tld>`, every `CN=testd root <covo name>` (and legacy `CN=testd root` or `CN=testd root testing`) in the System keychain | keychain operations are per SHA-1 |
| Windows | NRPT rules for `.<tld>`, every `CN=testd root <covo name>` (and legacy `CN=testd root` or `CN=testd root testing`) in the machine root store | per thumbprint |

The manifest records file bytes, modes, SHA-256 digests, and every pre-existing
store entry. Restore puts back what the suite removed, removes what it added,
reloads each consumer, and then verifies the host against the manifest; the
result is the `system-restore` check. Restores are idempotent. A report that ran
system checks more than once keeps each snapshot as `system-before`,
`system-before-2`, and so on.

A run that is killed outright cannot restore itself. The snapshot stays on disk,
so recover with the report directory:

```sh
python3 tests/release/run.py --restore-report ~/.local/share/testd/release-checks/<stamp>-<id>
```

This works from any shell, needs the same sudo (or elevation) as the original
run, restores every snapshot in the report newest first, and exits non-zero if
the host does not match the snapshots afterwards. Direct runs of
`tests/host/*.sh` and `tests/host/windows.ps1` cannot do privileged checks,
because they have no snapshot to restore from.

### CI coverage

Three levels, in `.github/workflows/ci.yml`:

- `test` runs the release-script unit tests on `ubuntu-latest`, `macos-15`, and `windows-latest`. They use an in-memory host, so they cover the manifest and restore rules, not the commands.
- `system-restore` runs `python tests/release/system_state.py --self-test` on the same three runners. It snapshots the real paths, installs what `doctor --fix` would (a resolver file, a throwaway root certificate, and on Windows an NRPT rule plus machine root), restores, and verifies. It refuses to run where testd integration already exists, so the disposable runners are its target. It needs elevation and `openssl` on Linux and macOS; the trust reload runs only where the distro tool exists, and the resolver reload is left to `host-system` because it needs a running systemd-resolved.
- `host-system` runs the full `host --system` suite. It is gated: dispatch the workflow with `host_system` checked, or set the `TESTD_CI_HOST_SYSTEM` repository variable to `true`. It is off by default because it rewrites the runner's resolver and trust store, and Linux needs `systemd-resolved`, which the runner image ships stopped. The service suite is not in CI: runners have no user session bus for `systemctl --user`.

### System checks need a running daemon

The resolver, name-resolution, and trust checks query the live daemon: the DNS
server answers the query, `doctor --fix` re-reads the route, and the trust check
connects to the edge. The scripts restart the daemon if it went away, and skip
the section with a reason if it cannot start, so a dead daemon is not reported
as a broken resolver.

On Windows the trust check connects to `https://testd.<tld>/` **without**
`--insecure`: any HTTP status means Schannel accepted the chain from the machine
store.

### Interpreting failures

- `init` fails: check the printed log. The script uses a temporary home, so a
  pre-existing lock in your real home is not involved.
- `DNS listener` fails: another process owns the port. On Windows this is
  usually `:53`; on Linux/macOS it is `:7753`.
- `HTTPS listener` fails: the configured `edge_addr` is in use, or the binary
  cannot bind it.
- Dashboard TLS fails but `curl --insecure` works: the root is not trusted. On
  Windows, Schannel reports `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` for a private
  root and does not honor `--cacert` the way OpenSSL does; use
  `--ssl-no-revoke` and either `--insecure` before trust or the machine root
  store after `testd doctor --fix`.
- System resolver check fails after `doctor --fix`: inspect
  `resolvectl status` (the route is a global `DNS=`/`Domains=` pair) or
  `/etc/resolver/testdcheck` (macOS), and make sure the daemon is still running.
  On Linux, `doctor --fix` refuses to write the drop-in when systemd-resolved is
  inactive or already has global `DNS=`/`Domains=` configured, and names the
  setting it would have replaced.

## Browser validation

Manual checks that a name works in a real browser. Run on the host, or on another device that trusts the root.

### Preconditions

- `testd init` and `testd host` on the host; `testd doctor` exits `0`.
- A live registration: `testd run app.example:3000 -- <your dev server>`.
- The device trusts the root. Either `testd doctor --fix` on that device, import `<pki>/root.crt` into the browser's store, or fetch `http://127.0.0.1:7737/ca.crt` from the host and import it.

### Trust stores

| Browser | Store | Import |
|---|---|---|
| Chrome, Edge (Linux) | Browser certificate manager or platform integration; varies by package | Import `root.crt` as a trusted authority in the browser certificate manager and verify the actual package's trust behavior |
| Chrome, Edge (macOS), Safari | system keychain | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root.crt` |
| Chrome, Edge (Windows) | machine store | `certutil -addstore -f Root root.crt` |
| Firefox (all) | Profile NSS store, or system roots when enabled | Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import; trust the root for websites |

For NSS command-line imports, use `certutil -d sql:<actual browser profile directory> -A -t 'C,,' -n testd-root -i root.crt`. Do not assume `~/.pki/nssdb` is the Firefox profile. Firefox's `security.enterprise_roots.enabled` can use supported OS root stores; validate it on the actual platform/package rather than assuming system installation is sufficient.

### Checks

Run each in every browser you support: Chrome, Firefox, Safari, Edge.

1. `https://app.example.test` loads with no certificate interstitial or bypass. The leaf is issued by `testd intermediate`, chains to `testd root`, carries `app.example.test` in its SAN, and expires within 24 hours.
2. Wait for the leaf to be re-minted, or restart the daemon: a reload still shows a valid certificate with a newer validity window. When the browser suite started the host, use the page's restart button.
3. The local dashboard opens at `http://127.0.0.1:7737/` and lists the live name. `testd.test` is not a special name on the edge.
4. WebSocket: a dev server using HMR websockets connects over `wss` and survives 60 seconds idle.
5. SSE and a 100 MB upload complete without a truncated response.
6. Cookies: two names in one project (`app.example.test`, `api.example.test`) share a cookie set on `.example.test`, exactly as `app.example.com` and `api.example.com` would.
7. Stop the upstream, reload: the edge returns `502`. Request an unregistered name: `404`.
8. Single-label warning: `testd run app:3000` prints the cross-site warning, and `app.test` still resolves.

### `*.localhost` mode

On a host initialised with `testd init --tld localhost`:

1. `testd run app:3000`, then open `https://app.localhost` (or `https://app.localhost:8443` if the edge uses port 8443). Port 3000 is the upstream HTTP port, not the HTTPS edge.
2. No resolver change was needed. Root trust and port-443 permissions are still required for HTTPS.
3. Record whether the browser resolves `*.localhost` itself (expected in Chrome, Firefox, and Safari) or sends it to DNS.
4. glibc caveat: name resolution through `getaddrinfo` for `*.localhost` depends on the resolver; `curl` may need `--resolve`. Browsers are the target, not CLI tools.

### Record

For each browser: name and version, OS, pass or fail, and the leaf's SHA-256 fingerprint. Keep the result in the release notes or the host test log.

## Release

A free release is a version tag, CLI archives, public tray bundles, workspace SBOMs, generated Homebrew definitions, and `SHA256SUMS`. The tag workflow attaches them to a draft GitHub release only after the test, dependency-policy, and MSRV jobs pass. No commercial service or updater participates.

### Before tagging

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo nextest run --workspace`
- [ ] `cargo deny check`
- [ ] `cargo +1.89.0 check --workspace --exclude testd-gui --locked`
- [ ] `cargo +1.90.0 check -p testd-gui --locked`
- [ ] `python3 scripts/release.py verify-version`
- [ ] Enable GitHub private vulnerability reporting for the public repository
- [ ] Run the release-validation suites above and retain reports for every claimed platform/browser
- [ ] `scripts/release-sbom.sh` and attach the SBOMs to the release
- [ ] Finalize the dated changelog entry; synchronize all package and Tauri bundle versions, and refresh `Cargo.lock` when dependencies change
- [ ] Run `testd doctor --json` against a clean VM and keep the output
- [ ] Verify the documented fresh-install path reaches a trusted HTTPS name, including Linux port privileges

### Build

Linux and macOS CLI:

```sh
cargo build --release --bin testd
```

Tray app (per platform):

```sh
cargo tauri build
```

Artifacts: CLI `.tar.gz` (Linux/macOS) or `.zip` (Windows), `.dmg` containing `.app` (macOS), `.exe` (Windows NSIS), `.AppImage`/`.deb` (Linux). CI builds macOS Apple Silicon and Intel, Linux x86-64, and Windows x86-64.

Windows ships the NSIS installer only. It installs per user into `%LOCALAPPDATA%\Testd` and asks for no elevation. Tauri's MSI is always per machine (`Program Files`, HKLM uninstall key, UAC prompt) with no option to make it per user, so it is not produced; `src-tauri/tauri.windows.conf.json` narrows the Windows target list. An enterprise deployment that needs a machine-wide install can build one with `cargo tauri build --bundles msi` and install that `.msi` by hand.

Removing the app does not remove the machine trust root or the DNS route. Run `testd uninstall` before uninstalling; add `--purge` to delete the local config directory.

### Sign

Notarization, Authenticode, and the Homebrew tap have their own runbooks:
[Signing and notarization](#signing-and-notarization) and [Homebrew](#homebrew). Browser checks are in
[Browser validation](#browser-validation).

- macOS: `codesign` with the Developer ID Application certificate, then
  `xcrun notarytool submit --wait` and `xcrun stapler staple`. Ship the privacy
  manifest from `packaging/macos/PrivacyInfo.xcprivacy`.
- Windows: Authenticode sign the NSIS installer and the binaries; submit to SmartScreen.

This repository does not ship an updater. Releases are installed by the user: the archive, `brew upgrade`, or the system package manager. The binaries never check for a new version.

A Linux container can build and test the CLI and run `cargo tauri build`, but
cannot produce notarized or Authenticode-signed artifacts.

### Publish

- [ ] Tag `vX.Y.Z` and push the tag after the pre-tag checks
- [ ] Let CI build CLI archives and tray bundles, generate SBOMs, Homebrew definitions and checksums, and attach them to a draft GitHub release
- [ ] Download the draft assets and run artifact, host, browser, and desktop validation on the real supported platforms
- [ ] Apply signing/notarization separately if shipping signed desktop downloads; regenerate definitions and checksums from the final signed bytes
- [ ] Copy the generated `testd.rb` and `testd-gui.rb` into the Homebrew tap, then audit and install them locally
- [ ] Publish the draft with the changelog entry and validation results

The public workflow produces unsigned tray bundles and does not replace existing release assets on rerun. If an upload is already present, retain a backup before explicitly replacing it. Do not move an existing release tag to different source.

### Rollback

- GitHub: mark the broken version as withdrawn and publish a fixed version. Keep the previous good version and its checksums available. Existing installs keep working until the user chooses to replace them.
- Homebrew: revert the formula commit and `brew update`.
- macOS and Windows bundles are versioned per release, so a broken version can be
  withdrawn without affecting the previous one.

## Homebrew

The formula ships the CLI and daemon; the cask ships the tray app.

### Tap layout

Homebrew wants a repository named `homebrew-<tap>`. For `brew tap testd/testd`:

```
homebrew-testd/
  Formula/testd.rb
  Casks/testd-gui.rb
```

`packaging/homebrew/*.rb.in` are the source templates. The release generator fills a version and real source/DMG digests and attaches installable `.rb` definitions to the public release. The cask selects Apple Silicon or Intel DMGs explicitly.

### Local test before publishing

```sh
# Definitions downloaded from the release (or generated locally from its final assets)
brew install --formula ./dist/testd.rb
brew install --cask ./dist/testd-gui.rb
brew test testd
brew audit --strict --online ./dist/testd.rb
brew uninstall --formula testd
brew uninstall --cask testd-gui
```

Verify Gatekeeper behavior on a clean Mac. An unsigned or unnotarized app may require a user override; do not claim a normal signed-install experience until signing and notarization have been verified.

### Digests

After the version tag exists and both final DMGs are in `dist/`:

```sh
python3 scripts/release.py homebrew --version 0.1.0 --artifacts dist --output dist
python3 scripts/release.py checksums dist
```

The source archive is fetched once and cached as `dist/testd-0.1.0-source.tar.gz`. The generator computes digests from that archive and both architecture-specific DMGs. It refuses to overwrite existing output definitions or checksums. Use a new staging directory after signing or changing assets; retain the previous bytes.

### Formula notes

- The formula builds from the source tarball with `cargo install` and declares `depends_on "rust" => :build`.
- `service do` runs `testd host` as a user agent with `keep_alive true`. `brew services start testd` is the supported path; the tray app is the alternative.
- The formula's `test do` runs `testd --help` and `testd doctor --json`. `doctor` exits non-zero without a config, so the test tolerates that exit code.

### Cask notes

- `depends_on macos: ">= :ventura"`.
- `app "Testd.app"`.
- `zap trash: "~/.config/testd"` only after the root and the DNS route are removed; `testd uninstall` does both. Document that order in the release notes, not as a cask stanza that silently deletes state.

### Bumping a release

1. Synchronize package and bundle versions and finalize the changelog entry
2. Tag the release and generate definitions from its final source archive and DMGs
3. Run `brew audit --strict --online`, `brew test testd`, and fresh formula/cask installs
4. Publish the matching definitions to the tap

## Signing and notarization

Optional signing of the public desktop artifacts: macOS notarization and Windows Authenticode need operator-supplied credentials. The public CI workflow does not sign or notarize. Source publication and CLI source builds do not require these credentials.

### macOS

#### Prerequisites

- Apple Developer Program membership (99 USD/year).
- A `Developer ID Application` certificate in the login keychain, with its private key. `security find-identity -v -p codesigning` lists it.
- An app-specific password for the Apple ID, or an App Store Connect API key.
- Xcode command line tools: `codesign`, `xcrun notarytool`, `stapler`, `spctl`.

Store the notary credentials once:

```sh
xcrun notarytool store-credentials testd-notary \
  --apple-id you@example.com \
  --team-id TEAMID1234 \
  --password "$APP_SPECIFIC_PASSWORD"
```

#### Build and sign

```sh
cargo tauri build --bundles app,dmg
```

Sign inside out: nested binaries and frameworks first, then the bundle. `cargo tauri build` signs with the identity it finds when `APPLE_SIGNING_IDENTITY` is set; otherwise sign manually:

```sh
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: Your Name (TEAMID1234)" \
  target/release/bundle/macos/Testd.app
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: Your Name (TEAMID1234)" \
  target/release/bundle/dmg/Testd_0.1.0_aarch64.dmg
```

Verify the signature and the hardened runtime before submitting:

```sh
codesign --verify --deep --strict --verbose=2 target/release/bundle/macos/Testd.app
codesign -d --entitlements - target/release/bundle/macos/Testd.app
```

No entitlements are required: the app is not sandboxed, uses no JIT, and shells out only through Tauri's process API. Keep it that way; every entitlement is a notarization review question.

#### Notarize

```sh
xcrun notarytool submit target/release/bundle/dmg/Testd_0.1.0_aarch64.dmg \
  --keychain-profile testd-notary --wait
xcrun stapler staple target/release/bundle/dmg/Testd_0.1.0_aarch64.dmg
xcrun stapler validate target/release/bundle/dmg/Testd_0.1.0_aarch64.dmg
```

`--wait` prints the submission id and the result. Keep the id in the release notes. Notarize the `.dmg` after signing the `.app` inside it, or notarize both; stapling the `.dmg` is what users download.

#### Verify as a user would

```sh
spctl -a -vv -t exec target/release/bundle/macos/Testd.app
```

Expect `accepted` and `source=Notarized Developer ID`. Also copy the `.dmg` to a clean account, mount it, and launch once: Gatekeeper must accept the first run without a right-click.

#### Common failures

| Symptom | Cause |
|---|---|
| `Invalid` with "The signature of the binary is invalid" | A nested binary was signed after the bundle, or not at all. Re-sign inside out. |
| `Invalid` with "hardened runtime is not enabled" | Missing `--options runtime`. |
| `Invalid` with "The executable does not have the hardened runtime enabled" on a dependency | A sidecar or dylib shipped unsigned. |
| `spctl` rejects but notarization passed | Staple was skipped; the app was moved out of the stapled dmg. |
| Submission stuck in `In Progress` for hours | Apple side; resubmit with `--wait` and the same profile. |

### Windows

- Sign the NSIS installer and the binaries with an Authenticode certificate (`signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256`).
- Submit the installer to SmartScreen once per certificate; fresh certificates start without reputation and gather it per download.
- This repository does not ship an updater; see [Release](#release).

### What not to sign

The root certificate and its private key are local data, not artifacts. They never enter the release pipeline.
