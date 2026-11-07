# Developing

## Prerequisites

- Rust toolchain from `rust-toolchain.toml`; CLI/daemon MSRV 1.89, tray MSRV 1.90
- Python 3.12 or newer for release tooling and reports; Bun for browser fixtures
- `cargo-cyclonedx` for workspace SBOM generation
- `cargo-nextest` for tests and `cargo-deny` for dependency checks
- `tauri-cli` and the platform's Tauri prerequisites for the tray app: Xcode command-line tools on macOS, WebKitGTK/GTK on Linux, MSVC on Windows
- On Fedora/RHEL, `qt5-qttools` provides `qtpaths`, which the Linux AppImage bundler needs

## Build

From the repository root:

```sh
cargo build --release -p testd   # CLI and daemon
cargo tauri build                # tray app
```

The workspace includes `testd-gui`. On a machine without GTK/WebKit, add `--exclude testd-gui` to workspace test and clippy commands. CI installs the Tauri system prerequisites and checks the full workspace.

## Icons

`src-tauri/icons/` is generated; its sources live in `assets/brand/`. Regenerate the bundle and tray icons with:

```sh
python3 scripts/build-icons.py
```

The script uses only the Python standard library. `testd-app.png` supplies sizes below 128px, `testd-app-large.png` supplies 128px and above, and the two 32px masks supply the tray variants. `testd-app-large.png` is a 1024px render of `testd-slim.svg`; refresh it when the SVG changes.

## Website

The product site lives under `sites/`; the documentation Markdown lives under `docs/` at the repository root. The site runs in a container, so no local `bun install` is needed to develop, build, or check it.

```sh
./sites/bin/site.sh dev      # product at http://127.0.0.1:5173/, docs at /docs/
./sites/bin/site.sh build    # dist/, with the docs under dist/docs
./sites/bin/site.sh preview  # serves dist/ at http://127.0.0.1:4173/
./sites/bin/site.sh check
./sites/bin/site.sh links
./sites/bin/site.sh shell
./sites/bin/site.sh clean
# or
bun run dev
```

The script runs the official Bun image (`oven/bun:1.4.4`) with `docs/`, `sites/`, and `scripts/` mounted, installs dependencies into the `testd-site-node-modules` volume, and runs the stock `vitepress` and `vite` CLI entrypoints with Bun. It prefers Podman and falls back to Docker; set `TESTD_SITE_RUNTIME` to pin one. The product server is the public origin and proxies `/docs/` to VitePress on loopback.

`--host 0.0.0.0` (or `TESTD_SITE_HOST`) serves the site to the network. `--port <port>` overrides the published port for `dev` or `preview`; `TESTD_SITE_PORT` and `TESTD_SITE_PREVIEW_PORT` set the defaults, and `TESTD_SITE_IMAGE` or `TESTD_SITE_VOLUME` overrides the image or dependency volume. Remove the volumes with `./sites/bin/site.sh clean`.

The build and check scripts remain the local path used by CI; they need `bun install` first and run outside the container:

```sh
bun install
bun run build     # dist/, with the docs under dist/docs
bun run preview   # serves the built tree at http://localhost:4173/
bun run check
bun run check:links
```

`bun run build` writes the product site first and the docs second; deploy `dist/` as one static tree. `bun run preview -- --host 0.0.0.0` exposes the built tree on every interface.

`master` publishes `dist/` to <https://testd.dev> through the Cloudflare Pages Git integration. The project settings and the Workers alternative are in [sites/README.md](sites/README.md#publish).

## Test

See [tests/README.md](tests/README.md) for the all-in-one platform runners, contract matrix, test layers, known gaps, and manual validation. The `all` suite prints boundaries for every stage and requires explicit opt-in for privileged or interactive checks.

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

# Linux OS integration on a disposable VM with a persisted full-system snapshot
sudo -v
python3 tests/release/run.py host --system --bin /path/to/candidate-testd \
  --report ~/testd-reports/linux-system-01

# Candidate archives and checksums on a separately backed-up disposable VM
python3 tests/release/run.py artifacts --artifacts ~/Downloads/testd-candidate --require-checksums \
  --report ~/testd-reports/artifacts-01
# Optional upgrade check: add --previous-bin /path/to/previous/testd

# Real browsers on a separately prepared disposable VM and fresh user
python3 tests/release/run.py browser --bin /path/to/candidate-testd --report ~/testd-reports/browser-01

# Linux desktop on a separately prepared disposable VM and fresh user
python3 tests/release/run.py desktop --app /path/to/candidate-app --bin /path/to/candidate-testd \
  --report ~/testd-reports/desktop-01
```

The `core` release suite runs ignored Rust contracts as well as ordinary tests; known failing contracts therefore block it until they are resolved or the relevant feature is explicitly excluded. See [tests/README.md](tests/README.md) for the current gaps.

Reports contain local PKI and test credentials and are private by default. Do not attach the entire report directory to a public issue; share only reviewed logs/JSON, never private keys or credentials.

The browser suite uses Bun fixtures and publishes `app.releasecheck`, `api.releasecheck`, and a dead-upstream name. It checks HTTPS, WebSocket idle survival, streamed SSE, a 100 MiB upload, and project-cookie scope. It refuses an occupied intake port, starts and stops its own candidate daemon, and disables real tunnel providers. Initialize the fresh test user and prepare OS DNS and trust on a separately backed-up disposable VM. `testd doctor --json` checks resolver readiness before the browser opens. Run the page in each supported browser, complete the certificate and error-response observations, and save the JSON report. Ctrl+C stops the fixture processes. For a high edge port, pass `--edge-port 8443`. The suite does not itself install trust or change the resolver.

The `service` suite (also available as `host --service` or `artifacts --service`) requires the disposable-host confirmation and a persisted report. Run it separately from `--system` on a restored snapshot. On Linux it exercises the real systemd user-session supervisor with a randomly named unit, isolated home, fake provider, high ports, and manager-directed crash and stop. It creates the unit exclusively, removes it only if its recorded identity and bytes still match, and retains the generated unit in the report. Launchd checks remain blocked until service ownership can be established; Windows does not ship a CLI service.

The desktop suite records each GUI checklist item as pass, fail, or not applicable with evidence. It requires a real interactive terminal and desktop session, a fresh user, a candidate app and CLI, and confirmation of a disposable host with a persisted full-system snapshot. Linux cleanup invokes the candidate's ownership-checked uninstall only after the operator confirms all candidate processes have stopped. macOS and Windows desktop checks remain blocked until resolver and trust ownership can be established. A scoped snapshot does not cover installer, login, browser, or shared CA-store effects. Unconfirmed shutdown defers cleanup. Skips and unanswered checks remain visible in `report.json`; they are not counted as passes.

`host --system` requires a clean disposable host, no testd daemon, an interactive confirmation, a new persisted report, and a persisted full-system snapshot. Linux uses the candidate's ownership-checked uninstall after verifying fixture shutdown; changed or unowned state is left untouched. The scoped verification does not establish that shared trust-store output or hooks are unchanged, so the system stage remains incomplete until independently reviewed against the full-system snapshot. macOS and Windows product system checks are blocked. Plain `host` does not change system integration. `--bin /path/to/testd` runs a candidate CLI without rebuilding it.

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
| `tests/host/linux.sh` | resolver route, CA trust, edge TLS, loopback dashboard, DNS A records, token requests, issued tokens, local registration, sharing, quick launches, URL actions, doctor state checks, launch-at-login entry, systemd unit |
| `tests/host/macos.sh` | Unprivileged edge, dashboard, DNS, registration, sharing, quick launches, doctor state, and launch-at-login checks; resolver and trust checks are blocked |
| `tests/host/windows.ps1` | Unprivileged edge, dashboard, DNS, registration, sharing, quick launches, and launch-at-login checks; NRPT and root trust checks are blocked |
| `tests/host/gui-checklist.md` | setup dialog, tray, dashboard window, click-to-open, single instance, quick launches, certificate controls, URL actions, packaging/signing |

The Linux and macOS scripts share their core checks in `tests/host/common.sh` and their helpers in `tests/host/lib.sh`; the platform scripts add the resolver, trust, and init-system sections.

The sharing checks start the daemon with `TESTD_TUNNEL` pointing at a fake provider, so they need no provider installed: start, list, refuse a second share, stop, refuse an unknown provider, and refuse a name that is no longer registered. The provider shapes themselves (cloudflared, ngrok, tailscale) are covered by `cargo test -p testd-daemon --test share`, which the Windows script cannot do because a PowerShell script is not a spawnable provider binary.

Local registration uses the operator secret that `testd init` writes into `[host] secret`; the standalone host has no accounts or roster. The scripts run the client on the node itself, where the default loopback profile uses that secret automatically; no `TESTD_TOKEN` is exported. A separate named profile with no credential requests a token, which the script approves and then revokes through `testd requests`, `testd approve`, and `testd tokens`.

The quick launch checks need `python3` (or `python` on Windows) to start a local HTTP server. They save a launch through the loopback dashboard, start it, check the name through the edge and DNS, stop it, and delete it.

Each script uses:

- a throwaway `HOME`/`%APPDATA%` retained under the persisted report directory,
- a test-only throwaway TLD (`testdcheck` by default) so it does not collide with a real `.test` setup,
- a high HTTPS port (`8443`) so it does not need root for the edge,
- dedicated upstream ports for registration (`18080`) and quick launches (`18081`).

The scripts do **not** call sudo themselves. On Linux and macOS they use `--cacert` for HTTPS; on Windows they use `--insecure` for edge and proxy checks because Schannel does not treat `--cacert` like OpenSSL. Only the Linux runner currently permits optional OS resolver and trust checks, with a cached sudo credential, a disposable-host confirmation, and a persisted full-system snapshot. macOS and Windows system checks are blocked.

### Linux

Prerequisites: `bash`, `curl`, `python3`, `resolvectl` (for the optional system
check), `systemd-analyze` (optional). `sudo` must be available if
`TESTD_HOST_TEST_SYSTEM=1`.

```sh
cd testd
cargo build --release -p testd

# Core checks, no system changes
tests/host/linux.sh

# Optional system checks on a backed-up disposable VM, with a new persisted report
sudo -v
python3 tests/release/run.py host --system --bin target/release/testd \
  --report ~/testd-reports/linux-system-01
```

The Linux system check can write `/etc/systemd/resolved.conf.d/90-testd.conf` and the distro's CA anchor: `/usr/local/share/ca-certificates/testd-root.crt` on Debian and Ubuntu or `/etc/pki/ca-trust/source/anchors/testd-root.crt` on Fedora and RHEL. Cleanup uses the candidate's ownership checks and reports conflicts without replacing or deleting unowned state. Trust-store regeneration and hooks can affect additional shared files, which the scoped snapshot does not verify.

### macOS

Prerequisites: `bash`, `curl`, `python3`, `plutil`, and `dscacheutil`. Xcode command-line tools are needed to build.

```sh
cd testd
cargo build --release -p testd
tests/host/macos.sh
```

The unprivileged host checks do not install a resolver or trust root. The product system checks, desktop runner, launchd service check, and resolver-specific probe are blocked until their ownership and cleanup can be established. The scoped self-test removes only a recorded exact fixture certificate and cannot verify all keychain trust settings or shared effects.

### Windows

Prerequisites: PowerShell 5.1 or later, `curl.exe` (included with Windows 10
1803+), and a free port 53. The daemon uses port 53 for NRPT; if another
service owns it, the script fails at the DNS check.

The unprivileged script prints the OS caption, version, build, and architecture at the start of every run. Compilation, PowerShell fixtures, and CLI checks do not validate NRPT, machine trust, or a desktop Windows release.

CI's `windows-latest` runner is Windows Server, not a desktop Windows 11 host.
It is useful for compilation and the CLI tests, but it does not replace the
NRPT and trust-store checks above.

```powershell
cd testd
cargo build --release -p testd

# Core checks: edge and proxy without system trust
powershell -NoProfile -ExecutionPolicy Bypass -File tests\host\windows.ps1
```

The unprivileged run intentionally uses `curl --insecure --ssl-no-revoke` for edge and proxy checks. That validates routing and TLS minting without requiring a trust-store change. The loopback dashboard is proxied through the edge and returns 200; these checks do not establish OS trust.

`testd init` and `testd doctor --fix` no longer need the whole process elevated
on Windows. Privileged actions are delegated to
`scripts/testd-elevated.ps1`, a closed-action helper that validates the TLD,
IPv4 address, certificate thumbprint, and CA constraints. If testd is not
elevated, Windows shows one UAC prompt for that helper only.

The Windows snapshot helper verifies NRPT rules and machine roots without deleting or recreating them by name. Real product system and desktop checks remain blocked because the helper cannot prove ownership of every change; use the persisted full-system snapshot for recovery. Windows NRPT rules cannot specify a port, so the daemon binds `:53`. If it is occupied, use a different disposable host rather than stopping an unrelated service.

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
| Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `dev.testd.host` | Read the entry without treating it as candidate evidence |

The CLI-only host scripts cannot establish that an existing login entry belongs to the candidate GUI. Windows records an existing entry as unverified, not as a pass or failure. The GUI checklist covers the actual run and toggle.

### Browser validation

The [Browser validation](#browser-validation) section holds the per-browser script: trust stores, padlock
and certificate expectations, WebSocket and SSE behaviour, cookie scope across
`app.example.test` and `api.example.test`. The host
scripts stop at the HTTP layer on purpose; they cannot judge a padlock.

### GUI

The tray is a public source build and an optional free release artifact. On a backed-up disposable Linux desktop, run `python3 tests/release/run.py desktop --app <candidate> --bin <candidate-cli> --report <new-report>` to record `tests/host/gui-checklist.md`. The app and CLI must come from the intended source. macOS and Windows desktop runs remain blocked until system ownership is proven. Attach/detach of existing processes is deferred and does not gate this release.

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
| `TESTD_HOST_TLD` | `testdcheck` | Test-only throwaway TLD; must be 1 to 10 lowercase alphanumeric chars |
| `TESTD_HOST_EDGE_PORT` | `8443` | HTTPS edge port |
| `TESTD_HOST_APP_PORT` | `18080` | Test upstream port |
| `TESTD_HOST_LAUNCH_PORT` | `18081` | Quick-launch upstream port |
| `TESTD_HOST_TEST_SYSTEM` | `0` | Allow resolver and trust changes |
| `TESTD_HOST_SNAPSHOT` | unset | Snapshot directory written by `run.py --system` |

### System integration

Before permitted system checks, `run.py` records selected integration under `<report>/system-before/`. The scoped snapshot is not a full-system backup and does not capture every artifact, trust setting, generated store, or hook affected by the product.

| Platform | Selected snapshot | Cleanup policy |
|---|---|---|
| Linux | The systemd-resolved drop-in, the distro's CA anchor, and their ownership markers | Candidate-owned integration is removed through the candidate's ownership checks; other changes are left untouched |
| macOS | The test TLD resolver file and named testd roots in the System keychain | Product checks are blocked; the self-test removes only its exact recorded fixture certificate |
| Windows | NRPT rules for the test TLD and named testd roots in the machine store | Verify only; never remove or recreate rules or roots by name |

File fixtures use exclusive creation and record their identity and content before cleanup. A replaced, changed, deleted, or unowned artifact is reported, not overwritten or removed. Pre-existing keychain and machine-root trust settings are not captured and cannot be verified from this snapshot. System stages remain incomplete when shared trust-store output or hooks have not been compared with the persisted full-system snapshot.

After an interrupted run, stop all candidate processes and inspect the persisted report and full-system snapshot. An interactive scoped recovery can be attempted with the relevant report or `self-test-state` directory:

```sh
python3 tests/release/run.py --restore-report ~/testd-reports/linux-system-01
```

Recovery requires the same platform and any necessary sudo or elevation. It leaves conflicts untouched. Exit `2` means scoped state matched but shared trust effects remain unverified; restore or compare the full-system snapshot before reusing the machine. Direct host scripts cannot run privileged checks without the runner's safeguards.

### CI coverage

`.github/workflows/ci.yml` provisions and runs the `ci` suite on Ubuntu 24.04, macOS 15 Apple Silicon and Intel, and Windows Server 2025. It installs Python 3.14, stable and both MSRV Rust toolchains, `cargo-nextest`, `cargo-deny`, Bun, and website dependencies; Linux build libraries come from the local dependency action. Xcode and MSVC/Windows SDK prerequisites come from the hosted runner images. Rust build caches are isolated by platform, and only master runs save them.

A separate Fedora 44 container job installs Fedora build dependencies, uses its system Python, and runs the same suite as a normal user. It establishes Fedora userspace compilation and CLI/daemon behavior on the Ubuntu runner's kernel, not native Fedora resolver, trust, systemd-session, SELinux, or desktop integration. Hosted Windows Server is not desktop Windows 11 evidence.

Every applicable job runs ignored contracts and executable doctests, rather than reserving them for stable tags. Missing prerequisites, unexpected skips, and incomplete checks make the CI command nonzero. The workflow uploads only `ci-summary.json`; fixture state and full report files are not uploaded. Separate Python 3.12 system-state fixture jobs retain minimum-runtime coverage without changing the runner's resolver or trust store. Site-only changes retain their lightweight website job.

Real system, service, browser-trust, installer, and desktop checks still require an explicitly confirmed disposable host with a persisted full-system snapshot; hosted CI does not supply that snapshot and does not run them. Tags and manual workflow dispatches build and package artifacts and generate SBOMs after the platform, minimum-runtime fixture, and website gates pass, without executing the interactive artifact smoke runner. Manual dispatches use the workspace version and do not publish a release; publishing remains restricted to version tags. Source builds and package creation do not replace installation, signing, or uninstall evidence. A green workflow is not release approval. Required-check settings must use the current platform job names rather than the removed standalone MSRV/audit jobs.

### System checks need a running daemon

The Linux resolver and trust checks query the fixture daemon. The runner verifies that its fixture ports are free before cleanup and refuses to stop or replace unrelated listeners. A missing daemon or unresolved cleanup is reported rather than counted as a pass.

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

Manual checks that a name works in a real browser. Use a disposable host with a persisted full-system snapshot. A separate device or non-loopback exposure needs separate approval and synthetic data.

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
3. The tray's `testd.test → dashboard` row opens the dashboard window, or `testd dashboard` prints the URL. The page lists the live name. `testd.test` is served by the edge for loopback clients only.
4. WebSocket: a dev server using HMR websockets connects over `wss` and survives 60 seconds idle.
5. SSE and a 100 MB upload complete without a truncated response.
6. Cookies: two names in one project (`app.example.test`, `api.example.test`) share a cookie set on `.example.test`, exactly as `app.example.com` and `api.example.com` would.
7. Stop the upstream, reload: the edge returns `502`. An unregistered name does not reach an application; DNS or TLS may reject it before any HTTP response.
8. Single-label warning: `testd run app:3000` prints the cross-site warning, and `app.test` still resolves.

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

Removing the app does not remove the machine trust root or the DNS route. CLI uninstall is blocked on macOS and Windows until system ownership can be verified; do not remove unowned state. On Linux, run `testd uninstall` before removing the app; add `--purge` to delete the local config directory after system cleanup succeeds.

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

Homebrew wants a repository named `homebrew-<tap>`. For `brew tap LapilliWorks/testd`:

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
