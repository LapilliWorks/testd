# Developing

## Prerequisites

- Rust toolchain from `rust-toolchain.toml`
- `cargo-nextest` for tests and `cargo-deny` for dependency checks
- `cargo-tauri` and the platform's Tauri prerequisites for the tray app: Xcode command-line tools on macOS, WebKitGTK/GTK on Linux, MSVC on Windows

## Build

From the repository root:

```sh
cargo build --release -p testd   # CLI and daemon
cargo tauri build                # tray app
```

The workspace excludes `testd-gui` (the Tauri app) from container checks because it needs GTK/WebKit system libraries.

## Test

```sh
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo deny check
```

## Contents

- [Quickstart](docs/quickstart.md) for using the installed tool
- [Host testing](#host-testing) for checks that need real machines
- [Browser validation](#browser-validation) for manual checks in real browsers
- [Release](#release) for the release checklist and artifacts
- [Homebrew](#homebrew) for the formula and cask
- [Signing and notarization](#signing-and-notarization) for macOS notarization and Windows Authenticode

## Host testing

The container suite covers the protocol, the edge, registration ownership, DNS answers, CLI behavior, and sharing. The checks below cover OS resolver integration, trust stores, privileged ports, packaging, code signing, and the tray.

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

Local registration uses the operator secret that `testd init` writes into `[host] secret`. The scripts run the client on the node itself, where the default loopback profile uses that secret automatically; no `TESTD_TOKEN` is exported. A separate named profile with no credential requests a token, which the script approves and then revokes through `testd requests`, `testd approve`, and `testd tokens`.

The quick launch checks need `python3` (or `python` on Windows) to start a local HTTP server. They save a launch through the loopback dashboard, start it, check the name through the edge and DNS, stop it, and delete it.

Each script uses:

- a throwaway `HOME`/`%APPDATA%` under the temp directory,
- a throwaway TLD (`testdcheck` by default) so it does not collide with a real `.test` setup,
- a high HTTPS port (`8443`) so it does not need root for the edge,
- dedicated upstream ports for registration (`18080`) and quick launches (`18081`).

The scripts do **not** call sudo by default. On Linux and macOS they use `--cacert` for HTTPS; on Windows they use `--insecure` for the edge and proxy checks because Schannel does not treat `--cacert` like OpenSSL. To also test the OS resolver and trust store, set `TESTD_HOST_TEST_SYSTEM=1` and have passwordless sudo (Linux/macOS) or an elevated PowerShell (Windows).

### Linux

Prerequisites: `bash`, `curl`, `python3`, `resolvectl` (for the optional system
check), `systemd-analyze` (optional). `sudo` must be available if
`TESTD_HOST_TEST_SYSTEM=1`.

```sh
cd testd
cargo build --release -p testd

# Core checks, no system changes
tests/host/linux.sh

# Optional: resolver + trust store on a disposable machine
sudo -v
TESTD_HOST_TEST_SYSTEM=1 tests/host/linux.sh

# Same, and clean up the resolver/trust changes afterwards
TESTD_HOST_TEST_SYSTEM=1 TESTD_HOST_TEST_CLEANUP=1 tests/host/linux.sh
```

The system check writes `/usr/local/share/ca-certificates/testd-root.crt` and
`/etc/systemd/resolved.conf.d/90-testd.conf`. Both are the same changes a real
`testd doctor --fix` makes. The printed cleanup commands are:

```sh
sudo rm -f /etc/systemd/resolved.conf.d/90-testd.conf
sudo systemctl reload systemd-resolved
sudo rm -f /usr/local/share/ca-certificates/testd-root.crt
sudo update-ca-certificates --fresh
```

### macOS

Prerequisites: `bash`, `curl`, `python3`, `plutil`, `dscacheutil`. Xcode
command-line tools are needed to build. `sudo` must be available if
`TESTD_HOST_TEST_SYSTEM=1`.

```sh
cd testd
cargo build --release -p testd

tests/host/macos.sh

sudo -v
TESTD_HOST_TEST_SYSTEM=1 tests/host/macos.sh
```

The system check writes `/etc/resolver/testdcheck` and installs the test root
into `/Library/Keychains/System.keychain`. Cleanup:

```sh
sudo rm -f /etc/resolver/testdcheck
sudo security delete-certificate -c "testd root" /Library/Keychains/System.keychain
```

If the machine already uses testd for `.test`, do not set
`TESTD_HOST_TEST_SYSTEM=1` without understanding that the root CA at
`/usr/local/share/ca-certificates/testd-root.crt` is replaced.

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
$env:TESTD_HOST_TEST_SYSTEM = "1"
powershell -NoProfile -ExecutionPolicy Bypass -File tests\host\windows.ps1
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

Cleanup:

```powershell
Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq '.testdcheck' } |
    ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Confirm:$false }
certutil -delstore Root "testd root"
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

Follow `tests/host/gui-checklist.md`. The tray app is a paid distribution
artifact but the source is public; build it locally and run the checklist
against the same commit as the CLI. The checklist separates current behavior
from the still-pending tray attach/detach and remote-host switching.

### Packaging and signing

These require credentials and hardware that do not belong in this repository:

- **macOS:** Developer ID certificate, notarization credentials, `codesign`,
  `spctl`, `xcrun stapler`.
- **Windows:** Authenticode certificate and SmartScreen reputation; verify with
  `Get-AuthenticodeSignature`.
- **Linux:** unsigned `.deb`, AppImage, and tarball; verify with `dpkg-deb -I`
  and an AppImage smoke run.
- **Updater:** Tauri update signing key in the private release repo; verify the
  manifest signature and a downgrade refusal.

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
| `TESTD_HOST_TEST_CLEANUP` | `0` | Revert resolver/trust changes after a system run |

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
| Chrome, Edge (Linux) | system (`/usr/local/share/ca-certificates`) | `sudo cp root.crt /usr/local/share/ca-certificates/testd-root.crt && sudo update-ca-certificates` |
| Chrome, Edge (macOS), Safari | login keychain | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root.crt` |
| Chrome, Edge (Windows) | machine store | `certutil -addstore -f Root root.crt` |
| Firefox (all) | NSS database, independent of the system | `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n testd-root -i root.crt` |

Firefox on macOS uses `<profile>/cert9.db`; the same `certutil` command with `-d sql:<profile dir>` applies. Setting `security.enterprise_roots.enabled` to `true` makes Firefox read the system store instead of its own.

### Checks

Run each in every browser you support: Chrome, Firefox, Safari, Edge.

1. `https://app.example.test` loads with a padlock, no interstitial. The certificate is issued by `testd root`, carries `app.example.test` in its SAN, and expires within 24 hours.
2. Wait for the leaf to be re-minted, or restart the daemon: a reload still shows a valid certificate with a newer validity window.
3. The local dashboard opens at `http://127.0.0.1:7737/` and lists the live name. `testd.test` is not a special name on the edge.
4. WebSocket: a dev server using HMR websockets connects over `wss` and survives 60 seconds idle.
5. SSE and a 100 MB upload complete without a truncated response.
6. Cookies: two names in one project (`app.example.test`, `api.example.test`) share a cookie set on `.example.test`, exactly as `app.example.com` and `api.example.com` would.
7. Stop the upstream, reload: the edge returns `502`. Request an unregistered name: `404`.
8. Single-label warning: `testd run app:3000` prints the cross-site warning, and `app.test` still resolves.

### `*.localhost` mode

On a host initialised with `testd init --tld localhost`:

1. `testd run app.localhost:3000`, then open `https://app.localhost:3000` and `https://app.localhost`.
2. No resolver change and no sudo were needed.
3. Record whether the browser resolves `*.localhost` itself (expected in Chrome, Firefox, and Safari) or sends it to DNS.
4. glibc caveat: name resolution through `getaddrinfo` for `*.localhost` depends on the resolver; `curl` may need `--resolve`. Browsers are the target, not CLI tools.

### Record

For each browser: name and version, OS, pass or fail, and the leaf's SHA-256 fingerprint. Keep the result in the release notes or the host test log.

## Release

One release is a tag plus four artifacts. Everything below is repeatable from a
clean checkout.

### Before tagging

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo nextest run --workspace`
- [ ] `cargo deny check`
- [ ] `cargo +1.88.0 check --workspace`
- [ ] `scripts/release-sbom.sh` and attach the SBOMs to the release
- [ ] Update `CHANGELOG.md`, bump the workspace version, refresh `Cargo.lock`
- [ ] Run `testd doctor --json` against a clean VM and keep the output
- [ ] Verify a fresh install reaches a working name in one command

### Build

Linux and macOS CLI:

```sh
cargo build --release --bin testd
```

Tray app (per platform):

```sh
cargo tauri build
```

Artifacts: `.dmg`/`.app` (macOS), `.exe` (Windows, NSIS), `.AppImage`/`.deb` (Linux).

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

- [ ] Upload platform artifacts to the storefront
- [ ] Update the Homebrew tap (`packaging/homebrew/testd.rb`) with the new URL and
      sha256; keep the cask on the same version
- [ ] Attach the release notes from `CHANGELOG.md` to the storefront entry
- [ ] Tag `vX.Y.Z`, push the tag, let CI attach bundles and SBOMs
- [ ] Announce to existing buyers for a major version

### Rollback

- Storefront: restore the previous version listing and re-upload the artifacts.
  Open-source installs keep working; they are replaced when the user installs the
  fixed release.
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

The copies in `packaging/homebrew/` are the sources of truth in this repository; the tap holds the published versions with real URLs and digests.

### Local test before publishing

```sh
cargo build --release -p testd
brew install --formula ./packaging/homebrew/testd.rb
brew install --cask ./packaging/homebrew/testd-gui.rb
brew audit --strict --online packaging/homebrew/testd.rb
brew uninstall --formula testd
brew uninstall --cask testd-gui
```

`--cask` install fails on an unsigned app: notarize first, see [Signing and notarization](#signing-and-notarization).

### Digests

Both files carry `sha256 "TODO"` until a release exists. After uploading the artifacts:

```sh
scripts/brew-sha256.sh packaging/homebrew/testd.rb \
  https://github.com/testd/testd/archive/refs/tags/v0.1.0.tar.gz   # or a local path
scripts/brew-sha256.sh packaging/homebrew/testd-gui.rb \
  Testd_0.1.0_aarch64.dmg
```

The script downloads when given an URL, hashes the file, and rewrites the `sha256` line. It refuses to guess when there is no `sha256` line in the file.

### Formula notes

- The formula builds from the source tarball with `cargo install` and declares `depends_on "rust" => :build`.
- `service do` runs `testd host` as a user agent with `keep_alive true`. `brew services start testd` is the supported path; the tray app is the alternative.
- The formula's `test do` runs `testd --help` and `testd doctor --json`. `doctor` exits non-zero without a config, so the test tolerates that exit code.

### Cask notes

- `depends_on macos: ">= :ventura"`.
- `app "Testd.app"`.
- `zap trash: "~/.config/testd"` only after the root and the DNS route are removed; `testd uninstall` does both. Document that order in the release notes, not as a cask stanza that silently deletes state.

### Bumping a release

1. Replace the artifact URLs with the tagged release or the new dmg.
2. Run `scripts/brew-sha256.sh` for each file.
3. `brew audit --strict --online`, then `brew reinstall` both locally.
4. Push the tap and announce.

## Signing and notarization

macOS notarization and Windows Authenticode. Both need credentials that do not live in this repository; everything else is scripted here.

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
