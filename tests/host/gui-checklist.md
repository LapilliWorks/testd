# GUI checklist

These are the checks that need a desktop session and the Tauri bundle. Run them
against a build from the same commit as the CLI/daemon. `python3 tests/release/run.py desktop --app <candidate>` launches the candidate and records each checkbox below as pass, fail, or not applicable, with evidence. The runner snapshots the system integration first and restores it when the checklist ends.

## Build

macOS (from the repository root):

```sh
cargo tauri build
open target/release/bundle/macos/Testd.app
```

Linux:

```sh
# Fedora/RHEL: qtpaths from qt5-qttools is required by the AppImage bundler
sudo dnf install qt5-qttools
cargo tauri build
./target/release/bundle/appimage/*.AppImage
```

The tray must bind port 443. Grant `CAP_NET_BIND_SERVICE` to the actual tray
binary or set `[host] edge_addr` to a high port before the daemon starts;
otherwise the tray exits after setup with a bind permission error.

Windows (elevated shell not required for the app itself):

```powershell
cargo tauri build
target\release\bundle\nsis\Testd_0.1.0_x64-setup.exe
```

Run `tests/release/run.py desktop` from an elevated PowerShell on Windows so
its system snapshot and restore can read the NRPT rules and machine root store.

The GUI imports the same daemon library as `testd host`. Only one daemon may
run at a time; the instance lock must reject a second tray or headless host.

## Setup

- [ ] First launch opens the setup wizard, not the tray: resolver, certificate,
      then operator secret.
- [ ] The resolver step reports either an existing route or configures it, and
      Continue is available only after it is ready.
- [ ] The certificate step shows the root summary, installs it, and Continue is
      available only after trust is installed.
- [ ] The secret step shows a generated secret, and **Generate** replaces it;
      **Copy** copies the current value.
- [ ] Editing the secret to a value shorter than 16 characters is refused, and
      the wizard stays on the secret step.
- [ ] Finish writes `~/.config/testd/config.toml` (`%APPDATA%\testd\config.toml`
      on Windows), starts the daemon, and closes the wizard.
- [ ] Resuming an interrupted wizard keeps the pending operator secret unless
      **Generate** is pressed.
- [ ] First launch after setup shows exactly one tray/menu-bar icon.

## Core

- [ ] Windows: the installer raises no UAC prompt, and the uninstall entry is
      `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Testd` with
      `InstallLocation` under `%LOCALAPPDATA%\Testd`.
- [ ] Windows: certificate install from the wizard raises one UAC prompt;
      later launches raise none when trust is already installed.
- [ ] macOS: after setup the app has no dock icon (activation policy Accessory).
- [ ] Tray menu shows the live domain list, each name with open and stop.
- [ ] Start `testd run app.example:3000` in a project; the domain appears in the
      tray within two seconds.
- [ ] Open the domain's stop action: the leaf stops and the name disappears, but
      its grant is kept, so the next run publishes it without asking.
- [ ] Click the domain's open action: the default browser opens
      `https://app.example.test` and the dev server responds.
- [ ] Stop `testd run`; the domain disappears from the tray.
- [ ] "Open dashboard" opens the authenticated dashboard URL in the browser.
- [ ] Dashboard shows the same domains, shares, and quick launches as the CLI.
- [ ] Quit from the tray exits the process, removes `control.json`, releases the instance lock, and stops the DNS and HTTPS listeners. The lock file may remain; another instance can acquire it.
- [ ] Launch a second instance while the first runs: the second must not start a
      second daemon. The same holds for `testd host` next to the tray.
- [ ] Launch-at-login (where configured) starts the tray after logout/login.

## Operator secret

- [ ] The setup wizard shows an editable operator secret and a Generate button.
- [ ] Saving a secret shorter than 16 characters is refused and the wizard stays put.

## Certificate commands

- [ ] The setup wizard can install trust through its certificate command; removal is available in the dashboard's Certificate section.

## Notifications

- [ ] Fresh host, no resolver route: the tray posts one "DNS routing is not set up" notification, not one per probe.
- [ ] Activate the notification action: the resolver is configured, the menu item disappears, and no further notice appears.
- [ ] Remove trust from the dashboard's certificate section (which records the
      removal), then restart the tray: one "Certificate is not trusted"
      notification appears and trust is not silently reinstalled.
- [ ] Dismiss the repair prompt or UAC: a "Setup repair failed" notification appears with a retry action.
- [ ] On a desktop session, `testd host` posts the same notifications; in a session without D-Bus they are logged as `[notice]` and no notification is attempted.
- [ ] A leaf without a token requests access: one "Token request from <label>" notification appears and the tray icon turns light blue until the request is approved, denied, or expires.

## Token requests

- [ ] A leaf without a token shows a notification and a light-blue tray icon until approved or denied.

## Dashboard

- [ ] **Active domains** lists registered names and targets; **Stop** ends the leaf and removes all its names while keeping grants.
- [ ] **Delete** removes only the selected name's grant; its leaf keeps publishing other granted names and must request that name again.
- [ ] **Shares** lists the URL, exposure, and provider; **Stop** removes the
      share but leaves the name registered.
- [ ] **Access** lists waiting requests and issued tokens; approving a request lets its leaf connect, and revoking a token closes all its current connections, releases names, and refuses its next connection.
- [ ] **Quick launches** lists saved definitions and their live state.
- [ ] **Certificate** shows the root summary and fingerprint; **Install** and
      **Remove** update the OS trust store and the page state. The tray menu has no certificate entry.
- [ ] After **Remove**, restarting the tray does not reinstall trust; **Install**
      or the setup wizard is needed to trust it again.
- [ ] A mutation from a cross-site page is refused: the dashboard requires the
      custom request header, and a non-loopback `Host` header gets 403.

## Quick launches

- [ ] Tray: **Quick launches** is a disabled heading, each saved launch is a
      submenu with `label :port`, and its action starts or stops the launch.
- [ ] Save a launch with a program, arguments, one name, and no target. Start it: the name shows `configured`, then `probing`, then `confirmed`; the browser reaches the process.
- [ ] Stop it: the process exits, the name disappears, and the state returns to `configured`.
- [ ] Save a launch with an explicit `127.0.0.1:<port>` target and start it; it registers without detection.
- [ ] While running, rebind to another listening address; the old target stays until the new one confirms.
- [ ] A launch that exits by itself removes its names and reports `exited`.
- [ ] A launch with an unreachable target reports `configured` plus an error and does not leave the child running when no name confirmed.
- [ ] Delete a stopped launch; it disappears from the table and from
      `~/.config/testd/launches.json`.
- [ ] Quit the tray while a launch runs: the child and its names are gone.
- [ ] Restart the tray: definitions are still listed but nothing is running.

## URL actions

- [ ] Release build: the scheme is registered. Linux: `xdg-mime query default x-scheme-handler/testd` prints the handler. Windows: `reg query HKCU\Software\Classes\testd`. macOS: `plutil -p target/release/bundle/macos/Testd.app/Contents/Info.plist | grep -A3 CFBundleURL`.
- [ ] With the tray running, open `testd://fix/resolver`: the repair runs in the existing instance and no second instance starts.
- [ ] With the tray closed, open `testd://fix/certificate`: the app launches, starts the daemon, and runs the repair.
- [ ] `testd url testd://fix/resolver` forwards to the running daemon; after stopping the daemon it repairs directly.
- [ ] `testd url testd://fix/unknown` is refused with "unknown testd action".
- [ ] A dev build does not overwrite the release handler unless `TESTD_REGISTER_SCHEME=1` is set.

## Launch at login

- [ ] First start after setup creates the login item; the artifact paths are in
      `DEVELOPING.md` ("Launch at login").
- [ ] The tray menu shows **Launch at login**, ticked.
- [ ] Untick it: the login item disappears from the OS, and it is still absent
      after restarting the tray.
- [ ] Tick it again: the login item is back, matching the OS listing.
- [ ] Remove the login item in the OS settings while the tray runs: within five
      seconds the checkbox reflects the change.
- [ ] Tick and untick "Launch at login": the tray stays responsive and the menu
      opens again every time. A click now only posts a message; doing OS or menu
      work inside the menu event froze the whole UI on Windows.
- [ ] `testd uninstall` does not remove the login item; untick it first, or remove
      it by hand.

## Browser

- [ ] Run the browser validation checks in `DEVELOPING.md` with Chrome,
      Firefox, Safari, and Edge on the target OS versions.

## Not implemented yet

Tray attach/detach of an already-running process by PID or port is deferred and is not a release gate. Quick launches wrap a child command instead.

## Packaging and signing

macOS:

```sh
codesign --verify --deep --strict --verbose=2 target/release/bundle/macos/Testd.app
spctl -a -vv -t exec target/release/bundle/macos/Testd.app
xcrun stapler validate target/release/bundle/macos/Testd.app
```

Windows:

```powershell
Get-AuthenticodeSignature target\release\bundle\nsis\*.exe | Format-List
```

Linux:

```sh
dpkg-deb -I target/release/bundle/deb/*.deb
dpkg-deb -c target/release/bundle/deb/*.deb | head
```

Signing credentials are supplied by the operator, not stored here. Public CI builds unsigned artifacts. Signing observations apply only to artifacts advertised as signed; record unsigned ones as not applicable with a reason.

## Install, upgrade, and removal

- [ ] Install the actual candidate package in a fresh desktop session and reach a trusted HTTPS name using the documented setup and Linux port-privilege instructions.
- [ ] Upgrade a previous install without changing the operator secret, root trust, saved launches, or the launch-at-login preference.
- [ ] Untick launch at login, stop the daemon, and run `testd uninstall`; DNS routing and the exact installed trust root are removed.
- [ ] Remove the app through the platform uninstaller; no tray process or listeners remain.
- [ ] Reinstall and confirm the documented setup path works again.
