# Desktop manual contracts

These checks require the actual candidate app, an interactive desktop, and the candidate CLI from the same source revision. They do not replace the real-browser, system-ownership, or artifact checks in `tests/manual/`.

## Safety and evidence

Use a clean disposable VM with a persisted, restorable full-system snapshot. Do not use an existing workstation, real credentials, production projects, or a real tunnel provider. Record the source commit, dirty state, candidate paths and hashes, OS and desktop versions, architecture, and evidence for each check; do not record secrets, tokens, private keys, or unreviewed report directories.

The desktop runner requires a fresh user without a testd config directory and asks for confirmation of the VM backup. It snapshots selected `.test` integration, not the entire OS, user profile, package installation, login items, browser stores, or shared CA-store effects. It clears `TESTD_HOST_TLD` in the launched process environment; use a clean desktop session without that test-only override in its inherited environment. The runner restores its scoped snapshot only after you confirm every candidate app, daemon, and provider has stopped. If restoration is deferred or interrupted, stop those processes and use the report's `--restore-report` recovery command; restore the VM snapshot if necessary.

On Linux, verify that the actual tray binary can bind port 443 before testing first-run setup. A failure to bind is a failed setup result, not a passed browser or tray check. On Windows, run the runner in an elevated PowerShell so it can snapshot the machine store and NRPT rules. macOS and Windows resolver and trust ownership protections remain incomplete; do not treat these checks as proof that either platform is safe for release.

```sh
python3 tests/release/run.py desktop --app /path/to/candidate --report /path/to/new-persisted-report
```

Answer each item `p`, `f`, `n`, or `q`. Give a reason for every failure or inapplicable item. A skipped item is not a pass; review every skip against the selected release scope. A zero exit from this runner alone is not release approval.

## First run and setup

- [ ] GUI-01: On a fresh user, launch the candidate. One setup dialog opens on an ephemeral loopback address, not the normal intake port or `testd.test`.
- [ ] GUI-02: Before resolver and certificate setup are complete, Finish is unavailable. Each setup card reports its actual success or failure.
- [ ] GUI-03: The operator secret is generated, can be regenerated and copied, and a value shorter than 16 characters cannot finish setup. Do not include the secret in evidence.
- [ ] GUI-04: Interrupt and reopen setup before finishing. The pending secret is retained unless Generate is selected.
- [ ] GUI-05: Temporarily occupy the edge port with a controlled loopback listener and select Finish. Setup reports the bind failure and the next launch resumes setup rather than claiming success.
- [ ] GUI-06: Release the test listener and complete setup. The config and local root are created for this user, the daemon starts once, the dialog closes, and the dashboard opens.

## Local workflow and lifecycle

- [ ] GUI-07: After setup there is one tray or menu-bar icon. The local dashboard and `https://testd.test/` on this machine show the same current state.
- [ ] GUI-08: Inspect the fresh configuration and listeners. Registration and HTTPS listen on loopback by default; DNS is loopback-only.
- [ ] GUI-09: Start a controlled local HTTP server and `testd run app.example:3000`. The name and target appear in the tray and dashboard, and opening it reaches the server over trusted HTTPS.
- [ ] GUI-10: Stop the leaf normally. Its name disappears from the tray, dashboard, and DNS, and the browser no longer reaches that application.
- [ ] GUI-11: Start an approved leaf again and stop it through the tray. Its names disappear and its grant remains available for a later run.
- [ ] GUI-12: While the tray is running, try another tray and `testd host`. Neither starts a second daemon or takes over the first daemon's listeners.
- [ ] GUI-13: Request a token from a separate controlled client. The pending request is visible, approval permits the requested name, and denial does not publish a name.
- [ ] GUI-14: Revoke an issued token with a live client. The connection closes, its names disappear, and the old credential is refused on reconnect.

## Dashboard, launches, and repair

- [ ] GUI-15: The dashboard lists live names, targets, saved launches, shares, and access requests consistently with the CLI and tray.
- [ ] GUI-16: Save and start a controlled quick launch. Its child starts, its registered name reaches the child, and stopping it removes the name and terminates the child.
- [ ] GUI-17: A quick launch whose child exits reports that exit and withdraws its name. A failed launch does not leave a child running or a false live name.
- [ ] GUI-18: Restart the tray after stopping a saved launch. The definition remains available, but the child does not start without an explicit action.
- [ ] GUI-19: The certificate view shows the local root fingerprint. Explicit removal changes trust and page state; a restart does not silently reinstall it, and explicit installation restores trust.
- [ ] GUI-20: A mutation without the required request header and a request with a non-loopback Host are refused. This check does not establish authentication against another local user.
- [ ] GUI-21: A missing resolver or certificate produces a useful notification or logged notice. Dismissing an authorization request reports failure rather than claiming repair succeeded.
- [ ] GUI-22: With the tray running, a supported `testd://fix/resolver` action reaches the existing instance; an unknown action is rejected.

## Platform and package observations

- [ ] GUI-23: Where launch at login is supported, toggle it off and on; the OS entry and tray state agree, and the tray remains responsive.
- [ ] GUI-24: If launch at login is included in the release claim, reference a separate persisted logout/login run showing the actual tray starts once. Otherwise record why this platform is out of scope.
- [ ] GUI-25: On Windows, observe the per-user installer and the UAC prompts for privileged setup. On macOS, observe the menu-bar and dock behavior. Record the actual platform and prompt count.
- [ ] GUI-26: Install the candidate package, complete a trusted name, and verify any claimed upgrade preserves the expected secret, root, launch definitions, and login preference.
- [ ] GUI-27: Stop launches and shares, disable the login item, uninstall the product integration, then remove the package. Verify the claimed cleanup and retain any reported conflicts.
- [ ] GUI-28: Quit the tray and verify the candidate app, daemon, provider children, DNS and HTTPS listeners are stopped and the instance lock can be acquired again before confirming restoration.

## Coverage limits

Browser behavior requires `tests/manual/browser.md`; resolver and trust coexistence require `tests/manual/system-integration.md`. Conditional network and share contracts are in `tests/manual/network-and-sharing.md`. A passing desktop checklist does not establish local operator authentication, safe non-loopback exposure, provider crash recovery, platform signing, or preservation of unowned system state.
