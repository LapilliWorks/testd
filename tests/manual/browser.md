# Real-browser contracts

These checks require an actual browser and OS resolver. Bun fixture tests do not execute the page in a browser and do not establish browser cookie, trust, or TLS behavior.

## Preconditions

Use a disposable, restorable host and a clean browser profile with no real accounts or data. Record the candidate CLI and app hashes, source commit, OS and browser versions, architecture, DNS mode, edge port, and evidence without recording credentials or private keys. Obtain approval before testing any non-loopback listener or another device.

Initialize the candidate and establish the OS resolver and trust path using the selected platform's setup on the disposable host. Confirm `testd doctor --json` reports working resolution. Do not bypass certificate warnings, use an insecure browser flag, or substitute browser-only DNS overrides for the OS resolution being tested. On a claimed browser that uses a separate trust store, install the candidate's public root in that disposable browser profile and record how it was trusted.

Run the suite from the same revision as the candidate. The report path must not exist yet. If the suite attaches to an existing daemon, separately verify that it is the intended candidate; the runner does not prove that association. A non-default edge port must match the running host.

```sh
python3 tests/release/run.py browser --bin /path/to/candidate-testd --report /path/to/new-persisted-report
# Add --edge-port 8443 when the candidate is configured to listen there
```

## Browser workflow

- [ ] BROWSER-01: In each browser and version selected for the release, open the URL printed by the runner. It loads without a warning or bypass and reports a secure HTTPS context.
- [ ] BROWSER-02: Inspect the certificate in the browser. The SAN matches the name, the leaf chains through the testd intermediate to the intended local root, and it expires within 24 hours of minting. Record the leaf SHA-256 fingerprint.
- [ ] BROWSER-03: Run the page's automatic checks. WebSocket exchange works before and after 60 seconds idle; SSE arrives without full-response buffering; a 100 MiB upload is complete.
- [ ] BROWSER-04: The project-domain cookie reaches the app and API names in the same project but not the separately registered `app.othercheck.test` project. Confirm the page reports the cookie isolation check as passed.
- [ ] BROWSER-05: Open the three observation links. The local dashboard loads, the unregistered name fails at DNS or TLS rather than reaching an application, and the registered dead upstream returns HTTP 502.
- [ ] BROWSER-06: Restart the daemon using the page button only when the suite started it; otherwise restart the intended daemon manually. Reload, verify the newly minted leaf is trusted, record its fingerprint, and rerun the automatic checks.
- [ ] BROWSER-07: Enter the browser and OS versions, confirm only observations actually performed, and save the page's report. A failed or incomplete run is retained as a failure, not repaired by checking boxes without evidence.
- [ ] BROWSER-08: Repeat on the default port and any non-default edge port claimed for release. Record explicit reasons for combinations not tested.

Use a distinct report for each run or retain every saved browser JSON. Stop the fixtures with Ctrl+C and confirm the names disappear; the runner stops only the daemon it started. Review the report for the exact four check names, manual confirmation, candidate commit, origin, fingerprint, and failures. A report for one browser does not prove another browser or OS combination.
