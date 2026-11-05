# System integration contracts

These checks can modify machine-wide DNS and trust. Use only a disposable VM with a persisted, restorable full-system snapshot and a fresh user. Do not seed or remove real routes, certificates, or production trust. Record the OS image and version, resolver implementation, candidate hashes and source commit, full-system snapshot location, commands, results, and before/after evidence without collecting private keys or credentials.

The release runner snapshots selected paths and refuses existing testd integration. Its snapshot is not a full machine backup and does not prove that shared CA bundles, hooks, unrelated resolver configuration, or login settings are unchanged. The conflicting-state cases below require separate, manually seeded disposable snapshots; do not use `host --system` to overwrite a conflict. macOS and Windows do not yet have equivalent ownership safeguards, so their destructive conflict cases are known blockers and must never be attempted on a real host.

```sh
python3 tests/release/run.py host --system --bin /path/to/candidate-testd --report /path/to/new-persisted-report
```

## Clean installation and recovery

- [ ] SYS-01: On a clean disposable host, run the candidate's `host --system` release suite with the required elevation. It installs its test-only DNS route and root, resolves its test name through the OS, reaches the edge without a TLS bypass, and records an actual successful restore.
- [ ] SYS-02: Verify `doctor --json` distinguishes an unavailable resolver, a missing route, missing trust, and a working setup. Check that failures give an actionable reason and do not claim success.
- [ ] SYS-03: Interrupt a separate test run after a scoped snapshot is persisted. Stop all candidate and provider processes, run the report's `--restore-report` recovery command, and compare the selected state with the snapshot. Restore the full VM if recovery is incomplete.
- [ ] SYS-04: Before uninstall or purge, retain the installation ID and root certificate required for owned cleanup. Confirm a missing root or missing ownership proof produces an error and does not purge the data needed for recovery.

## Unowned and conflicting state

For each case, restore a clean VM snapshot, seed only synthetic state, record its bytes, file identity, permissions, certificate fingerprint, and applicable OS route or store entries, and then run the candidate operation. Compare the same state afterwards. A reported conflict is not permission to delete the fixture manually on a non-disposable host.

- [ ] SYS-05: Seed compatible resolver configuration without a testd ownership record. Setup may use it, but uninstall must not adopt, remove, or rewrite it.
- [ ] SYS-06: Seed a conflicting resolver route or occupied resolver path, including a symlink and a per-link route where supported. Setup reports the conflict and leaves the fixture and unrelated routes unchanged.
- [ ] SYS-07: After testd installs an owned route, replace or alter the route or ownership record. Cleanup reports the changed state and leaves it untouched; an unchanged owned route can be removed.
- [ ] SYS-08: Seed trust in the same public root without an ownership record. Setup may use it, but uninstall must not claim or remove that trust.
- [ ] SYS-09: Seed an unrelated certificate at the candidate anchor path or in the relevant store. Setup and cleanup report conflicts and preserve the unrelated certificate and its metadata.
- [ ] SYS-10: After testd installs an owned anchor, change or replace the anchor or ownership record. Cleanup refuses the altered state; an unchanged owned anchor can be removed.
- [ ] SYS-11: On Linux with systemd-resolved, seed a non-conflicting loopback link DNS and route. Installing and removing the owned drop-in does not revert those link settings.
- [ ] SYS-12: On Linux, compare unrelated source anchors and effective trust before and after each CA-store rebuild, including any distro hooks and the generated bundle. Record any shared-store effect rather than assuming byte-for-byte regeneration is a no-op.
- [ ] SYS-13: Pause a privileged authorization prompt, change a synthetic resolver or trust fixture from another authorized session, then approve. The operation must recheck and refuse conflicting state; this single interleaving does not prove absence of all concurrent races.

## Platform evidence

- [ ] SYS-14: Run the applicable cases on each claimed Linux distribution and resolver stack, including the actual distro trust utility. Unsupported resolver stacks report their limitation rather than being marked passed.
- [ ] SYS-15: After equivalent ownership safeguards exist, repeat the cases against macOS `/etc/resolver` and the System keychain. Until then, record this platform's ownership coverage as blocked.
- [ ] SYS-16: After equivalent ownership safeguards exist, repeat the cases against Windows NRPT and the machine root store, including UAC and exact certificate identity. Until then, record this platform's ownership coverage as blocked.

A successful fixture script or a restored test-only path is not evidence that a real OS trust store, browser store, or unowned configuration was preserved. Keep all reports private until reviewed.
