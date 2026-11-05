# Installation and artifact contracts

Run on each OS, architecture, packaging format, and upgrade path selected for release. Use a disposable machine with a persisted full-system snapshot. A source build, archive checksum, or script fixture is not proof that the installed desktop package works.

## Provenance

- [ ] INSTALL-01: Record the exact source commit, clean or dirty state, toolchains, build host, build commands, artifact names, and SHA-256 digests. Verify that every candidate binary was built from the intended source; a shared build cache alone is not provenance.
- [ ] INSTALL-02: Verify the published checksum manifest against the downloaded candidate. Verify signing and notarization only when advertised; otherwise record the artifact as unsigned, not verified.
- [ ] INSTALL-03: Run `python3 tests/release/run.py artifacts --artifacts /path/to/candidate --require-checksums --report /path/to/new-persisted-report`. Retain the report and distinguish archive checks from installed-app observations.

## Installed workflow

- [ ] INSTALL-04: Install the actual selected package for the current platform, launch it with a fresh user, and complete setup. Record privileges and prompts, including Linux port-binding prerequisites.
- [ ] INSTALL-05: Start a controlled local service, register a project name, resolve it through the OS, and open trusted HTTPS in a real browser. Do not bypass DNS or certificate checks.
- [ ] INSTALL-06: Stop the registration and verify the name and application route disappear. Check `doctor` and the dashboard report the resulting state accurately.
- [ ] INSTALL-07: If upgrading an actual prior release is in scope, install that release, retain the secret, root certificate, launch definitions, and relevant preferences, upgrade to the candidate, and verify those attributes and the workflow. Do not treat an unpublished test tag as a prior release.
- [ ] INSTALL-08: On a separate snapshot, exercise an interrupted or failed upgrade and the documented rollback. Verify the prior binary and retained data, then repeat the core workflow.
- [ ] INSTALL-09: Stop candidate processes and shares, disable any login item, uninstall owned resolver and trust integration, and remove the package. Verify owned state is gone and unowned state is unchanged; preserve and report conflicts.
- [ ] INSTALL-10: Purge user data only after system cleanup is complete and its ownership evidence is no longer needed. Reinstall and verify the documented fresh setup path.

Record each platform and package result separately. macOS and Windows resolver/trust ownership remains blocked until its safeguards and disposable-host validation are complete. Keep reports private until reviewed.
