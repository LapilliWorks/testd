# Test contracts

The test suite is organized around observable standalone behavior: initialize a host, keep its default listeners local, register a name for the lifetime of a connection, resolve that name, serve it over trusted HTTPS, diagnose failures, and remove only owned integration. Shares and network exposure have additional safety contracts when included in the release. Team workspaces, payment, and organization authority are not prerequisites for a standalone test run.

## Evidence levels

| Level | What it establishes | What it does not establish |
|---|---|---|
| Unit | Parsing, validation, ownership decisions, protocol framing, and failure paths in isolation | A running system or browser |
| Component integration | Real loopback TCP, UDP, TLS, subprocess, and proxy behavior using controlled fixtures | OS DNS routing, system trust, real providers, or a full installed product |
| Host | A candidate CLI and daemon with an isolated user and test-only TLD; optional system changes only on a disposable host | A desktop UI or a real browser |
| Manual | Actual installed artifacts, OS integration, GUI, browsers, and explicitly approved provider/network behavior | Other OS versions, browsers, or artifacts not tested |

Never count an ignored, skipped, inapplicable, or unrun check as a pass. A successful command is not release approval: review its scope, failures, skips, candidate provenance, and the platform/browser matrix. Keep reports private until reviewed; they can contain credentials and local PKI material.

## Contract matrix

| Contract | Automated coverage | Remaining evidence or blocker |
|---|---|---|
| Fresh configuration, private state, DNS-only setup, and local defaults | `tests/cli.rs`, `testd-core` config tests | Installed packages, OS permissions, and actual GUI setup |
| Authentication, name validation, duplicate ownership, rollback, disconnect, and revocation | `crates/testd-daemon/tests/engine.rs`, core protocol and registry tests, `product_flow.rs` | The deferred grant-revocation race and platform workflow validation |
| DNS A answers, case-insensitive names, unknown names, malformed input, and loopback listener | `resolver/dns.rs` unit tests and `product_flow.rs` over real UDP | Real OS resolver integration |
| TLS name and root validation, proxy routing and failures | `crates/testd-daemon/tests/edge.rs`, `product_flow.rs`, `testd-pki` tests | Installed system and browser trust; real browser behavior |
| Preserve unowned resolver and trust state, report conflicts, remove only proven owned state | Linux ownership, resolver, and trust script fixtures in `crates/testd-setup` | Shared trust-store effects and concurrent privileged changes; real disposable-host checks; macOS and Windows ownership safeguards are incomplete |
| Loopback dashboard, quick launches, and request protections | `engine.rs`, `tests/host/`, dashboard and launch unit tests | Real tray and browser; dashboard authentication and other local-user boundaries are not implemented |
| Share lifecycle and provider exits | `crates/testd-daemon/tests/share.rs` and fake-provider reconciliation tests | Four claim and pending-start contracts currently fail and are ignored; actual provider termination, cleanup failures, and crash recovery remain unverified |
| Explicit network exposure and pause on network change | Default listener tests only | Separate controls, dashboard authorization, network-change pause, and share handling are not implemented |
| Packaging, rollback, and reports | `tests/release/test_release.py`, release-script fixtures, and artifact runner | Candidate provenance, actual installation, signing, upgrade, and uninstall on each claimed platform |
| Browser fixture | `tests/release/browser.test.ts` exercises the fixture server, not a browser | Execute and save real-browser results for every claimed OS/browser combination |

`crates/testd-daemon/tests/product_flow.rs` composes the real registration engine, DNS server, and TLS edge on ephemeral loopback sockets. Its root is trusted only by the test client, and a resolver wrapper forbids system integration. It is not a full daemon process, OS trust test, browser test, or GUI test.

## All-in-one platform run

Run the matching script on each actual platform and architecture. The `all` suite runs GUI and non-GUI Rust checks, the ignored release contracts, doctests, release-script and browser-server fixtures, the full dependency audit, version verification, website checks, a candidate CLI build, and the unprivileged host suite. Each stage has explicit `BEGIN` and `END` markers, its own report and logs, and a final summary. Failed stages do not prevent independent checks from running.

```sh
python3 scripts/test-linux.py all
python3 scripts/test-macos.py all
```

```powershell
python scripts\test-windows.py all
```

The scripts require Python 3.12 or newer, Rust 1.89, 1.90 and stable, `cargo-nextest`, `cargo-deny`, Bun, installed website dependencies, and the platform GUI prerequisites. They do not install dependencies. `all` builds a CLI unless `--bin` specifies an existing candidate; a pre-existing build candidate is backed up in the report. Website output and caches are isolated inside the report rather than overwriting the checkout's `dist/`. Run `all --plan` to list stages without executing them.

For the system, desktop, browser, artifact, and manual stages, provide the candidate assets and explicitly opt in. The report directory must be new and persisted outside temporary storage. Use a disposable VM with a persisted full-system snapshot; on Windows, use an elevated PowerShell.

```sh
python3 scripts/test-linux.py all --system --interactive --app /path/to/candidate-app \
  --artifacts /path/to/host-assets --no-previous-release --report /path/to/new-persisted-report
```

```powershell
python scripts\test-windows.py all --system --interactive --app C:\candidate\setup.exe `
  --artifacts C:\candidate\assets --no-previous-release --report D:\testd-reports\run-001
```

On macOS, use `scripts/test-macos.py` with the same options. Pass `--bin` for a verified candidate CLI. Supply `--previous-bin` instead of `--no-previous-release` when a real previous release exists. The assets directory must contain the host-compatible candidate assets and `SHA256SUMS`. The build fingerprint and CLI hash do not establish release-artifact provenance.

`--system` requires an interactive confirmation of the disposable host and full-system snapshot; each sensitive stage asks again. `--interactive` adds the actual desktop and browser runners and prompts for every manual checklist result and evidence. The browser stage requires configured OS DNS and trust and refuses to attach to an existing daemon. Some checklists require separately restored snapshots, multiple machines, or separate browser runs; skip a stage and use another run on the appropriate VM rather than assuming one snapshot covers them. Network exposure and real providers still require explicit approval.

Missing prerequisites, declined stages, unprovided artifacts, and skipped checks are recorded as blocked, not passed. Exit status is `1` for any failure, `2` for an incomplete run without failures, and `0` only when all applicable stages completed without failures. The Linux and macOS release-contract stages currently fail on four share-lifetime contracts; the full GUI dependency audit has a known unmaintained-dependency advisory. The optional Windows NRPT diagnostic is not tracked and its cleanup can remove unrelated rules, so it remains blocked instead of being run automatically. The macOS probe is wrapped in a scoped resolver/trust snapshot, which is not a full VM backup.

Inspect `report.json`, `boundaries.log`, and each stage's report and logs. A failed or incomplete system stage blocks later sensitive stages unless its cleanup was verified. If the self-test cannot restore, its retained `self-test-state` directory can be passed to `tests/release/run.py --restore-report`; use the full VM snapshot if scoped recovery is incomplete. Reports may contain credentials and fixture keys and must remain private.

## Individual platform suites

Without arguments, the platform scripts retain their non-GUI automated sequence. Use the Linux script in WSL. Each entry point rejects a different operating system. Run `--help` to see all options:

```sh
python3 scripts/test-linux.py
python3 scripts/test-macos.py
```

```powershell
python scripts\test-windows.py
```

The same options work on all three platforms:

| Invocation | Checks |
|---|---|
| `all` | Every automated stage, plus explicitly enabled and prepared system, artifact, desktop, browser, and manual stages |
| `automated --gui` | Default automated checks plus the Rust 1.90 tray check and full-workspace tests; requires platform GUI prerequisites |
| `contracts` | Release contracts including ignored cases; currently fails on known blockers |
| `audit` | Full-workspace cargo-deny audit; requires `cargo-deny` |
| `host --bin <candidate> --report <new-report>` | Unprivileged candidate CLI and daemon checks |
| `host --build --report <new-report>` | Build a candidate, then run the unprivileged host checks |
| `host --bin <candidate> --report <new-report> --system` | Privileged resolver and trust checks; requires a disposable, backed-up host and interactive confirmation |
| `browser --bin <candidate> --report <new-report>` | Launch the browser fixture; complete the real-browser checklist yourself |
| `desktop --app <candidate> --report <new-report>` | Launch the candidate and record the interactive desktop checklist |

For example, `python3 scripts/test-linux.py host --build --report "$HOME/testd-reports/linux-host"` builds and tests on Linux. On Windows, use `python scripts\test-windows.py host --bin target\release\testd.exe --report C:\testd-reports\windows-host`. Report paths must not exist already; build, system, and desktop reports must be outside temporary directories. The build uses the stable compiler's native target under `CARGO_TARGET_DIR` (or this checkout's `target/`), preserves an existing target binary in the report, and uses a checkout-specific compiler fingerprint. It does not by itself establish release-artifact provenance. Automatic builds reject `CARGO_BUILD_TARGET`; use `--bin` for a separately built candidate or a cross-target build.

System, desktop, browser-trust, and installation checks require a clean disposable machine and a persisted full-system snapshot. On Linux and macOS, validate sudo in the same terminal before `host --system`; on Windows, use an elevated PowerShell. The runner's scoped snapshot is not a full machine backup. Desktop and browser suites need actual operator interaction; they are not covered by the automated fixtures.

## Routine automated checks

The scripts above run these commands. To run them individually from the repository root:

```sh
cargo +stable fmt --all -- --check
cargo +stable clippy --workspace --all-targets --exclude testd-gui --locked -- -D warnings
cargo +1.89.0 nextest run --workspace --exclude testd-gui --locked
python3 -m unittest discover -s tests/release -p test_release.py
bun test "$(pwd)/tests/release/browser.test.ts"
```

Use an absolute fixture path: Bun treats a relative path as a search pattern and can otherwise run matching tests from nested worktrees or build snapshots. On Windows PowerShell, use `bun test "$PWD\tests\release\browser.test.ts"`.

The GUI requires its platform build prerequisites and separate Rust 1.90 checks. Run the full dependency policy against the selected release scope; a non-GUI or CI-scoped pass does not clear a GUI-only advisory. The cross-language browser-report fixture skips without Bun, and PowerShell parser and behavior fixtures skip when PowerShell is unavailable; a PowerShell fixture is not a Windows platform run.

The four share contracts are deliberately ignored in the default Rust run because they currently fail. Run them explicitly to reproduce the known failures, then remove the ignore markers when the behavior is implemented. The release runner's `core` suite includes ignored tests, so it remains blocked by these failures. Stable version tags also run that gate in CI; prerelease tags and ordinary CI runs do not, and do not constitute release approval. These contracts use fake Unix providers and do not test the deferred grant-revocation race.

```sh
cargo +1.89.0 test -p testd-daemon --lib daemon::tests -- --ignored
```

After implementing them, run the complete non-GUI suite including ignored cases and require no unexplained skips:

```sh
cargo +1.89.0 nextest run --workspace --exclude testd-gui --locked --run-ignored all
```

## Host and manual checks

For an unprivileged host run, use an identified candidate and a new persisted report path. The suite binds fixed loopback fixture ports and refuses busy ports; it must not compete with a real daemon.

```sh
python3 tests/release/run.py host --bin /path/to/candidate-testd --report /path/to/new-persisted-report
```

Resolver and trust operations, package installation, and desktop sessions require a clean disposable machine and a persisted full-system snapshot. The runner's scoped snapshot is not a full-machine backup. Use the following contracts and record pass, fail, blocked, or not applicable with a reason for every selected platform and feature:

- [Desktop setup and tray](host/gui-checklist.md)
- [Real browsers](manual/browser.md)
- [Resolver and trust coexistence](manual/system-integration.md)
- [Installation and artifacts](manual/installation.md)
- [Conditional network and share behavior](manual/network-and-sharing.md)

The GUI runner requires an interactive terminal and a fresh user. It asks for backup and shutdown confirmation, refuses an empty checklist, snapshots the product `.test` integration, and defers restoration if candidate processes have not been confirmed stopped. The report's recovery command restores only its scoped snapshot; a VM snapshot remains necessary.
