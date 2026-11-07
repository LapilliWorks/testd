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
| Share lifecycle and provider exits | Fake-provider claim, pending-start, replacement, cleanup-failure, and reconciliation tests in `daemon.rs`, `engine.rs`, and `crates/testd-daemon/tests/share.rs` | Actual provider termination, network-pause behavior, tailnet ownership, and crash recovery remain unverified |
| Explicit network exposure and pause on network change | Default listener tests only | Separate controls, dashboard authorization, network-change pause, and share handling are not implemented |
| Packaging, rollback, and reports | `tests/release/test_release.py`, release-script fixtures, and artifact runner | Candidate provenance, actual installation, signing, upgrade, and uninstall on each claimed platform |
| Browser fixture | `tests/release/browser.test.ts` exercises the fixture server; an opt-in Playwright runner drives a real browser | Run the selected engine on each claimed OS/browser combination; fixtures alone do not prove browser behavior |

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

`--system` requires an interactive confirmation of the disposable host and full-system snapshot; each sensitive stage asks again. Artifact checks are sensitive because they execute candidate binaries. `--interactive` adds the desktop and browser runners and prompts for every manual checklist result and evidence. The browser stage refuses occupied fixture ports without contacting the listener and starts its own candidate daemon with real providers disabled. With `--browser-engine chromium`, `firefox`, or `webkit`, it drives the selected Playwright browser instead of collecting a manual browser report. Linux `--system` provisions a fixture-owned resolver and CA for the browser stage; other platforms remain blocked for product-managed system setup. Some checklists require separately restored snapshots, multiple machines, or separate browser runs; skip a stage and use another run on the appropriate VM. Network exposure and real providers still require explicit approval.

Missing prerequisites, declined stages, unprovided artifacts, and skipped checks are recorded as blocked, not passed. Explicitly inapplicable platform fixtures remain recorded as skips without blocking the applicable fixture stage; system, browser, artifact, and other missing evidence remain separate blockers. Exit status is `1` for any failure, `2` for an incomplete run without failures, and `0` only when all applicable stages completed without failures. The full GUI audit has a narrow documented exception for an unmaintained build-time GTK macro; other advisories remain enforced. The Windows NRPT diagnostic and macOS resolver probe are blocked until their cleanup proves ownership.

Every suite writes a live UTF-8 `run.log` containing runner messages and emitted command stdout and stderr. The `all` transcript includes every stage boundary and summary; individual command logs retain the raw combined bytes. Rust nextest output includes passing and failing tests. The `all` doctest stages retain each executable's separate stdout and stderr and replay them into the transcript, including ignored tests. If an existing Cargo rustdoc flag or custom target runner prevents safe capture, the tests still run unchanged but doctest logging is marked blocked.

To retain the exact tracked staged and unstaged changes, including mode bits, pass `--include-git-diff`. The report stores separate binary patches and checks whether tracked changes remained stable during capture. It does not collect untracked file contents. Patches can contain secrets, so use this option only with a private report and review them before sharing.

Inspect `report.json`, `run.log`, `boundaries.log`, and each stage's report and logs. Desktop app output, browser evidence, host fixture files, and system snapshots remain separate report files; typed input, sudo prompts, and GUI actions are not recorded. A failed or incomplete system stage blocks later sensitive stages unless its cleanup was verified. The real system self-test cannot verify shared trust-store output or hooks, so it records blocked coverage and stops later sensitive stages in that run. Use separate restored VMs or snapshots for other checks. After an interrupted self-test, its retained `self-test-state` directory can be passed to interactive `tests/release/run.py --restore-report`; scoped verification still does not replace full-system recovery. Complete logs can contain credentials and fixture keys and must remain private.

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
| `contracts` | Release contracts including ignored cases |
| `audit` | Full-workspace cargo-deny audit; requires `cargo-deny` |
| `host --bin <candidate> --report <new-report>` | Unprivileged candidate CLI and daemon checks |
| `host --build --report <new-report>` | Build a candidate, then run the unprivileged host checks |
| `host --bin <candidate> --report <new-report> --system` | Linux-only resolver and trust checks; requires a disposable, backed-up host and interactive confirmation; shared trust effects remain unverified |
| `browser --bin <candidate> --report <new-report>` | Launch the browser fixture against separately configured OS DNS and trust; complete the real-browser checklist yourself |
| `browser --bin <candidate> --report <new-report> --browser-engine chromium` | Drive a real Playwright browser against separately configured OS DNS and trust |
| `browser --bin <candidate> --report <new-report> --system --browser-engine chromium --edge-port 8443` | Linux-only fixture-owned system integration and Playwright check with scoped cleanup and verification; shared trust effects remain unverified |
| `desktop --app <candidate> --bin <candidate-cli> --report <new-report>` | Run the Linux interactive desktop checklist with ownership-checked cleanup; macOS and Windows are blocked |

For example, `python3 scripts/test-linux.py host --build --report "$HOME/testd-reports/linux-host"` builds and tests on Linux. On Windows, use `python scripts\test-windows.py host --bin target\release\testd.exe --report C:\testd-reports\windows-host`. Report paths must not exist already; build, system, and desktop reports must be outside temporary directories. The build uses the stable compiler's native target under `CARGO_TARGET_DIR` (or this checkout's `target/`), preserves an existing target binary in the report, and uses a checkout-specific compiler fingerprint. It does not by itself establish release-artifact provenance. Automatic builds reject `CARGO_BUILD_TARGET`; use `--bin` for a separately built candidate or a cross-target build.

System, service, desktop, browser-trust, artifact, and installation checks require a clean disposable machine and a persisted full-system snapshot. Linux `host --system` also needs cached sudo in the same terminal. macOS and Windows product system and desktop checks, macOS launchd supervision, and the platform resolver probes are blocked until ownership and cleanup can be established. The runner's scoped snapshot is not a full-machine backup. Desktop checks and manual browser checks need actual operator interaction; they are not covered by automated fixtures.

### Playwright browser run

Install the `playwright` package where Bun can resolve it and install the selected browser on the disposable machine before running the suite. On Linux, Chromium and Firefox also require the NSS `certutil` tool for an isolated browser-profile trust store. The runner installs no tools or browsers. Use a fresh, private report and confirm that the VM blocks external network egress. The fixture accepts only loopback DNS results and browser requests to its named HTTPS origins; it does not change firewall policy.

For bounded Linux product integration, run `python3 scripts/test-linux.py browser --bin /path/to/candidate-testd --report /path/to/new-persisted-report --system --browser-engine chromium --edge-port 8443`. A high edge port avoids privileged-port access requirements. The runner creates a private fixture home, starts its own daemon, applies the candidate's resolver and root CA through `doctor --fix`, drives a fresh Playwright profile, stops its processes, asks the candidate to remove only owned integration, and compares scoped state. It refuses pre-existing conflicting state. If browser, restart-watcher, or listener shutdown cannot be verified, it leaves system state untouched and requires full-system recovery. Shared trust-store effects remain unverified, so this run is incomplete until the VM is restored or independently compared.

Without `--system`, initialize and configure the same candidate's `.test` DNS and trust separately on the disposable host. The automatic runner requires the candidate root at the default `testd/pki/root.crt` location, verifies OS resolver and trust status, and refuses an occupied intake port. macOS and Windows support this preconfigured browser mode but still require separately proven, recoverable system setup. A pre-existing daemon is never adopted or restarted.

The Playwright report records the engine, user agent, candidate and root hashes, browser-reported certificate details, loopback responses, the fixture's WebSocket, SSE, upload and cookie checks, and leaf fingerprints before and after a runner-owned daemon restart. Separate TLS probes use OS DNS and Python's default platform trust store with hostname verification and must match both browser-run leaf fingerprints. HTTPS errors are not bypassed and DNS is not overridden. The browser uses a direct connection and isolated profile without inherited proxy or trust overrides. Linux's isolated profile imports only the fixture's public root after the OS trust check; it does not modify the operator's browser profile. A short-lived private runtime directory is removed only if it remains owned and empty. A Playwright engine does not establish coverage for installed branded browsers, their certificate viewers, desktop UI, or untested platforms. Reports and retained profiles are private and may contain fixture credentials.

## Routine automated checks

The scripts above run these checks and retain a transcript. Individual commands print output without creating a runner report:

```sh
cargo +stable fmt --all -- --check
cargo +stable clippy --workspace --all-targets --exclude testd-gui --locked -- -D warnings
cargo +1.89.0 nextest run --workspace --exclude testd-gui --locked \
  --success-output immediate --failure-output immediate --status-level all --final-status-level all
python3 -m unittest discover -s tests/release -p 'test_*.py' -v
bun test "$(pwd)/tests/release/browser.test.ts"
```

Use an absolute fixture path: Bun treats a relative path as a search pattern and can otherwise run matching tests from nested worktrees or build snapshots. On Windows PowerShell, use `bun test "$PWD\tests\release\browser.test.ts"`.

The GUI requires its platform build prerequisites and separate Rust 1.90 checks. Run the full dependency policy against the selected release scope; a non-GUI or CI-scoped pass does not clear a GUI-only advisory. The cross-language browser-report fixture requires Bun. PowerShell parser and behavior fixtures are required on Windows; their absence on other platforms is inapplicable. A PowerShell fixture is not a Windows platform run.

The release runner's `core` suite and stable version tags include ignored tests; prerelease tags and ordinary CI runs do not constitute release approval. Share-lifetime contracts use fake Unix providers and do not test the deferred grant-revocation race. Run the complete non-GUI suite including ignored cases and require no unexplained skips:

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

The Linux GUI runner requires an interactive terminal, a fresh user, the candidate CLI, and backup and shutdown confirmation. It refuses an empty checklist, snapshots selected `.test` integration, and defers cleanup if candidate processes have not been confirmed stopped. macOS and Windows GUI runs remain blocked. Scoped recovery leaves unowned or changed state untouched and does not verify shared trust-store effects; a full VM snapshot remains necessary.
