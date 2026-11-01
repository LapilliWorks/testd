# Dependency advisory exceptions

`cargo deny check` remains the dependency policy gate. Vulnerability advisories are not exempted.

## D-Bus crate merger

The following informational `unmaintained` advisories are temporarily accepted:

| Advisory | Crate | Upstream replacement |
|---|---|---|
| RUSTSEC-2026-0370 | `zvariant` | `zbus::wire` in zbus 6 |
| RUSTSEC-2026-0371 | `zbus_names` | `zbus::names` in zbus 6 |
| RUSTSEC-2026-0372 | `zvariant_derive` | Derive macros in zbus 6 |

These advisories describe the standalone crates being merged into zbus, not reported exploitable vulnerabilities. Their records contain no patched standalone version.

`notify-rust` and Tauri's Linux single-instance backend require zbus 5. Current upstream releases retain that requirement. Upgrading a transitive version cannot replace zbus 5 with the incompatible zbus 6 API. Notification actions and single-instance/deep-link behavior remain enabled.

The three advisory IDs are listed explicitly in `deny.toml`; all other advisory checks remain enforced. Their dependency entries in `crates/testd-daemon/Cargo.toml` and `src-tauri/Cargo.toml` carry the same rationale.

Remove these exceptions once both dependency paths use zbus 6 and the standalone crates no longer appear in the resolved graph. Reassess the exceptions on every notification or single-instance dependency update. Upstream migration: [zbus issue 2043](https://github.com/z-galaxy/zbus/issues/2043).

## Notification MSRV

The daemon pins `notify-rust` to 4.17.0. Version 4.18 raises its declared minimum Rust version to 1.89, above the CLI/daemon's Rust 1.88 minimum. Revisit the pin when a compatible upstream release is available or the supported minimum Rust version changes.
