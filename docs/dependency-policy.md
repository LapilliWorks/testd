---
title: Dependency policy
description: 'Advisory exceptions and MSRV constraints accepted by the dependency gate.'
---

# Dependency advisory exceptions

`cargo deny check` remains the dependency policy gate. Vulnerability advisories are not exempted.

## GTK3 procedural macros

RUSTSEC-2024-0370 reports that `proc-macro-error` 1.0.4 is unmaintained; it does not report a vulnerability or a patched release. The locked crate is used at build time through `glib-macros` and `gtk3-macros` in the GUI's GTK3 dependency graph, not in the shipped runtime. The single advisory is temporarily exempted in `deny.toml`.

An unmaintained crate can still develop security problems. Reassess the exception when the GTK or Tauri dependencies change, remove it when those macros no longer require the crate, and continue enforcing any vulnerability advisory.

## D-Bus crate merger

The following informational `unmaintained` advisories are temporarily accepted:

| Advisory | Crate | Upstream replacement |
|---|---|---|
| RUSTSEC-2026-0370 | `zvariant` | `zbus::wire` in zbus 6 |
| RUSTSEC-2026-0371 | `zbus_names` | `zbus::names` in zbus 6 |
| RUSTSEC-2026-0372 | `zvariant_derive` | Derive macros in zbus 6 |

These advisories describe the standalone crates being merged into zbus, not reported exploitable vulnerabilities. Their records contain no patched standalone version.

`notify-rust` and Tauri's Linux single-instance backend require zbus 5. Current upstream releases retain that requirement. Upgrading a transitive version cannot replace zbus 5 with the incompatible zbus 6 API. Notification actions and single-instance/deep-link behavior remain enabled.

These three advisory IDs are listed explicitly in `deny.toml`; other advisory checks remain enforced except for the GTK3 maintenance notice above. Their dependency entries in `crates/testd-daemon/Cargo.toml` and `src-tauri/Cargo.toml` carry the same rationale.

Remove these exceptions once both dependency paths use zbus 6 and the standalone crates no longer appear in the resolved graph. Reassess the exceptions on every notification or single-instance dependency update. Upstream migration: [zbus issue 2043](https://github.com/z-galaxy/zbus/issues/2043).

## Notification MSRV

The daemon requires `notify-rust` 4.18 for notification action callbacks on macOS and Windows. This release requires Rust 1.89, which is the CLI/daemon MSRV. The tray MSRV remains Rust 1.90. Release-validation and CI checks use these respective toolchains.
