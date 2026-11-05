# Conditional network and share contracts

These checks apply only if the corresponding feature is included in the release. Separate network controls, network-change pause, and claim-bound share lifetime are not implemented yet; they are blocked contracts, not passes. Provider cleanup-failure and recovery policy still need decisions.

Use two disposable, restorable machines on an isolated test network, synthetic services, and short-lived fixture credentials. Record the candidate commits and hashes, interface addresses, network transitions, authorization decisions, process and provider observations, and results. Do not retain tokens, private keys, live public URLs, or packet captures containing credentials in public reports. Do not enable a real provider or an externally reachable listener without explicit operator approval.

## Network boundaries

- [ ] NET-01: A fresh instance accepts registration and HTTPS only on loopback, serves DNS only on loopback, and does not expose the dashboard to the second machine.
- [ ] NET-02: When the separate controls exist, explicitly enable only registration on a selected interface. Remote registration works only there, local dashboard and quick-launch control continue to work, and other surfaces remain unexposed.
- [ ] NET-03: Explicitly enable only the application edge on a selected interface. The intended remote client can reach an authorized app, while registration and dashboard exposure remain independently controlled.
- [ ] NET-04: Remote dashboard access remains disabled until explicitly enabled and requires the approved authentication and session protections. Test a different local OS user, an unauthenticated remote browser, CSRF, and DNS rebinding after that design exists.
- [ ] NET-05: While affected HTTP, streaming, WebSocket, dashboard, and registration connections are active, disconnect or reassociate the selected connection. Affected exposure pauses and connections close; stored grants remain.
- [ ] NET-06: Reconnect with the same network label. Exposure remains paused until explicit confirmation unless authenticated continuity has been established; a label or SSID alone is not proof of continuity.
- [ ] NET-07: Repeat the applicable transition and confirmation checks for wired and wireless connections. Verify that unaffected interfaces remain available only when their independence is established.
- [ ] NET-08: On network pause, affected or not-provably-independent shares stop and affected pending starts are cancelled. They do not restart automatically after network confirmation; cleanup failures are visible.

## Share lifetime

Start with a controlled registered service and an approved provider fixture. If a real provider is needed for a claimed platform, use an explicitly authorized test account and synthetic content; verify the URL and provider's declared exposure before sending any request.

- [ ] SHARE-01: Start and stop a share. Its published URL, exposure, target, and provider are visible; stop removes the publication while the underlying local registration remains.
- [ ] SHARE-02: Repeat the same name and target on the same connection. The existing share and provider remain uninterrupted.
- [ ] SHARE-03: Change the registered target on the same connection. The previous share stops and does not publish either the old or the new target until explicitly started again.
- [ ] SHARE-04: Force a name takeover from another connection, then separately reconnect using the same credential and target. Each new owner causes the previous share to stop and requires explicit re-sharing.
- [ ] SHARE-05: Fail a registration change and restore the original claim without an intervening successful change. The original share remains only if that restoration is proven; an intervening successful owner or target change stops it.
- [ ] SHARE-06: Hold a provider at a controlled startup barrier, remove or change its authorizing claim, then release the barrier. The start is cancelled, no share is listed or reachable, and no provider is left running.
- [ ] SHARE-07: On normal stop, daemon exit, failed provider startup, and provider exit, check both the reported share list and the actual owned provider state. A missing list entry alone is not proof of cleanup.
- [ ] SHARE-08: After the cleanup and recovery policy is decided, interrupt the disposable daemon and test restart reconciliation. Unrelated provider processes, accounts, and configuration must not be changed without proven ownership.

A fake provider is useful for deterministic lifecycle tests but cannot establish a real provider's exposure, stop behavior, network independence, or crash cleanup. Record those as separate platform and provider results.
