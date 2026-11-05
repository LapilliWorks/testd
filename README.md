# testd

Stable HTTPS names for projects running in containers, VMs, WSL, or remote boxes. The machine with the browser runs the host daemon; each dev environment registers over a single TCP connection.

```
dev environment (VM, container, WSL, remote box)
  testd run app.example:3000
        │
        │  NDJSON over TCP, leaf token
        ▼
host machine (browser machine)
  testd host
    ├─ DNS: *.test → the host
    ├─ HTTPS edge: minted leaf certificates
    └─ reverse proxy → the dev environment's port
```

No Caddy, no per-project `/etc/hosts` edits, and no per-project certificates. A registration lives only as long as the connection that created it. Closing the terminal removes the name.

## Documentation

- [Quickstart](docs/quickstart.md): install, first host, first name
- [Daily usage](docs/usage.md): names, dashboard, sharing, access, troubleshooting
- [Advanced usage](docs/advanced.md): remote leaves, profiles, quick launches, tunnels, external fronts
- [Reference](docs/reference.md): commands, configuration, files, endpoints, limits
- [Security](docs/security.md): trust boundaries, credentials, exposure, hardening

The same pages are published at <https://testd.dev/docs/>. The product site lives at <https://testd.dev>.

## Install

From source:

```sh
cargo install --path .
```

Public releases provide CLI archives, tray bundles, `SHA256SUMS`, and generated Homebrew definitions. Verify the checksums before installing. Homebrew templates live in `packaging/homebrew/`; a release generates installable definitions with real digests. The tray app is a separate, public Tauri build. [DEVELOPING.md](DEVELOPING.md) covers building and release validation. There is no in-app updater or commercial-service requirement.

## First name

On the host:

```sh
testd init
testd host
```

`init` is idempotent and runs without prompts when stdin is not a terminal. It creates `~/.config/testd/config.toml`, a local CA, and an operator secret. It does not change the system resolver yet: that privileged step is deferred until the first registration arrives from another machine. For the `.test` TLD on every platform, configure the resolver and install root trust once with:

```sh
testd doctor --fix
```

On Linux, port 443 requires privileges. For a root-managed system service, use `packaging/systemd/testd@.service`, which grants only `CAP_NET_BIND_SERVICE`. For a foreground CLI, run `sudo setcap 'cap_net_bind_service=+ep' "$(readlink -f "$(command -v testd)")"` after installing or replacing the executable. For a tray build, grant it to the actual tray executable, not an AppImage wrapper. Alternatively, set `[host] edge_addr = '127.0.0.1:8443'` and include `:8443` in browser URLs. A systemd user service with `NoNewPrivileges=yes` cannot acquire a file capability: use a high port there.

Then, in the project:

```sh
testd run app.example:3000 -- npm run dev
```

Open `https://app.example.test`. The name is `app.example`; the `.test` TLD is appended by the host. Use `<service>.<project>` so cookies behave as they would on `app.example.com` and `api.example.com`.

A single-label name (`app.test`) works but is cross-site with every other project. `testd` prints a warning when you use one.

The three main commands:

```sh
testd init            # host setup, once
testd host            # run the daemon
testd run :3000       # register the current directory, forever
```

`testd dashboard` prints the local dashboard URL.

`testd run` also wraps a process:

```sh
testd run frontend:3000 api:8080 -- npm run dev
testd run 10.0.0.5:myapp:3000 -- npm run dev   # custom target host
```

## Remote dev environments

Registration and token issuance use plain TCP. Use a trusted network or a separately secured transport, such as an encrypted private network or SSH tunnel. Do not expose port 7737 to the public internet. The HTTPS edge encrypts browser traffic; it does not encrypt leaf registration traffic.

The host intake defaults to loopback. For a remote leaf, configure a reachable `[host] listen_addr` and restrict access; see [Advanced usage](docs/advanced.md#remote-development).

From the VM, container, or WSL instance, run:

```sh
testd run --host 192.168.1.5 :3000
```

With no credential for the selected profile, `testd` asks the host for a grant and names the domains it wants; the token it gets covers those names. On the host, approve it:

```sh
testd requests
testd approve <id>
```

The local dashboard's **Access** card does the same. The tray posts a notification and turns its icon light blue while a request is waiting. The leaf saves the token to `~/.config/testd/credentials/default`, so later runs do not ask again. The host stores issued tokens in `~/.config/testd/tokens.json`; `testd tokens` lists them and `testd tokens --revoke <id>` withdraws one. Revoking a token deletes the leaf's whole grant: its connections close, the names it published are released, and the leaf forgets the dead credential. Run it again to request a new grant. A host reset leaves the same stale credential behind; remove `~/.config/testd/credentials/<profile>` and run again.

A name the token does not cover raises its own request the first time the leaf publishes it. The dashboard's **Access** card shows the requested names, and approving adds that one name to the leaf's grant without touching its other names.

`testd run` accepts `--host`, `--hosts`, and `TESTD_HOSTS` for a one-off list, and reads `[profiles.<name>]` from `~/.config/testd/leaf.toml` for a named one. The host infers the proxy target from the client's connection IP and the port you passed. A remote leaf may only target its own address by default; set `[host] allow_remote_targets = true` to permit an explicit different host.

For unattended clients that cannot wait for an approval, `testd init` also writes an operator secret into `[host] secret`. Present it as `TESTD_TOKEN` on the leaf:

```sh
export TESTD_TOKEN=<the secret>
```

That secret admits registrations directly. Issued tokens are the per-leaf path that can be listed and revoked without changing the bootstrap secret.

## Dashboard

The daemon serves its dashboard on the loopback listener, at `http://127.0.0.1:7737/`, and at `https://testd.test/` through the edge. Both are local surfaces: the edge forwards the dashboard name only for clients on this machine, and the listener refuses every non-loopback peer. There is no login and no URL token; the loopback peer is the authority. Every `POST` carries `X-Testd-Request: 1`, so a cross-site page cannot mutate state.

It lists live names with two actions, active shares with a stop button, access requests with approve and deny buttons, issued tokens with a revoke button, the **Quick launches** table, and the certificate actions. The page keeps a token-authenticated event stream open, so name, share, launch, access, and token changes appear without a reload. On a name, **stop** ends the leaf but keeps its grants, so the next run publishes the names again; **delete** (after a confirmation) deletes the grant for that one name, so the leaf stops publishing it and must ask for a grant next time. A name published with the operator secret or by a local quick launch has no issued grant to delete, so it offers only **stop**; a quick launch is deleted from its own card. `/api/status` is the machine-readable form of the names and shares:

```sh
curl http://127.0.0.1:7737/api/status
```

Fetch the root from either dashboard URL:

```sh
curl http://127.0.0.1:7737/ca.crt
```

The tray enables launch at login once, on its first start, and has a **Launch at login** checkbox from then on. Unticking it is final until you tick it again, even if the login item is removed outside the tray. The first start opens a setup dialog served on an ephemeral loopback port, covering the DNS resolver, the root certificate, and the operator secret; it generates a pronounceable secret into an editable field, where an existing one can replace it. The dialog talks to the daemon over HTTP rather than IPC, and closes into the dashboard once the daemon starts.

## Sharing a name

Names are reachable only from the host and the devices that trust its root. To reach one from a phone, a webhook, or a colleague, share it through a tunnel:

```sh
testd share app.example                       # cloudflared, public
testd share app.example --provider tailscale  # tailnet only
testd share --list                            # name, URL, exposure, provider
testd share --stop app.example
```

The daemon owns the tunnel, not the CLI process, so closing the terminal does not close the share. The lifetime is the registration's: when the name goes, the tunnel goes, and `testd share` says so instead of leaving a stale URL behind.

| Provider | Exposure | Target | Notes |
|---|---|---|---|
| `cloudflared` | public internet | anything the host reaches | quick tunnel; no account needed |
| `ngrok` | public internet | anything the host reaches | needs `ngrok config add-authtoken` once |
| `tailscale` | your tailnet | anything the host reaches | `tailscale serve` points at the plain edge listener, which answers the tailnet name |

`tailscale serve` cannot proxy a container or LAN address directly, so `testd` points it at the host's plain edge listener instead and registers the tailnet name as an alias there. The edge then proxies to the real target, and the app sees the name it was registered under, exactly as a browser request would. This needs the plain HTTP routing listener; it works with the built-in TLS edge on or off.

`serve --bg` keeps its config across restarts while the alias does not, so a host that stopped mid-share would leave the tailnet URL answering 404. On start, `testd` clears any serve entry whose root handler points at its own edge and leaves every other serve entry alone.

Providers are spawned, never linked: no SDK, no account integration, no vendor API in the product. `testd` sets `TESTD_TUNNEL_PROVIDER` for a default other than `cloudflared`, and `TESTD_TUNNEL` to point at a provider binary outside `PATH`.

The dashboard has a **Shares** card: provider URL, the registered name, the exposure, and a stop button. Shares are listed separately from active names because they are provider URLs, not testd names; stopping one leaves the name in place. The tray does the same from the menu. One provider terminating TLS means the share is as private as that provider makes it: a public share is a public route to the app, and a tailnet share is only as closed as the tailnet.

## Quick launches

The local dashboard's **Quick launches** section starts a command and owns its names for the process lifetime. A name with no target detects the child's listening port; an explicit `host:port` overrides detection. Each name moves through `configured -> probing -> confirmed`, and the name is registered only after the target accepts. Stop stops the process group; quitting the app stops every launch. Definitions live in `~/.config/testd/launches.json`; running claims are not persisted. The tray lists saved launches with start and stop actions.

## Diagnosis

```sh
testd doctor          # human-readable checks
testd doctor --json   # stable exit codes and machine-readable output
testd doctor --fix    # resolver, CA trust, and Caddyfile repair
testd url testd://fix/resolver   # run a scheme action; forwards to the running daemon
```

Exit codes: `0` ready, `1` configuration or missing state, `2` resolver, `3` HTTPS edge or trust.

The daemon re-checks the resolver route every 10 seconds and root trust every 60 seconds, with immediate checks after repairs. On a desktop session, a missing prerequisite or a failed repair is posted as a notification; activating the notification runs the repair. Without a notification service the same notices are logged as `[notice]`.

## Certificates

The local dashboard's **Certificate** section shows the root certificate's trust state, SHA-256 fingerprint, and expiry, and installs or removes system trust. Trust can only be changed from the local page; `testd.test/ca.crt` serves the same root the loopback page does.

The local intermediate renews near expiry on startup or certificate minting without changing root trust. The previous intermediate certificate and key are retained under `pki/backups/`. If `root.key` was moved offline, restore it before the intermediate expires; `testd doctor` reports expiry and `testd doctor --fix` repairs it when the key is available.

## Uninstall

Stop the daemon first, then remove the OS resolver route and the trusted root:

```sh
testd uninstall
```

`testd uninstall --purge` also deletes `~/.config/testd`, including the PKI and local state, after system cleanup succeeds. Pass `--keep-resolver` or `--keep-certificate` to leave either system change in place. If the local root certificate is missing, testd skips trust removal and reports incomplete cleanup. On Linux, resolver and trust cleanup leave unowned or changed state in place.

Removing the tray app with the OS uninstaller does not remove the certificate or DNS route; run `testd uninstall` first.

## URL actions

Notifications and OS URL-scheme launches share one action grammar:

```
testd://fix/resolver
testd://fix/certificate
```

The tray app registers `testd` on Windows and Linux at startup in release builds, and through its bundle on macOS. `testd url <url>` forwards the action to a running daemon; if the daemon is gone it performs the repair itself, so a stale notification still works. Dev builds skip registration unless `TESTD_REGISTER_SCHEME=1` is set.

## Configuration

`~/.config/testd/config.toml`; on Windows, `%APPDATA%\testd\config.toml`.

Useful `[host]` keys:

| Key | Default | Meaning |
|---|---|---|
| `listen_addr` | `127.0.0.1:7737` | Dev-environment intake |
| `edge_addr` | `127.0.0.1:443` | HTTPS edge; use a high port if the binary lacks `CAP_NET_BIND_SERVICE` |
| `allow_remote_targets` | `false` | Permit a remote leaf to name a target other than its own address |
| `trust_forwarded_for` | `false` | Trust `X-Forwarded-For` from a configured front proxy; the dashboard name needs it on the plain listener |

Client state lives in `~/.config/testd/leaf.toml`. It contains node profiles, never credentials:

```toml
default_profile = "home"

[profiles.home]
hosts = ["192.168.1.5:7737", "192.168.1.6:7737"]
```

Credentials live in `~/.config/testd/credentials/<profile>`, mode `0600`, or in `TESTD_TOKEN` for a one-off run. Precedence for nodes is CLI/env, then the selected client profile, then the node's own loopback listener. The token profile is chosen by `--token-profile` or `TESTD_TOKEN_PROFILE`, then `token_profile` in the project's `.testd.toml`, then `default`. `TESTD_TOKEN` overrides the credential file; without it, the leaf uses `credentials/<profile>` or, on the node and only over loopback, the operator secret. When no credential is found for the profile, the leaf requests one from the host instead of failing.

Issued tokens live on the node in `~/.config/testd/tokens.json`, mode `0600`, and cover only the names the operator approved. The file holds the token secrets and their labels; neither `testd tokens` nor the dashboard prints a secret.

On the node itself no credential file is needed: when the `default` profile has no credential and every target is a loopback endpoint, leaf actions (`testd run`, `testd deregister`) use `[host] secret` from the host config. A named profile or a non-loopback target asks for a token instead, so the operator secret is never sent to another machine.

The managed Caddyfile is optional. `testd export-caddyfile` writes one and prints the import line for users who want to provide their own front end; the built-in edge does not need it.

