---
title: Daily usage
description: 'Names, targets, lifetimes, the dashboard, sharing, access requests, and troubleshooting.'
---

# Daily usage

## Register a name

```sh
testd run app.example:3000
```

The general entry forms are:

| Entry | Meaning |
|---|---|
| `:3000` | Name from the current directory; target the leaf's address and port 3000 |
| `app.example:3000` | Explicit name; target the leaf's address and port 3000 |
| `10.0.0.5:app.example:3000` | Explicit name and target host |
| `app.example.test:3000` | A trailing `.test` is stripped |

One connection can publish several names:

```sh
testd run frontend:3000 api:8080
```

They share one connection, one token, and one grant list.

To tie the registration to a process:

```sh
testd run app.example:3000 -- npm run dev
```

The names appear when the process is running, and go away when it exits or Ctrl+C interrupts it. `testd run` exits with the child's status.

A bare port is completed with the address the leaf connected from. That is `127.0.0.1` on the host and the dev machine's address on a remote leaf. Use an explicit `host:name:port` or `host:port` when the inferred address is wrong.

The app must listen on an address the host can reach. A dev server bound only to `127.0.0.1` on a remote machine is not reachable from the host.

## Names and targets

Names are `<service>.<project>`, without the TLD. The host appends `.test`. The daemon stores and shows the bare name, for example `app.example`; browsers use `app.example.test`.

Use two labels or more. `app.example.test` and `api.example.test` share a registrable domain, so cookies behave like they do on `app.example.com` and `api.example.com`. A single-label `app.test` is cross-site with every other project, and `testd` prints a warning when you use one. The name `testd.test` is reserved for the dashboard, which the edge serves to this machine only.

Labels may contain ASCII letters, digits, and hyphens, and may not start or end with a hyphen. Each label is at most 63 bytes, and the full name at most 253 bytes. Targets are a bare port, `host:port`, `ip:port`, or `[ipv6]:port`; port 0 and malformed names are rejected.

The resolver answers registered names with the host's address, not the app target's. The edge speaks HTTP/1.1 and handles WebSocket upgrades, so HMR connections work. The app receives the original `Host` header plus `X-Forwarded-For` and `X-Forwarded-Proto`. The host-to-app hop is plain HTTP.

## How long a name lives

A registration is a lease on the TCP connection that created it. Stop the command, kill the process, or lose the network, and the host releases that connection's names. The leaf reconnects every few seconds and registers the same names again. Reconnecting needs no new approval as long as the token and its grant still exist.

Operator actions differ:

| Action | Effect |
|---|---|
| Stop | Ends the leaf connection; the token and grants stay; the next run registers the same names immediately |
| Delete | Removes the grant for one name and stops it; the leaf keeps its other names and asks for that name again on the next use |
| Revoke token | Deletes the token, closes every connection using it, and releases all of its names; the leaf forgets the credential |

Stop and Delete are dashboard actions. Revoke is `testd tokens --revoke <id>` or the dashboard's token card.

To remove registrations without stopping a process, use a one-shot command:

```sh
testd deregister app.example api.example
```

This releases the names from the host but leaves the token and grants in place.

To take names owned by another connection, use `--force`:

```sh
testd run --force app.example:3000
```

Use it only when you intend to take over the name. Without it, a duplicate name fails with the owner's connection id.

## The dashboard

```sh
testd dashboard
```

The command prints `http://127.0.0.1:7737/`. The same page is at `https://testd.test/`. There is no user login and no URL token: the loopback listener, and the edge's rule that forwards the dashboard name only for clients on this machine, are the authority. Every mutation also needs the `X-Testd-Request: 1` header, which a cross-site page cannot send.

The dashboard shows:

- Live names, with Stop and, for issued grants, Delete
- Active shares, with a stop button
- Access requests, with approve and deny
- Issued tokens, with a revoke button
- Quick launches, with start, stop, and logs
- Certificate trust state, fingerprint, and expiry, with install and remove actions

It is served only on the loopback listener and checks that the `Host` header is loopback. It is not proxied by the edge. If you open it through a port forward or a reverse proxy under another name, it refuses the request.

Useful machine-readable endpoints:

```sh
curl http://127.0.0.1:7737/api/status
curl http://127.0.0.1:7737/ca.crt -o testd-root.crt
```

`/api/status` lists names, targets, projects, advisories, and shares. `/ca.crt` returns the root certificate for installing trust elsewhere. The edge serves neither.

## Check and repair

```sh
testd doctor
testd doctor --json
testd doctor --fix
```

`doctor` checks configuration, the operator secret, the resolver route, name resolution, optional Caddy wiring, and the edge. When the built-in TLS edge is enabled it also checks PKI validity and root trust; with `edge_enabled = false`, the external front owns TLS trust. The exit codes are stable:

| Code | Meaning |
|---|---|
| `0` | Ready |
| `1` | Missing or invalid configuration or state |
| `2` | Resolver route or name resolution is wrong |
| `3` | Certificate trust, PKI, or the HTTPS edge is not ready |

`--fix` applies privileged repairs: configure the OS resolver, write a missing operator secret, add the Caddyfile import, reload Caddy, and install or reinstall the root.

While the daemon runs, it re-checks the resolver every 10 seconds and root trust every 60 seconds, with an immediate check after a repair. On a desktop session, a failure is posted as a notification whose activation runs the repair. Without a notification service, the same notices are logged as `[notice]`.

## Share a name

Names resolve only on the host. To reach one from a phone, a webhook, or a colleague, use a tunnel:

```sh
testd share app.example
testd share app.example --provider tailscale
testd share --list
testd share --stop app.example
```

| Provider | Exposure | Requires |
|---|---|---|
| `cloudflared` | Public internet | `cloudflared` on `PATH`; no account for a quick tunnel |
| `ngrok` | Public internet | `ngrok` on `PATH`; run `ngrok config add-authtoken` once |
| `tailscale` | Your tailnet | `tailscale` on `PATH`; uses the plain edge listener |

The daemon owns the tunnel, not the CLI process, so closing the terminal does not close the share. A share ends when its owning connection or target changes, including a reconnect to the same target; share it again after reconnecting. Repeating an unchanged registration on the same connection keeps the share. A failed change also keeps it only when the original claim is restored without an intervening successful change. The dashboard's Shares card and the tray menu provide the same controls.

A public share is a public route to the app. A tailnet share is only as private as the tailnet.

## Access requests and tokens

The host intake defaults to loopback. For a remote leaf, configure a reachable `[host] listen_addr` and restrict access; see [Advanced usage](advanced.md#remote-development).

A leaf with no credential for the selected profile asks for access, naming the names it wants:

```sh
testd run --host 192.168.1.5 :3000
```

On the host:

```sh
testd requests
testd approve <id>
testd deny <id>
```

`requests` lists the request id, leaf label, requested names, source address, and age. The label comes from the leaf and carries the project its names cover, for example `user@host:example`. A request waits up to two minutes. A denied or expired request ends that leaf attempt; run it again to ask again. The dashboard's Access card and the tray notification provide the same decisions.

A token covers exact names. If a leaf publishes a name outside its grant, the host queues a request for that one name and keeps the registration waiting. Approving adds the name to the existing token without touching its other names.

List and revoke tokens:

```sh
testd tokens
testd tokens --revoke <id>
```

A token can be used by more than one connection; those connections share its grants. The list shows the token id, label (`user@host:project`), granted names, issue age, and last use. Secrets are never printed. Revoking closes every connection using that token, releases its names, and makes the leaf forget its stored credential. Run the leaf again to request access.

For unattended clients, the operator secret can be presented as `TESTD_TOKEN`:

```sh
export TESTD_TOKEN=<operator secret>
```

This admits registrations without approval and is not individually revocable. Prefer an issued token for CI. See [Advanced usage](advanced.md#credentials-and-profiles).

## Common workflows

| Task | Command or action |
|---|---|
| Run the app on another port | `testd run app.example:4000` |
| Add an API next to the UI | `testd run frontend:3000 api:8080 -- npm run dev` |
| Restart the dev server | Restart the command; the name returns when the process is back |
| Keep a name after a child exits | Run `testd run ...` without `--`, or use a dashboard Quick launch |
| Take over a stale or duplicate name | `testd run --force ...` |
| Temporarily stop a name | Dashboard Stop, then run again |
| Remove one name's access | Dashboard Delete on that name |
| Change the project's cookie domain | Use `<service>.<project>`, not a single label |
| Use a high HTTPS port | Set `[host] edge_addr` and include the port in the URL |

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Browser certificate warning | Root is not trusted; run `testd doctor --fix`. Firefox may need a separate trust import |
| Name does not resolve | Resolver is not configured, or the daemon is not running; run `testd doctor` |
| 404 from the edge | No live claim: the leaf stopped, the name was stopped, or its grant was deleted |
| 502 from the edge | The host cannot reach the target: wrong address, app bound only to loopback, or a firewall |
| Duplicate name | Another connection owns it; use `--force` only for an intentional takeover |
| Authentication failed | Stale credential after a host reset or a revoked token; remove `~/.config/testd/credentials/<profile>` and run again |
| Access request expired | The operator did not approve within two minutes; run the leaf again |
| `port 53 already in use` on Windows | Another service owns the DNS port; stop it, or use Linux or macOS where testd uses 7753 |
| `nothing is serving HTTPS` | Start `testd host`; check `edge_addr`; ports below 1024 need a capability or a privileged launch |
| `no daemon is running` | Start `testd host` or the tray; the dashboard, shares, requests, and tokens live in the daemon |
| Share has no URL | The provider is missing, not authenticated, or failed to report a URL; check the daemon log |

More platform and configuration detail is in the [Reference](reference.md).
