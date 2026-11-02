# Security

testd is a development tool. It gives names and HTTPS to machines you control, and it assumes the host is the trust authority. It is not a production ingress controller, a public DNS service, or a multi-tenant platform.

This page covers the operational security model. Vulnerability reporting is in [SECURITY.md](../SECURITY.md).

## Trust boundaries

| Path | Transport | Trust |
|---|---|---|
| Browser to host edge | TLS, rustls with the ring provider | Browser trusts the testd root or a sharing provider |
| Leaf to host intake | Plain TCP, NDJSON | Bearer credential in the clear; network must be trusted or separately encrypted |
| Host to app target | Plain HTTP/1.1 | The app should not assume the upstream hop is encrypted |
| Dashboard and control channel | Loopback TCP, no TLS | Same-user local access plus a per-run token |

The root CA and intermediate are created by the host. The root key stays on the host and is never copied to a dev environment. Leaf certificates are minted on demand for live names and live 24 hours.

## Secrets

| Secret | Where it lives | Scope |
|---|---|---|
| Operator secret | `[host] secret` in `config.toml` | Any valid name on this host |
| Issued token | `tokens.json` on the host; `credentials/<profile>` on a leaf | The names in its grant; revocable |
| Root CA key | `pki/root.key` | Can sign any certificate under the root |
| Intermediate key | `pki/node.key` | Can issue leaf certificates |
| Control token | `control.json` | Loopback dashboard and control channel for this daemon run |

`config.toml`, `tokens.json`, `credentials/<profile>`, and the private keys are written with user-only permissions on Unix. Treat any copy of them as a credential. A leaked operator secret can register any valid name; a leaked issued token can publish only its granted names.

The operator secret cannot be revoked individually. To rotate it, write a new value into `[host] secret` and restart the daemon. Leaves that were admitted with the old secret must be updated. Issued tokens remain valid.

To withdraw one leaf, revoke its token. To withdraw one name, delete that name's grant. Both close the affected connections and release the live claims.

## Registration network

Leaf registration and token issuance use plain TCP. Tokens, labels, names, and targets are visible to anything on the path. The HTTPS edge encrypts browser traffic; it does not encrypt leaf traffic.

- Use a trusted LAN, a VPN, or another encrypted network.
- Do not expose intake port 7737 to the public internet.
- Prefer a network that preserves the leaf's source address. A source-rewriting tunnel such as an SSH local forward makes a remote leaf appear local, which changes target inference and bypasses the remote-target check.
- Treat a token copied into CI as a production credential for the names it covers.

Issued tokens are scoped and revocable. The operator secret is broad and survives token changes. Use issued tokens wherever approval is possible, and reserve the secret for unattended bootstrap.

`TESTD_TOKEN` is visible to the same user's process inspection on most systems. Prefer the credential file when that exposure matters. Do not put either in a command line, a repository, or a log.

## Remote targets

By default, a leaf that connects from a non-loopback address may only target its own address. This prevents an issued name from becoming a proxy into the host's loopback services or another network.

```toml
[host]
allow_remote_targets = true
```

Enable it only for leaves you would already trust with that reach. Once enabled, a granted name can point at any target the host can reach, including services that are not otherwise exposed.

## The local dashboard

The dashboard is served on loopback and checks that the `Host` header is `localhost`, `127.0.0.1`, or `[::1]`. That check blocks DNS-rebinding pages from becoming local admin clients.

A bare URL is read-only. Mutations and every `/api/local/*` path need the per-run token from `control.json`; a `POST` also needs `X-Testd-Request: 1`, which a cross-site form cannot set. The token is delivered in the URL fragment, so it is not sent in the HTTP request. It remains in browser history while the page is open; do not paste the authenticated URL into screenshots, issue trackers, or chat.

The dashboard has no TLS and no user login. It refuses non-loopback peers and enforces a loopback `Host` header. Do not port-forward it or put it behind a reverse proxy. The edge does not proxy it.

## Certificates and trust

The testd root is a local certificate authority. Anything that trusts it accepts certificates signed by its key. Protect `pki/root.key` accordingly:

- Keep the config directory private to the host user.
- Do not copy the root key to dev machines or containers.
- If the root key is exposed, rebuild the PKI, reinstall trust on every browser machine, and restart the host.
- If the root key is moved offline, restore it before the intermediate expires; the intermediate renews with it.

Installing the root on a browser machine is a real trust change. Remove it with `testd uninstall` when the machine no longer uses testd. Removing the desktop app does not remove the root or the resolver route.

Firefox may use its own trust store and need a separate import. That is a browser configuration step, not an additional testd authority.

## Tunnels and exposure

A share is an explicit exposure decision.

- `cloudflared` and `ngrok` create public URLs. The provider terminates TLS and forwards traffic to the app. Anyone with the URL can reach the app; the tunnel adds no authentication.
- `tailscale serve` exposes the name to the tailnet. Its privacy depends on tailnet membership and ACLs.
- The provider sees the application traffic in both cases, including credentials the app sends.

Stop a share when it is no longer needed. A share lives only as long as its registration, but a running dev server and a forgotten URL can outlive the reason for sharing.

The provider binary is spawned from `PATH` or `TESTD_TUNNEL`. A compromised binary runs with the daemon's privileges and can read the host state.

## External front and forwarded headers

`trust_forwarded_for` must stay off unless a front you control sets `X-Forwarded-For` and strips any client-supplied value. With the setting on and the edge reachable directly, a client can spoof its source address. `X-Forwarded-Proto` is set by the edge itself.

An external front that terminates TLS has its own trust anchor and certificate lifecycle. The testd root is not involved unless the front proxies to the testd TLS edge.

## Hosts resolver

The hosts backend edits a managed block in the system hosts file through a helper invoked with `sudo`. `testd setup-hosts-helper` installs the helper and a `NOPASSWD` rule scoped to that helper for the invoking user, then validates the rule with `visudo -c`.

- Keep the helper path root-owned and not writable by unprivileged users.
- Review the sudoers drop-in before relying on it.
- The helper is not supported on Windows; use the DNS backend there.

The DNS backend does not need root at runtime and listens on loopback only. It is the safer default.

## Resource limits

The daemon bounds work so a buggy or hostile local client cannot exhaust it without effort:

- 256 simultaneous intake connections
- 64 KiB NDJSON frames
- 512 edge connections total, 64 per source address
- 32 pending access requests, each with a two-minute lifetime
- 1024 cached edge certificates
- 32 KiB HTTP request heads and 256 KiB bodies

These are robustness limits, not authentication. Network exposure still needs a network control such as a firewall, a VPN, or a private tailnet.

## Desktop integration

The tray app registers the `testd://` scheme in release builds. The scheme accepts `fix/resolver` and `fix/certificate`; `testd url` forwards them to the running daemon or performs the repair directly. There is no general command channel over the scheme.

The loopback control channel accepts typed commands authenticated by the per-run token in `control.json`: repairs, share start and stop, request decisions, and token revocation. It is not reachable off the machine. The token has no name scope, is accepted only by the daemon that wrote it, and does not appear in the token store.

The root-managed systemd unit grants only `CAP_NET_BIND_SERVICE` and keeps `NoNewPrivileges=yes`. The user unit cannot acquire a file capability, so it must use a high edge port. Keep that separation rather than running the daemon as root.

## Incident checklist

1. Stop sharing names and stop the affected leaves.
2. Revoke issued tokens with `testd tokens --revoke <id>`.
3. If the operator secret leaked, replace it and restart the daemon.
4. If the root or intermediate key leaked, rebuild the PKI, reinstall trust everywhere, and restart.
5. Remove any exposure at the firewall, tunnel, or tailnet layer.
6. Check `~/.config/testd/tokens.json` and the dashboard Access card for unexpected grants.
7. When the host is retired, run `testd uninstall` and remove the config directory.

## What testd does not do

- No telemetry, usage data, or name reporting
- No public DNS or ACME dependency
- No vendor SDK for tunnels; providers are spawned processes
- No remote administration API
- No guarantee of isolation between projects that share a host or a token profile
- No name that outlives its leaf connection or target; a sleeping laptop or stopped server takes its names with it
