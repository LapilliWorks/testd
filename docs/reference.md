# Reference

## Command line

```text
testd <command> [options]
```

| Command | Purpose |
|---|---|
| `init` | Prepare this machine as a host; idempotent |
| `run` | Register names, optionally wrap a command, deregister on exit |
| `deregister` | Release names without stopping a process |
| `host` | Run the host daemon in the foreground |
| `dashboard` | Print the authenticated local dashboard URL |
| `url` | Handle a `testd://` action |
| `doctor` | Check host setup; optionally repair |
| `share` | Start, stop, or list tunnels for registered names |
| `requests` | List waiting access requests |
| `approve` | Approve one request and issue its token |
| `deny` | Deny one request |
| `tokens` | List issued tokens, or revoke one |
| `export-caddyfile` | Write the managed Caddyfile for an external front |
| `uninstall` | Remove the OS resolver route and trusted root |
| `setup-hosts-helper` | Install the hosts resolver helper and sudoers rule |

Global options: `--help`, `--version`.

### init

```text
testd init [--caddyfile <path>] [-y|--yes] [--resolver-now]
```

| Option | Meaning |
|---|---|
| `--caddyfile <path>` | Global Caddyfile to import; empty string disables the external front. Env: `TESTD_CADDYFILE` |
| `-y`, `--yes` | Accept defaults and allow privileged steps without prompting. Env: `TESTD_YES` |
| `--resolver-now` | Configure the OS resolver now instead of lazily on the first remote client |

Creates `config.toml`, the root CA and intermediate, and the operator secret if missing. Re-running keeps the existing secret and unknown config keys. Without a terminal and without `--yes`, it does not touch files outside the config directory.

### run

```text
testd run <entry>... [--force] [--host <addr>] [--hosts <list>]
                      [--token-profile <name>] [--node-profile <name>]
                      [-- <command>...]
```

Entries are `:port`, `name:port`, or `host:name:port`. A trailing `.test` on a name is stripped. Without a command, the registration is held until Ctrl+C. With a command, the registration follows the child's lifetime, and the exit status is the child's.

| Option | Meaning |
|---|---|
| `--force` | Take names owned by another connection |
| `--host <addr>` | One host endpoint. Env: `TESTD_HOST` |
| `--hosts <list>` | Comma-separated host endpoints. Env: `TESTD_HOSTS` |
| `--token-profile <name>` | Credential profile. Env: `TESTD_TOKEN_PROFILE` |
| `--node-profile <name>` | Node profile from `leaf.toml`. Env: `TESTD_PROFILE` |

`--host` and `--hosts` entries without a port get `:7737`. Addresses from the environment or `leaf.toml` must include a port.

### deregister

```text
testd deregister <domain>... [--host <addr>] [--hosts <list>]
                             [--token-profile <name>] [--node-profile <name>]
```

Connects to the host and releases the named registrations. The token and its grants remain. Accepts the same host and profile options as `run`.

### host

```text
testd host
```

Runs the daemon in the foreground. A second instance fails on the instance lock. Stop it with Ctrl+C or the service manager.

### dashboard

```text
testd dashboard
```

Prints the loopback dashboard URL including the per-run token fragment. Requires a running daemon.

### url

```text
testd url <url>
```

Accepts `testd://fix/resolver` and `testd://fix/certificate`. Forwards to the running daemon when possible, otherwise performs the repair itself. Without a terminal it uses a native authorization dialog.

### doctor

```text
testd doctor [--fix] [--json]
```

| Option | Meaning |
|---|---|
| `--fix` | Configure the resolver, write a missing secret, add the Caddyfile import, reload Caddy, and install or reinstall the root |
| `--json` | Print `{ ok, exit_code, checks[] }` with `name`, `ok`, `detail`, and `fix` per check |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Ready |
| `1` | Configuration or missing state |
| `2` | Resolver or name resolution |
| `3` | PKI, certificate trust, or HTTPS edge |

Other CLI failures exit `1`.

### share

```text
testd share <name> [--provider <name>]
testd share --list
testd share --stop <name>
```

Providers: `cloudflared` (default), `tailscale`, `ngrok`. The daemon owns the tunnel. Requires a running daemon.

| Variable | Meaning |
|---|---|
| `TESTD_TUNNEL_PROVIDER` | Default provider when `--provider` is omitted |
| `TESTD_TUNNEL` | Path to a provider binary outside `PATH` |

### requests, approve, deny, tokens

```text
testd requests
testd approve <id>
testd deny <id>
testd tokens
testd tokens --revoke <id>
```

All require a running daemon. `requests` prints the id, label, requested names, address, and age. Requests expire after two minutes. Token secrets are never printed.

### export-caddyfile

```text
testd export-caddyfile
```

Writes the managed Caddyfile to `[host] caddyfile_path` and prints the `import` line to add to the global Caddyfile.

### uninstall

```text
testd uninstall [--purge] [--keep-resolver] [--keep-certificate]
```

| Option | Meaning |
|---|---|
| `--purge` | Also delete the config directory, PKI, tokens, and local state |
| `--keep-resolver` | Leave the OS resolver route in place |
| `--keep-certificate` | Leave the trusted root in place |

Stop the daemon first. The hosts helper and its sudoers rule are removed whenever they are present. `--purge` proceeds only when system cleanup succeeds.

### setup-hosts-helper

```text
testd setup-hosts-helper [--prefix <path>]
```

Installs `{prefix}/libexec/testd-hosts-helper` and `/etc/sudoers.d/testd-hosts-helper` for the invoking user, then validates the rule. Default prefix: `/usr/local`. Not supported on Windows.

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `TESTD_HOST` | `run`, `deregister`, tray | One host endpoint, `host:port` |
| `TESTD_HOSTS` | `run`, `deregister`, tray | Comma-separated `host:port` endpoints |
| `TESTD_PROFILE` | `run`, `deregister` | Node profile name |
| `TESTD_TOKEN` | `run`, `deregister` | Credential override; skips the credential file |
| `TESTD_TOKEN_PROFILE` | `run`, `deregister` | Token profile name |
| `TESTD_CADDYFILE` | `init` | Global Caddyfile path |
| `TESTD_YES` | `init` | Same as `--yes` |
| `TESTD_TUNNEL_PROVIDER` | `host` | Default tunnel provider |
| `TESTD_TUNNEL` | `host` | Provider binary path |
| `TESTD_REGISTER_SCHEME` | Tray dev builds | Register the `testd://` scheme outside a release build |

## Host configuration

Path: `~/.config/testd/config.toml`; on Windows, `%APPDATA%\testd\config.toml`. Mode `0600`.

| Key | Default | Meaning |
|---|---|---|
| `resolver` | `dns` | `dns` for the built-in server or `hosts` for a managed hosts block |
| `listen_addr` | `0.0.0.0:7737` | Leaf intake |
| `edge_addr` | `0.0.0.0:443` | HTTPS edge |
| `edge_enabled` | `true` | Start the built-in TLS edge and its plain listener |
| `http_addr` | `127.0.0.1:7740` | Plain HTTP routing for an external front |
| `answer_addr` | `127.0.0.1` | A-record address returned for registered names |
| `allow_remote_targets` | `false` | Permit a remote leaf to name a target other than its own address |
| `trust_forwarded_for` | `false` | Trust inbound `X-Forwarded-For` from a configured front |
| `secret` | generated | Operator secret; bootstrap credential |
| `pki_dir` | `~/.config/testd/pki` | Root CA, intermediate, and backups |
| `caddyfile_path` | `~/.config/testd/Caddyfile` | Managed Caddyfile |
| `caddy_config_path` | detected | Global Caddyfile to inspect and reload |
| `hosts_path` | platform hosts file | File edited by the hosts resolver |
| `hosts_helper_path` | `/usr/local/libexec/testd-hosts-helper` | Privileged hosts helper |

The DNS server always binds loopback and answers `testd.test` plus every registered name. It is not a LAN DNS service. From another machine, reach a name through `testd share`, not by pointing its resolver at the host.

The daemon reads the operator secret at startup; restart it after changing the value. Existing issued tokens are unaffected.

## Leaf configuration

Path: `~/.config/testd/leaf.toml`; on Windows, `%APPDATA%\testd\leaf.toml`.

```toml
default_profile = 'home'

[profiles.home]
hosts = ['192.168.1.5:7737', '192.168.1.6:7737']
```

Contains addresses only, never credentials.

Project configuration: the nearest `.testd.toml` found upward from the working directory.

```toml
token_profile = 'myproject'
```

Safe to commit. No secrets.

## Files and permissions

Host, under the config directory:

| Path | Contents | Mode |
|---|---|---|
| `config.toml` | Host settings and operator secret | `0600` |
| `pki/root.crt` | Trust anchor | `0644` |
| `pki/root.key` | Root CA private key | private |
| `pki/node.crt`, `pki/node.key` | Host intermediate | private key private |
| `pki/backups/` | Previous intermediates | private |
| `tokens.json` | Issued tokens and granted names, including secrets | `0600` |
| `control.json` | Per-run loopback control token | user-private |
| `launches.json` | Quick launch definitions | user-private |
| `Caddyfile` | Managed external-front config | plain |

Leaf:

| Path | Contents |
|---|---|
| `leaf.toml` | Node profiles |
| `credentials/<profile>` | Bearer token for that profile, mode `0600` |

The host's token store is the source of truth. A leaf's credential file is a copy, not a second grant database.

## Listeners and ports

| Listener | Default | Config key | Notes |
|---|---|---|---|
| Leaf intake | `0.0.0.0:7737` | `listen_addr` | Plain TCP, bearer token |
| Dashboard | `127.0.0.1:7737` | follows `listen_addr` port | Loopback only |
| HTTPS edge | `0.0.0.0:443` | `edge_addr` | Needs privilege on Linux |
| Plain HTTP routing | `127.0.0.1:7740` | `http_addr` | Part of the edge |
| DNS | `127.0.0.1:7753` | fixed | Linux and macOS |
| DNS | `127.0.0.1:53` | fixed | Windows |

The control channel uses the dashboard address with a per-run token from `control.json`.

## Names, targets, and limits

- The TLD is fixed to `.test`. It is appended by the host; a trailing `.test` in an entry is stripped.
- Names are `<service>.<project>`, stored and displayed without the TLD.
- Labels allow ASCII letters, digits, and hyphens; they may not start or end with a hyphen.
- Maximum label: 63 bytes. Maximum full name: 253 bytes.
- `testd.test` is reserved for the dashboard.
- Targets: bare port, `host:port`, `ip:port`, or `[ipv6]:port`. Maximum 512 bytes. Port 0 is invalid. The `run` entry syntax splits `host:name:port` on colons, so an IPv6 host cannot be used in a `run` entry; use a host name. Quick launches accept a full IPv6 target.
- A bare port is completed with the leaf's connection address.

Operational limits:

| Limit | Value |
|---|---|
| Intake connections | 256 simultaneous |
| NDJSON frame | 64 KiB |
| HTTP request head | 32 KiB |
| HTTP request body | 256 KiB |
| HTTP request timeout | 10 seconds |
| HTTP response write timeout | 5 seconds |
| Edge connections | 512 total, 64 per source address |
| Edge certificate cache | 1024 entries |
| Pending access requests | 32 |
| Access request lifetime | 120 seconds |
| Control request line | 4096 bytes |
| Quick launch log | 500 lines in memory |
| Leaf certificate | 24 hours |
| Intermediate certificate | 1 year |
| Root certificate | 10 years |

There is no telemetry, usage reporting, or name reporting.

## Dashboard and HTTP API

Base URL: `http://127.0.0.1:7737/`. The `Host` header must be `localhost`, `127.0.0.1`, or `[::1]`. Only `GET` and `POST` are accepted.

A bare URL is read-only. Mutations and `/api/local/*` need the per-run token from `control.json`, sent as:

```text
X-Testd-Token: <token>
```

Every `POST` also needs:

```text
X-Testd-Request: 1
```

The token is normally supplied by the dashboard URL fragment (`#token=...`), which the page reads and sends as a header. The fragment is not sent in the HTTP request.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/` | None | Dashboard, read-only without a token |
| `GET` | `/api/status` | None | Names, targets, projects, advisories, shares |
| `GET` | `/ca.crt` | None | Root certificate PEM |
| `GET` | `/ok.svg` | None | Trivial liveness image |
| `GET` | `/api/local/launches` | Token | Quick launch definitions and running state |
| `POST` | `/api/local/launches/save` | Token | Create or update a definition |
| `POST` | `/api/local/launches/delete` | Token | Delete a definition |
| `POST` | `/api/local/launches/start` | Token | Start a definition |
| `POST` | `/api/local/launches/stop` | Token | Stop a running definition |
| `POST` | `/api/local/launches/rebind` | Token | Change one running entry's target |
| `GET` | `/api/local/requests` | Token | Pending access requests |
| `POST` | `/api/local/requests/approve` | Token | Approve a request |
| `POST` | `/api/local/requests/deny` | Token | Deny a request |
| `GET` | `/api/local/tokens` | Token | Issued tokens |
| `POST` | `/api/local/tokens/revoke` | Token | Revoke a token |
| `GET` | `/api/local/certificate` | Token | Trust state, fingerprint, expiry |
| `POST` | `/api/local/certificate/install` | Token | Install system trust |
| `POST` | `/api/local/certificate/remove` | Token | Remove system trust |
| `POST` | `/stop/<name>` | Token | Stop a name's leaf; keep its grant |
| `POST` | `/delete/<name>` | Token | Delete one name's grant and stop it |
| `POST` | `/unshare/<name>` | Token | Stop a name's tunnel |

All `/api/local/*` paths require the token even for `GET`. The dashboard and API are not served by the edge.

## Tunnels

| Provider | Exposure | Start command behavior | URL shape |
|---|---|---|---|
| `cloudflared` | Public | `cloudflared tunnel --no-autoupdate --url http://<target>` | `https://*.trycloudflare.com` |
| `ngrok` | Public | `ngrok http <target>` | `https://*.ngrok-free.app`, `*.ngrok-free.dev`, `*.ngrok.io`, `*.ngrok.app` |
| `tailscale` | Tailnet | `tailscale serve --bg http://<edge plain address>` | `https://*.ts.net` |

A provider has 30 seconds to report its URL. `tailscale` requires the built-in edge and refuses to overwrite existing `serve` configuration on port 443. One share per registered name.

## Platform notes

- Linux: DNS on UDP 7753; port 443 needs `CAP_NET_BIND_SERVICE` or a high `edge_addr`. Use `packaging/systemd/testd@.service` for the capability, or `packaging/systemd/testd.service` with a high port.
- macOS: DNS on UDP 7753; launchd template in `packaging/launchd/`. The root is installed in the system keychain through the setup helper.
- Windows: DNS on UDP 53; config under `%APPDATA%\testd`. NRPT rules route `.test` to the local server. The hosts resolver is not supported. A stale answer may need `ipconfig /flushdns`.
- Firefox: may use its own trust store; import the root separately if Chromium-based browsers and the system store accept it but Firefox does not.
- Caddy: optional. The built-in edge needs no external front.

## Troubleshooting by layer

| Check | Command or observation |
|---|---|
| Configuration present | `testd doctor`; first check is `config` |
| Operator secret set | `doctor` check `secret` |
| Resolver route | `doctor` check `resolver` |
| Name resolves through the OS | `doctor` check `resolution` |
| PKI can issue a leaf | `doctor` check `pki` |
| Root trusted | `doctor` check `certificate` |
| Edge listening and trusted | `doctor` check `edge` |
| Optional Caddy wiring | `doctor` checks `caddy`, `caddyfile`, `reload` |
| Live names and targets | `curl http://127.0.0.1:7737/api/status` |
| Pending requests | `testd requests` |
| Issued tokens | `testd tokens` |
| Shares and URLs | `testd share --list` |
