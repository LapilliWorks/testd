---
title: Quickstart
description: 'From a clean machine to a working HTTPS name: install, first host, first registration.'
---

# Quickstart

This is the shortest path from a clean machine to a working HTTPS name. It assumes the host is the machine with the browser; the project can run on the same machine or on a remote dev box.

```text
browser
  │ DNS: app.example.test → the host
  ▼
host machine
  ├─ DNS for *.test
  ├─ HTTPS edge on :443
  └─ reverse proxy → app target
                         ▲
                         │ plain TCP control connection
leaf (VM, container, WSL, remote box)
  └─ testd run, bearer token
```

The browser never connects to the leaf. It resolves the name to the host, the host terminates TLS, and the host proxies to the target. The leaf keeps one outbound TCP connection open and registers names on it; the connection is the lifetime of those names.

## 1. Install

From the repository:

```sh
cargo install --path .
```

Release archives and generated Homebrew formulas are also published. Verify `SHA256SUMS` before installing. The tray app is a separate Tauri build. See [DEVELOPING.md](https://github.com/LapilliWorks/testd/blob/master/DEVELOPING.md#release) for building and packaging.

## 2. Prepare the host

```sh
testd init
testd doctor --fix
```

`init` is idempotent. It:

1. Writes `~/.config/testd/config.toml` with mode `0600`.
2. Creates a local root CA and host intermediate under `~/.config/testd/pki/`.
3. Writes the operator secret to `[host] secret`.
4. Detects an external Caddy install and offers to import the managed Caddyfile.
5. Installs the root certificate into the system trust store when stdin is a terminal or `--yes` is passed.

It leaves the OS resolver alone by default, until the first registration from another machine. Run `testd doctor --fix` now to configure the `.test` resolver and root trust immediately. These steps need administrator privileges.

## 3. Start the host

```sh
testd host
```

The daemon owns the listeners:

| Listener | Default | Purpose |
|---|---|---|
| TCP | `0.0.0.0:7737` | Leaf intake; the dashboard answers on `127.0.0.1:7737` |
| TCP | `0.0.0.0:443` | HTTPS edge for registered names, when `edge_enabled` is true |
| TCP | `127.0.0.1:7740` | Plain HTTP routing for an external front |
| UDP | `127.0.0.1:7753` | DNS for `.test` on Linux and macOS |
| UDP | `127.0.0.1:53` | DNS for `.test` on Windows |

A second daemon fails fast on the instance lock. `testd dashboard` prints the authenticated dashboard URL.

On Linux, binding port 443 needs `CAP_NET_BIND_SERVICE`. Use the root-managed `packaging/systemd/testd@.service`, grant the capability to the executable yourself, or set a high edge port and include it in browser URLs. See [Advanced usage](advanced.md#privileged-ports).

## 4. Register a name

In the project directory:

```sh
testd run app.example:3000
```

Other forms:

```sh
testd run :3000                              # name inferred from the directory
testd run app.example:3000 -- npm run dev    # name lives as long as the process
testd run frontend:3000 api:8080 -- npm run dev
```

Open `https://app.example.test`. The name is given without the TLD; the host appends `.test`. Keep the command running: Ctrl+C, a child exit, or a lost connection removes the name.

Use `<service>.<project>` names such as `app.example`, not single-label names such as `app`. The two-label form gives cookies the same scope they would have on `app.example.com` and `api.example.com`. `testd` warns when it sees a single-label name.

## 5. Check the result

```sh
testd doctor
```

Exit code `0` means ready. `1` means missing configuration or state, `2` means the resolver is not configured, and `3` means the edge or certificate trust is not ready. `testd doctor --json` is stable for scripts. `testd doctor --fix` repairs the resolver, Caddyfile import, and root trust.

## Remote project in one minute

On the other machine, point at the host:

```sh
testd run --host <host-lan-ip> :3000
```

With no credential for the profile, the leaf asks for access. On the host, approve it:

```sh
testd requests
testd approve <id>
```

The token is saved on the leaf and reused. The app must listen on an address the host can reach; a server bound only to `127.0.0.1` on the remote machine is not reachable from the host.

Registration traffic is plain TCP and carries a bearer token. Use a trusted network or an encrypted private network, and do not expose port 7737 to the internet. See [Security](security.md).

## Where next

- [Daily usage](usage.md): names, dashboard, sharing, access requests, troubleshooting
- [Advanced usage](advanced.md): remote leaves, profiles, quick launches, tunnels, external fronts, system service
- [Reference](reference.md): commands, options, configuration, files, endpoints, limits
- [Security](security.md): trust boundaries, credentials, exposure, and hardening
