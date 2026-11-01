# Quickstart

This is the shortest path from a clean host to a working name, plus the remote path. It assumes the host is the machine with the browser.

## 1. Install

From the repository:

```sh
cargo install --path .
```

Or install a CLI archive or the generated Homebrew formula from a public release after verifying `SHA256SUMS`. `packaging/homebrew/*.rb.in` are release templates, not directly installable definitions. The public tray app is separate; see [DEVELOPING.md](../DEVELOPING.md#release).

## 2. Initialize the host

```sh
testd init
```

What it does:

1. Writes `~/.config/testd/config.toml` (mode `0600`).
2. Creates a local root CA and intermediate at `~/.config/testd/pki/`.
3. Writes the operator secret used by this machine and by unattended clients that present it as `TESTD_TOKEN`.
4. Leaves the OS resolver alone until a remote client registers. Run `testd doctor --fix` to configure it immediately.
5. Installs the root into the system trust store when stdin is a terminal or `--yes` is passed.

For the default `.test` TLD, run `testd doctor --fix` on every platform to configure the resolver before using a local registration. Otherwise lazy setup does not run until a remote client arrives.

The default TLD is `.test`. For a single-machine setup that needs no resolver change:

```sh
testd init --tld localhost
```

## 3. Start the host daemon

```sh
testd host
```

The daemon owns the TCP intake (`:7737`), the HTTPS edge (`:443`), and the DNS server (`127.0.0.1:7753`, or `:53` on Windows). A second instance fails fast on the instance lock.

On Linux, port 443 needs `CAP_NET_BIND_SERVICE`. The root-managed `testd@.service` grants that capability; a systemd user service must use a high port. For a foreground executable, grant the capability to that executable, or set `[host] edge_addr = '127.0.0.1:8443'` and use `https://app.example.test:8443`. `*.localhost` removes only the DNS setup requirement, not CA trust or privileged-port requirements.

## 4. Register the first name

In the project directory:

```sh
testd run :3000
```

This infers the project name from the directory. Or name it explicitly:

```sh
testd run app.example:3000
```

Open `https://app.example.test`. Keep the command running; Ctrl+C removes the name.

Wrap a dev server so the name appears and disappears with the process:

```sh
testd run app.example:3000 -- npm run dev
```

## 5. Check the host

```sh
testd doctor
```

`0` means ready. Exit `2` means the resolver is not configured; `3` means the certificate is not trusted or the edge is not listening. `--json` is stable for scripts.

## Remote environments

Registration, including bearer tokens, uses plain TCP. Use a trusted local network or a separately secured transport. Do not expose intake port 7737 to the public internet.

On the other machine, register against the host:

```sh
testd run --host <host-lan-ip> :3000
```

With no credential for the profile, the leaf requests a grant and names the domains it wants. On the host, approve it:

```sh
testd requests
testd approve <id>
```

The local dashboard's **Access** card does the same; the tray also posts a notification and turns its icon light blue while a request is waiting. The token is saved on the leaf and reused. The host stores issued tokens in `~/.config/testd/tokens.json`; `testd tokens` lists them and `testd tokens --revoke <id>` withdraws one, closing its connections and deleting all of the leaf's grants; the leaf forgets the dead credential and must request access again. Delete the leaf's `~/.config/testd/credentials/<profile>` file to request a new token after a host reset. A name the token does not cover asks for its own grant when the leaf first publishes it, and the dashboard's Delete removes that one name only.

For an unattended leaf, `[host] secret` is the bootstrap credential. Put it in `TESTD_TOKEN` and skip the approval:

```sh
export TESTD_TOKEN=<the secret>
```

The host answers `*.localhost` or `*.test` locally; other devices reach the name through the host's DNS and edge, so the resolver and the root certificate must be configured there too. `testd doctor` on the host reports both. To make the host's names available to another machine, copy the root from the local dashboard:

```sh
curl http://127.0.0.1:7737/ca.crt -o testd-root.crt
```

## Certificates and removal

The local dashboard's certificate section shows the root certificate's trust state, fingerprint, and expiry, and installs or removes system trust. Command-line users have `testd doctor --fix` for repair.

To remove the system integration, stop the daemon and run:

```sh
testd uninstall
```

This removes the OS resolver route and the trusted root. `--purge` also deletes `~/.config/testd`; `--keep-resolver` and `--keep-certificate` preserve either system change. Removing the app with the OS installer does not remove these, so run `testd uninstall` first.

## Troubleshooting

- **No certificate or browser warning**: run `testd doctor --fix` to install the root certificate. Firefox may need a separate trust import.
- **`port 53 already in use` on Windows**: another service owns the DNS port. Stop it, or use Linux or macOS, where testd uses `:7753`.
- **`nothing is serving HTTPS`**: run `testd host`, or check `edge_addr`; ports below 1024 need `CAP_NET_BIND_SERVICE` or a privileged launch.
- **Name resolves but the proxy returns 502**: the dev server stopped, the target host is wrong, or a firewall blocks the host from reaching the dev environment.
- **Duplicate name**: another connection owns it. Use `testd run --force` only when you intend to take it over.
