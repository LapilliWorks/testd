# Security policy

## Supported versions

The latest minor release of the current major version receives security fixes.
Older majors keep working but do not receive fixes.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/LapilliWorks/testd/security/advisories/new). Do not open a public issue for a suspected vulnerability. Private reporting must be enabled on the public repository before its first release. Include:

- affected version and platform
- reproduction steps or a proof of concept
- impact: name spoofing, traffic interception, secret disclosure, local escalation

Expect an acknowledgement within 7 days and a fix or mitigation plan within 30
days. Credit is given unless you ask otherwise.

## Design boundaries

- The daemon never needs root at runtime; privileged setup is limited to the OS
  resolver, the root CA trust store, and `/etc/hosts`.
- The root CA key stays in the host config directory and is never copied to a dev environment.
- Leaf certificates live 24 hours; the local intermediate lives one year and renews near expiry without replacing the root. Renewal requires the root key and backs up the previous intermediate first.
- Leaf tokens are approved only over the node's loopback dashboard or control channel, stored with mode `0600`, and revocable. A token request never receives the operator secret. Dashboard mutations and `/api/local/*` require the per-run control token from `control.json`; a bare dashboard URL is read-only.
- A remote leaf may only target its own address unless `[host] allow_remote_targets` is enabled. This keeps an issued name grant from becoming a proxy into the host's loopback or another network.
- Browser-facing TLS is rustls with the ring provider. There is no OpenSSL in the dependency tree.
- Leaf registration and token issuance use plain TCP, not TLS. Bearer credentials and registration data are visible to the network between the leaf and host. Use only trusted local networks or a separately secured transport, such as an SSH tunnel or encrypted private network. Do not expose intake port 7737 to the internet.
- Intake accepts at most 256 simultaneous connections. NDJSON frames are limited to 64 KiB, HTTP headers to 32 KiB, setup and started-frame reads to 10 seconds, and reply writes to 5 seconds. Idle authenticated leaves keep their registrations.
- The product does not send telemetry, usage data, or names anywhere.
