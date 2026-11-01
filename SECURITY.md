# Security policy

## Supported versions

The latest minor release of the current major version receives security fixes.
Older majors keep working but do not receive fixes.

## Reporting a vulnerability

Email the maintainer listed on the project page. Do not open a public issue for
a suspected vulnerability. Include:

- affected version and platform
- reproduction steps or a proof of concept
- impact: name spoofing, traffic interception, secret disclosure, local escalation

Expect an acknowledgement within 7 days and a fix or mitigation plan within 30
days. Credit is given unless you ask otherwise.

## Design boundaries

- The daemon never needs root at runtime; privileged setup is limited to the OS
  resolver, the root CA trust store, and `/etc/hosts`.
- The root CA key stays in the host config directory and is never copied to a dev environment.
- Leaf certificates live 24 hours; the local intermediate lives one year.
- Leaf tokens are approved only over the node's loopback dashboard or control channel, stored with mode `0600`, and revocable. A token request never receives the operator secret.
- TLS is rustls with the ring provider. There is no OpenSSL in the dependency tree.
- The product does not send telemetry, usage data, or names anywhere.
