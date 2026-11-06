#!/usr/bin/env bash
# The macOS resolver probe is disabled until resolver and trust cleanup can
# prove ownership. It must not uninstall a user's configuration or remove a
# route merely because the route uses the test TLD.

set -euo pipefail

printf '%s\n' 'The macOS resolver probe is blocked: system ownership cannot yet be proven; no state was changed.' >&2
exit 2
