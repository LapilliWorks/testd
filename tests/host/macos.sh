#!/usr/bin/env bash
# macOS host checks: resolver, trust, edge, DNS, registration, sharing, launchd.
#
# Run on the target Mac, not in the dev container:
#   cargo build --release -p testd
#   tests/host/macos.sh
#
# Resolver and trust checks are blocked until macOS integration proves ownership.

set -euo pipefail
if [ "${TESTD_HOST_TEST_SYSTEM:-0}" = '1' ]; then
	printf '%s\n' 'macOS system checks are blocked until resolver and trust ownership is enforced' >&2
	exit 2
fi
cd "$(dirname "$0")/../.."
source tests/host/lib.sh
source tests/host/common.sh
require_bin

check_binary
check_init
check_daemon
check_edge
check_dashboard
check_doctor_state
check_dns
check_registration
check_sharing
check_quick_launch
check_url_actions

section 'resolver and trust'
skip 'system checks blocked until macOS resolver and trust ownership is enforced'

section 'launchd'
if plutil -lint packaging/launchd/dev.testd.host.plist >/dev/null 2>&1; then
	pass 'plist verifies'
else
	fail 'plist verifies'
fi

check_launch_at_login

section 'cleanup'
printf 'config:      %s\n' "$TEST_HOME"

stop_daemon
summary
