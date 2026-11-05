#!/usr/bin/env bash
# Linux host checks: resolver, trust, edge, DNS, registration, sharing, units.
#
# Run on the target host, not in the dev container:
#   cargo build --release -p testd
#   tests/host/linux.sh
#
# Resolver and trust checks need a clean disposable host and a snapshot. They
# only run through the runner, which restores the integration afterwards:
#   sudo -v && python3 tests/release/run.py host --system

set -euo pipefail
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
if [ "${TESTD_HOST_TEST_SYSTEM:-0}" != '1' ] || ! sudo -n true 2>/dev/null; then
	skip 'system changes disabled (set TESTD_HOST_TEST_SYSTEM=1 with passwordless sudo to test resolver and trust)'
elif ! require_daemon; then
	skip 'system checks need a running daemon, and it could not be started'
else
	if HOME="$TEST_HOME" "$TESTD_BIN" doctor --fix --json >"$TEST_HOME/doctor.json" 2>"$TEST_HOME/doctor.log"; then
		pass 'doctor --fix'
	else
		fail 'doctor --fix'
		sed -n '1,120p' "$TEST_HOME/doctor.log" >&2
	fi
	if python3 - "$TEST_HOME/doctor.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
checks = {check['name']: check['ok'] for check in value['checks']}
assert checks.get('resolver') is True, checks
assert checks.get('resolution') is True, checks
assert checks.get('certificate') is True, checks
assert checks.get('edge') is True, checks
PY
	then
		pass 'resolver, name resolution, root trust, and edge'
	else
		fail 'resolver, name resolution, root trust, or edge'
	fi
	if getent hosts "testd.$TLD" >/dev/null 2>&1; then
		pass 'system resolver route'
	else
		fail 'system resolver route'
	fi
	if grep -q '^DNS=' /etc/systemd/resolved.conf.d/90-testd.conf 2>/dev/null; then
		pass 'resolver drop-in'
	else
		fail 'resolver drop-in'
	fi
	if [ "$(system_http_status "testd.$TLD" /ok.svg)" = '404' ]; then
		pass 'system trust store accepts the edge certificate'
	else
		fail 'system trust store accepts the edge certificate'
	fi
	# The URL handler forwards to the running daemon instead of repairing twice.
	if HOME="$TEST_HOME" "$TESTD_BIN" url testd://fix/resolver >/dev/null 2>&1; then
		pass 'testd url forwards the resolver repair'
	else
		fail 'testd url forwards the resolver repair'
	fi
	if HOME="$TEST_HOME" "$TESTD_BIN" url testd://fix/certificate >/dev/null 2>&1; then
		pass 'testd url forwards the certificate repair'
	else
		fail 'testd url forwards the certificate repair'
	fi
fi

section 'systemd unit'
if have systemd-analyze; then
	if systemd-analyze verify packaging/systemd/testd.service 2>/dev/null; then
		pass 'unit verifies'
	else
		fail 'unit verifies'
	fi
else
	skip 'systemd-analyze not installed'
fi

check_launch_at_login

section 'cleanup'
if [ -n "${TESTD_HOST_SNAPSHOT:-}" ]; then
	printf 'integration: restored from %s by tests/release/run.py after this script\n' \
		"$TESTD_HOST_SNAPSHOT"
fi
printf 'config:      %s\n' "$TEST_HOME"

stop_daemon
summary
