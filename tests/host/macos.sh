#!/usr/bin/env bash
# macOS host checks: resolver, trust, edge, DNS, registration, sharing, launchd.
#
# Run on the target Mac, not in the dev container:
#   cargo build --release -p testd
#   sudo -v   # optional: resolver and trust checks, with TESTD_HOST_TEST_SYSTEM=1
#   tests/host/macos.sh

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
check_hosts_helper

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
	if dscacheutil -q host -a name "testd.$TLD" | grep -q '127.0.0.1'; then
		pass 'system resolver route'
	else
		fail 'system resolver route'
	fi
	if grep -q '^nameserver 127.0.0.1$' "/etc/resolver/$TLD" 2>/dev/null \
		&& grep -q '^port 7753$' "/etc/resolver/$TLD" 2>/dev/null; then
		pass 'resolver file'
	else
		fail 'resolver file'
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

section 'launchd'
if plutil -lint packaging/launchd/dev.testd.host.plist >/dev/null 2>&1; then
	pass 'plist verifies'
else
	fail 'plist verifies'
fi

check_launch_at_login

section 'cleanup'
printf 'resolver: sudo rm -f /etc/resolver/%s\n' "$TLD"
printf 'trust:    sudo security delete-certificate -c "testd root" /Library/Keychains/System.keychain\n'
printf 'config:   %s\n' "$TEST_HOME"
if [ "${TESTD_HOST_TEST_SYSTEM:-0}" = '1' ] && [ "${TESTD_HOST_TEST_CLEANUP:-0}" = '1' ]; then
	sudo -n rm -f "/etc/resolver/$TLD" 2>/dev/null || true
	sudo -n security delete-certificate -c 'testd root' /Library/Keychains/System.keychain >/dev/null 2>&1 || true
fi

stop_daemon
summary
