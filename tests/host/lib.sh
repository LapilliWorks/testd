#!/usr/bin/env bash
# Shared helpers for the host-only checks.
#
# Each script uses a throwaway HOME, TLD, edge port, and app ports so it does not
# collide with a normal testd install. System changes (resolver, trust store) only
# happen through tests/release/run.py, which snapshots the host integration first
# and restores it afterwards; a direct run of this script cannot do that.
#
# Environment:
#   TESTD_BIN                 binary to test (default target/release/testd)
#   TESTD_HOST_TLD            test-only throwaway TLD (default testdcheck)
#   TESTD_HOST_EDGE_PORT      HTTPS edge port (default 8443)
#   TESTD_HOST_APP_PORT       upstream port for registration (default 18080)
#   TESTD_HOST_LAUNCH_PORT    quick-launch upstream port (default 18081)
#   TESTD_HOST_TEST_SYSTEM    allow resolver and trust changes (default 0)
#   TESTD_HOST_SNAPSHOT       snapshot directory from tests/release/run.py --system

set -euo pipefail

# Keep only test-runner controls; never inherit real hosts, credentials, or providers.
for variable in ${!TESTD_@}; do
	case "$variable" in
		TESTD_BIN|TESTD_HOST_TLD|TESTD_HOST_EDGE_PORT|TESTD_HOST_APP_PORT|TESTD_HOST_LAUNCH_PORT|\
		TESTD_HOST_OUTPUT_DIR|TESTD_HOST_TEST_SYSTEM|TESTD_HOST_SNAPSHOT|TESTD_HOST_DISPOSABLE_CONFIRMED) ;;
		*) unset "$variable" ;;
	esac
done

if [ "${TESTD_HOST_TEST_SYSTEM:-0}" = '1' ]; then
	if [ "${TESTD_HOST_DISPOSABLE_CONFIRMED:-0}" != '1' ] || [ ! -t 0 ] || \
		[ ! -f "${TESTD_HOST_SNAPSHOT:-/nonexistent}/manifest.json" ]; then
		printf 'system checks require a confirmed disposable host and snapshot through the release runner\n' >&2
		exit 2
	fi
fi

TLD="${TESTD_HOST_TLD:-testdcheck}"
export TESTD_HOST_TLD="$TLD"
EDGE_PORT="${TESTD_HOST_EDGE_PORT:-8443}"
APP_PORT="${TESTD_HOST_APP_PORT:-18080}"
LAUNCH_PORT="${TESTD_HOST_LAUNCH_PORT:-18081}"
# Platform default from crates/testd-core/src/config.rs; Windows uses 53.
DNS_PORT=7753
TESTD_BIN="${TESTD_BIN:-$(pwd)/target/release/testd}"
HOST_OUTPUT_ROOT="${TESTD_HOST_OUTPUT_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/testd/host-checks}"
mkdir -p "$HOST_OUTPUT_ROOT"
TEST_HOME="$(mktemp -d "$HOST_OUTPUT_ROOT/testd-host-XXXXXX")"
LOG="$TEST_HOME/daemon.log"
FAKE_TUNNEL="$TEST_HOME/fake-tunnel.sh"
APP_LOG="$TEST_HOME/app.log"
CLIENT_LOG="$TEST_HOME/client.log"
DAEMON_PID=""
CLIENT_PID=""
APP_PID=""
LAUNCH_ID=""
PASSED=0
FAILED=0
SKIPPED=0

cleanup() {
	if [ -n "$LAUNCH_ID" ]; then
		dashboard_post /api/local/launches/stop "{\"id\":\"$LAUNCH_ID\"}" >/dev/null 2>&1 || true
	fi
	stop_client
	stop_app
	stop_daemon
}
trap cleanup EXIT

pass() { PASSED=$((PASSED + 1)); printf 'ok    %s\n' "$*"; }
fail() { FAILED=$((FAILED + 1)); printf 'FAIL  %s\n' "$*"; }
skip() { SKIPPED=$((SKIPPED + 1)); printf 'skip  %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

require_bin() {
	if [ ! -x "$TESTD_BIN" ]; then
		printf 'testd binary not found: %s\n' "$TESTD_BIN" >&2
		printf 'build it first: cargo build --release -p testd\n' >&2
		exit 2
	fi
	local newer
	newer="$(find src crates -name '*.rs' -newer "$TESTD_BIN" -print -quit 2>/dev/null || true)"
	if [ -n "$newer" ]; then
		printf 'warning: %s is newer than %s; rebuild with cargo build --release -p testd\n' "$newer" "$TESTD_BIN" >&2
	fi
}

config_path() { printf '%s/.config/testd/config.toml' "$TEST_HOME"; }
pki_path() { printf '%s/.config/testd/pki' "$TEST_HOME"; }
control_path() { printf '%s/.config/testd/control.json' "$TEST_HOME"; }
launches_path() { printf '%s/.config/testd/launches.json' "$TEST_HOME"; }

# Replace or add a [host] key in the generated config.
config_set() {
	local key="$1" value="$2" path
	path="$(config_path)"
	if grep -qE "^${key}[[:space:]]*=" "$path"; then
		awk -v key="$key" -v value="$value" '
			$0 ~ "^" key "[[:space:]]*=" { print key " = " value; next }
			{ print }
		' "$path" > "$path.new" && mv "$path.new" "$path"
	else
		awk -v key="$key" -v value="$value" '
			/^\[host\]/ { print; print key " = " value; next }
			{ print }
		' "$path" > "$path.new" && mv "$path.new" "$path"
	fi
}

file_mode() {
	case "$(uname -s)" in
		Darwin) stat -f '%Lp' "$1" ;;
		*) stat -c '%a' "$1" ;;
	esac
}

wait_for_tcp() {
	local host="$1" port="$2" seconds="${3:-30}"
	for _ in $(seq 1 "$seconds"); do
		if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
			exec 3>&- 3<&-
			return 0
		fi
		sleep 1
	done
	return 1
}

wait_for_log() {
	local pattern="$1" file="$2" seconds="${3:-30}"
	for _ in $(seq 1 "$seconds"); do
		if grep -qE "$pattern" "$file" 2>/dev/null; then return 0; fi
		sleep 1
	done
	return 1
}

wait_for_proxy() {
	local host="$1" seconds="${2:-30}"
	for _ in $(seq 1 "$seconds"); do
		if http_get "$host" / >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	return 1
}

# A fake tunnel provider: prints a quick-tunnel URL and stays up, so the share
# checks do not need cloudflared installed. The daemon reads TESTD_TUNNEL.
create_fake_tunnel() {
	cat >"$FAKE_TUNNEL" <<'SH'
#!/bin/sh
echo 'INF |  https://fake-name.trycloudflare.com  |' >&2
exec sleep 60
SH
	chmod +x "$FAKE_TUNNEL"
}

start_daemon() {
	create_fake_tunnel
	TESTD_TUNNEL="$FAKE_TUNNEL" HOME="$TEST_HOME" "$TESTD_BIN" host >"$LOG" 2>&1 &
	DAEMON_PID=$!
	for _ in $(seq 1 30); do
		if wait_for_tcp 127.0.0.1 7737 1; then return 0; fi
		if ! kill -0 "$DAEMON_PID" 2>/dev/null; then break; fi
	done
	printf 'daemon failed to start:\n' >&2
	sed -n '1,120p' "$LOG" >&2 || true
	return 1
}

stop_daemon() {
	if [ -n "$DAEMON_PID" ]; then
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
		DAEMON_PID=""
	fi
}

stop_client() {
	if [ -n "$CLIENT_PID" ]; then
		kill "$CLIENT_PID" 2>/dev/null || true
		wait "$CLIENT_PID" 2>/dev/null || true
		CLIENT_PID=""
	fi
}

stop_app() {
	if [ -n "$APP_PID" ]; then
		kill "$APP_PID" 2>/dev/null || true
		wait "$APP_PID" 2>/dev/null || true
		APP_PID=""
	fi
}

# Start the upstream HTTP server once for registration and sharing checks.
ensure_app_server() {
	if [ -n "$APP_PID" ] && kill -0 "$APP_PID" 2>/dev/null; then return 0; fi
	python3 tests/host/http-server.py "$APP_PORT" >"$APP_LOG" 2>&1 &
	APP_PID=$!
	if wait_for_tcp 127.0.0.1 "$APP_PORT" 10; then return 0; fi
	printf 'upstream failed to start:\n' >&2
	sed -n '1,40p' "$APP_LOG" >&2 || true
	return 1
}

# Query A records from the built-in DNS server without dig/dnspython.
dns_query() {
	local name="$1" port="$2"
	python3 - "$name" "$port" <<'PY'
import random
import socket
import struct
import sys

name, port = sys.argv[1], int(sys.argv[2])
qid = random.randrange(65536)
query = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
for label in name.strip('.').split('.'):
    query += bytes([len(label)]) + label.encode()
query += b'\x00' + struct.pack('>HH', 1, 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(query, ('127.0.0.1', port))
data, _ = sock.recvfrom(2048)
off = 12
for _ in range(struct.unpack('>H', data[4:6])[0]):
    while data[off] != 0:
        off += data[off] + 1
    off += 5
answers = []
for _ in range(struct.unpack('>H', data[6:8])[0]):
    if data[off] & 0xC0 == 0xC0:
        off += 2
    else:
        while data[off] != 0:
            off += data[off] + 1
        off += 1
    rtype, rclass, ttl, rdlen = struct.unpack('>HHIH', data[off:off + 10])
    off += 10
    rdata = data[off:off + rdlen]
    off += rdlen
    if rtype == 1 and rdlen == 4:
        answers.append(socket.inet_ntoa(rdata))
if not answers:
    sys.exit(1)
print(' '.join(answers))
PY
}

http_get() {
	local host="$1" path="${2:-/}"
	curl --silent --show-error --fail --max-time 10 --noproxy '*' \
		--cacert "$(pki_path)/root.crt" \
		--resolve "$host:$EDGE_PORT:127.0.0.1" \
		"https://$host:$EDGE_PORT$path"
}

# HTTP status from the edge, trusting the throwaway root explicitly.
http_status() {
	local host="$1" path="${2:-/}"
	curl --silent --max-time 10 --noproxy '*' --output /dev/null --write-out '%{http_code}' \
		--cacert "$(pki_path)/root.crt" \
		--resolve "$host:$EDGE_PORT:127.0.0.1" \
		"https://$host:$EDGE_PORT$path" 2>/dev/null || true
}

# HTTP status through the OS trust store, for the system trust check.
system_http_status() {
	local host="$1" path="${2:-/}"
	curl --silent --max-time 10 --noproxy '*' --output /dev/null --write-out '%{http_code}' \
		--resolve "$host:$EDGE_PORT:127.0.0.1" \
		"https://$host:$EDGE_PORT$path" 2>/dev/null || true
}

# --- local dashboard -------------------------------------------------------

# The operator secret `testd init` writes into [host].
operator_secret() {
	awk '
		/^\[host\]/ { in_host = 1; next }
		/^\[/ { in_host = 0 }
		in_host && /^secret[[:space:]]*=/ {
			line = $0
			sub(/^[^=]*=[[:space:]]*"/, "", line)
			sub(/"[[:space:]]*$/, "", line)
			print line
			exit
		}
	' "$(config_path)"
}

dashboard_token() {
	sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$TEST_HOME/.config/testd/control.json" 2>/dev/null || true
}

dashboard_get() {
	local token
	token="$(dashboard_token)"
	curl --silent --show-error --fail --max-time 10 --noproxy '*' \
		-H "X-Testd-Token: $token" "http://127.0.0.1:7737$1"
}

dashboard_post() {
	local path="$1" body="${2:-}" token
	token="$(dashboard_token)"
	if [ -n "$body" ]; then
		curl --silent --show-error --fail --max-time 20 --noproxy '*' \
			-H "X-Testd-Token: $token" -H 'X-Testd-Request: 1' -H 'Content-Type: application/json' \
			-X POST --data "$body" "http://127.0.0.1:7737$path"
	else
		curl --silent --show-error --fail --max-time 20 --noproxy '*' \
			-H "X-Testd-Token: $token" -H 'X-Testd-Request: 1' -X POST "http://127.0.0.1:7737$path"
	fi
}

# Where the tray records launch at login on this platform.
autostart_path() {
	case "$(uname -s)" in
		Darwin) printf '%s/Library/LaunchAgents/dev.testd.host.plist' "$TEST_HOME" ;;
		*) printf '%s/.config/autostart/dev.testd.host.desktop' "$TEST_HOME" ;;
	esac
}

# The system checks query the live daemon: the DNS server answers, `doctor --fix`
# re-reads the route, and the trust check fetches the root certificate.
require_daemon() {
	if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		pass 'daemon running for the system checks'
		return 0
	fi
	printf 'daemon is not running; restarting it for the system checks\n' >&2
	if start_daemon; then
		pass 'daemon restarted for the system checks'
		return 0
	fi
	printf 'the daemon could not be restarted, so the system checks cannot run\n' >&2
	return 1
}

summary() {
	printf '\npassed %d, failed %d, skipped %d\n' "$PASSED" "$FAILED" "$SKIPPED"
	if [ "$FAILED" -ne 0 ]; then exit 1; fi
}
