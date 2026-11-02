#!/usr/bin/env bash
# Probe the macOS /etc/resolver configure/unconfigure path.
#
# The script snapshots the current resolver file, runs `doctor --fix`, checks
# resolution through the OS resolver and the DNS server directly, removes the
# route with `uninstall --keep-certificate`, checks again, then restores the
# original file. Evidence is kept under a persisted directory.
#
# It changes only /etc/resolver/<tld>. It also lets `doctor --fix` touch the
# root trust and Caddyfile import, so run it on a machine where that is allowed.
# `uninstall --keep-certificate` leaves root trust in place.
#
# Usage:
#   tests/release/macos-resolver-probe.sh [--bin PATH] [--tld TLD]
#       [--dns-port PORT] [--backup-root DIR]
#
# Run as the operator, not through sudo. The script calls sudo itself.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
CONFIG="$HOME/.config/testd/config.toml"
BIN="$ROOT/target/release/testd"
TLD=''
DNS_ADDR=127.0.0.1
DNS_PORT=7753
BACKUP_ROOT="$HOME/Library/Application Support/testd/resolver-probes"
HOST_READY=0
RESTORED=0
dir_existed=0
file_existed=0
file_mode=644
file_owner=root
file_group=wheel

usage() {
	sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

fail() {
	printf 'error: %s\n' "$*" >&2
	exit 2
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--bin) BIN=${2:?missing --bin value}; shift 2 ;;
		--tld) TLD=${2:?missing --tld value}; shift 2 ;;
		--dns-port) DNS_PORT=${2:?missing --dns-port value}; shift 2 ;;
		--backup-root) BACKUP_ROOT=${2:?missing --backup-root value}; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) fail "unknown argument: $1" ;;
	esac
done

[ "$(uname -s)" = 'Darwin' ] || fail 'this probe only runs on macOS'
[ "$(id -u)" -ne 0 ] || fail 'run this as the operator, without sudo'
[ -x "$BIN" ] || fail "testd binary not executable: $BIN"
[ -f "$CONFIG" ] || fail "missing host config: $CONFIG (run testd init first)"
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'

case "$DNS_PORT" in
	''|*[!0-9]*) fail "invalid DNS port: $DNS_PORT" ;;
esac

config_values=$(python3 - "$CONFIG" <<'PY'
import sys
import tomllib

with open(sys.argv[1], 'rb') as source:
	host = tomllib.load(source)['host']
print(host['tld'])
print(host.get('resolver', 'dns'))
PY
)
config_tld=$(printf '%s\n' "$config_values" | sed -n '1p')
config_backend=$(printf '%s\n' "$config_values" | sed -n '2p')
[ -n "$config_tld" ] || fail "no [host] tld in $CONFIG"
[ "$config_backend" = 'dns' ] || fail "this probe needs resolver = \"dns\"; config uses $config_backend"
if [ -n "$TLD" ] && [ "$TLD" != "$config_tld" ]; then
	fail "--tld $TLD does not match the configured host TLD $config_tld"
fi
TLD="$config_tld"
[ "$TLD" != 'localhost' ] || fail '.localhost needs no resolver route; use --tld localhost only in the browser suite'

case "$TLD" in
	''|*/*|*[!A-Za-z0-9.-]*) fail "unsafe TLD: $TLD" ;;
esac

resolver="/etc/resolver/$TLD"
domain="testd.$TLD"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup="$BACKUP_ROOT/$stamp"
mkdir -p "$backup"
chmod 700 "$backup"

log_command() {
	printf '$'
	printf ' %q' "$@"
	printf '\n'
	"$@" 2>&1 || printf '(exit %s)\n' "$?"
}

flush_dns() {
	sudo dscacheutil -flushcache >/dev/null 2>&1 || true
	sudo killall -HUP mDNSResponder >/dev/null 2>&1 || true
}

snapshot() {
	local label=$1
	local directory="$backup/$label"
	mkdir -p "$directory"
	{
		printf '# captured %s\n' "$(date -u +%Y%m%dT%H%M%SZ)"
		printf '\n## resolver file: %s\n' "$resolver"
		if sudo test -f "$resolver"; then
			sudo cat "$resolver"
			sudo stat -f 'mode=%Lp owner=%Su group=%Sg' "$resolver"
		else
			printf '(absent)\n'
		fi
		printf '\n## /etc/resolver\n'
		sudo ls -la /etc/resolver 2>&1 || true
		printf '\n## scutil --dns\n'
		scutil --dns 2>&1 || true
		printf '\n## dscacheutil\n'
		log_command dscacheutil -q host -a name "$domain"
		printf '\n## getaddrinfo\n'
		log_command python3 -c \
			'import socket, sys; print(socket.getaddrinfo(sys.argv[1], 443, type=socket.SOCK_STREAM))' "$domain"
		printf '\n## direct DNS query\n'
		if command -v dig >/dev/null 2>&1; then
			log_command dig "@$DNS_ADDR" -p "$DNS_PORT" "$domain" A +time=2 +tries=1
		else
			printf 'dig is not installed\n'
		fi
		printf '\n## testd doctor\n'
		log_command "$BIN" doctor --json
	} >"$directory/snapshot.txt" 2>&1
}

resolves_to_host() {
	python3 -c '
import socket, sys
try:
	addresses = {item[4][0] for item in socket.getaddrinfo(sys.argv[1], 443, type=socket.SOCK_STREAM)}
except OSError:
	sys.exit(1)
sys.exit(0 if sys.argv[2] in addresses else 1)
' "$domain" "$DNS_ADDR" >/dev/null 2>&1
}

does_not_resolve_to_host() {
	python3 -c '
import socket, sys
try:
	addresses = {item[4][0] for item in socket.getaddrinfo(sys.argv[1], 443, type=socket.SOCK_STREAM)}
except OSError:
	sys.exit(0)
sys.exit(0 if sys.argv[2] not in addresses else 1)
' "$domain" "$DNS_ADDR" >/dev/null 2>&1
}

wait_for() {
	local predicate=$1
	local seconds=$2
	local attempt
	for attempt in $(seq 1 "$seconds"); do
		if "$predicate"; then
			printf '%s after %s second(s)\n' "$predicate" "$attempt"
			return 0
		fi
		sleep 1
	done
	printf '%s did not happen within %s seconds\n' "$predicate" "$seconds"
	return 1
}

route_present() {
	sudo test -f "$resolver" \
		&& sudo grep -Fxq "nameserver $DNS_ADDR" "$resolver" \
		&& sudo grep -Fxq "port $DNS_PORT" "$resolver"
}

restore() {
	if [ "$RESTORED" -eq 1 ]; then
		return 0
	fi
	RESTORED=1
	local status=0
	set +e
	printf '\nRestoring %s from %s\n' "$resolver" "$backup"
	flush_dns
	if [ "$file_existed" -eq 1 ]; then
		sudo mkdir -p /etc/resolver
		sudo cp "$backup/resolver-before" "$resolver" || status=1
		sudo chmod "$file_mode" "$resolver" || status=1
		sudo chown "$file_owner:$file_group" "$resolver" || status=1
	else
		sudo rm -f "$resolver" || status=1
	fi
	if [ "$dir_existed" -eq 0 ] && sudo test -d /etc/resolver \
		&& [ -z "$(sudo ls -A /etc/resolver)" ]; then
		sudo rmdir /etc/resolver || status=1
	fi
	flush_dns
	if [ "$file_existed" -eq 1 ]; then
		sudo cmp -s "$backup/resolver-before" "$resolver" || status=1
	else
		sudo test ! -e "$resolver" || status=1
	fi
	if [ "$status" -ne 0 ]; then
		printf 'error: the original resolver state was not restored; evidence: %s\n' "$backup" >&2
	fi
	set -e
	return "$status"
}

cleanup() {
	local status=$?
	trap - EXIT INT TERM
	if ! restore; then
		status=1
	fi
	exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Report: %s\n' "$backup"
printf 'Binary: %s\n' "$BIN"
printf 'Route:  %s -> %s:%s\n' "$resolver" "$DNS_ADDR" "$DNS_PORT"
sudo -v

if sudo test -d /etc/resolver; then
	dir_existed=1
fi
if sudo test -f "$resolver"; then
	file_existed=1
	sudo cat "$resolver" >"$backup/resolver-before"
	file_mode=$(sudo stat -f '%Lp' "$resolver")
	file_owner=$(sudo stat -f '%Su' "$resolver")
	file_group=$(sudo stat -f '%Sg' "$resolver")
fi
snapshot before

if command -v dig >/dev/null 2>&1 \
	&& dig "@$DNS_ADDR" -p "$DNS_PORT" "$domain" A +time=1 +tries=1 >/dev/null 2>&1; then
	HOST_READY=1
else
	printf 'warning: no DNS answer from %s:%s; start `testd host` to test OS resolution\n' "$DNS_ADDR" "$DNS_PORT" >&2
fi

printf '\n== configure ==\n'
log_command "$BIN" doctor --fix >"$backup/configure.log" 2>&1 || true
configure_code=0
grep -q '"exit_code": 0' "$backup/configure.log" || configure_code=1
if route_present; then configure_file=pass; else configure_file=fail; fi
if [ "$HOST_READY" -eq 1 ]; then
	if wait_for resolves_to_host 10; then configure_resolution=pass; else configure_resolution=fail; fi
else
	configure_resolution=skip
fi
snapshot after-configure

printf '\n== unconfigure ==\n'
log_command "$BIN" uninstall --keep-certificate >"$backup/unconfigure.log" 2>&1 || true
if sudo test -e "$resolver"; then unconfigure_file=fail; else unconfigure_file=pass; fi
if [ "$HOST_READY" -eq 1 ]; then
	if wait_for does_not_resolve_to_host 10; then unconfigure_resolution=pass; else unconfigure_resolution=fail; fi
else
	unconfigure_resolution=skip
fi
snapshot after-unconfigure

if restore; then restored=pass; else restored=fail; fi
snapshot restored

printf '\n== probe ==\n'
printf 'configure file:         %s\n' "$configure_file"
printf 'configure resolution:   %s\n' "$configure_resolution"
printf 'configure exit_code 0:  %s\n' "$configure_code"
printf 'unconfigure file:       %s\n' "$unconfigure_file"
printf 'unconfigure resolution: %s\n' "$unconfigure_resolution"
printf 'restored:               %s\n' "$restored"
printf 'evidence:               %s\n' "$backup"

if [ "$configure_file" = pass ] && [ "$unconfigure_file" = pass ] \
	&& [ "$configure_resolution" != fail ] && [ "$unconfigure_resolution" != fail ] \
	&& [ "$restored" = pass ]; then
	exit 0
fi
exit 1
