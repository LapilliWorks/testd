#!/usr/bin/env bash
# Core host checks shared by linux.sh and macos.sh. Source lib.sh first.

check_binary() {
	section 'binary'
	if "$TESTD_BIN" --help >/dev/null; then pass 'testd --help'; else fail 'testd --help'; fi
	if "$TESTD_BIN" --version >/dev/null 2>&1; then pass 'testd --version'; else skip 'testd --version is not exposed'; fi
}

check_init() {
	section 'init'
	if ! HOME="$TEST_HOME" "$TESTD_BIN" init --caddyfile "" --tld "$TLD" </dev/null >"$TEST_HOME/init.log" 2>&1; then
		fail 'init'
		sed -n '1,120p' "$TEST_HOME/init.log" >&2
		summary
	fi
	pass 'init'

	if [ -f "$(config_path)" ]; then
		pass 'init writes config.toml'
	else
		fail 'init writes config.toml'
	fi
	if [ -f "$(pki_path)/root.crt" ]; then
		pass 'init writes the root certificate'
	else
		fail 'init writes the root certificate'
	fi

	local secret
	secret="$(operator_secret)"
	if [ -n "$secret" ]; then pass 'init writes the operator secret'; else fail 'init writes the operator secret'; fi
	if [ "${#secret}" -ge 16 ]; then
		pass 'operator secret is long enough'
	else
		fail "operator secret is too short: ${#secret}"
	fi
	if [ "$(file_mode "$(config_path)")" = '600' ]; then pass 'config is private'; else fail 'config is private'; fi

	# Re-running init must keep the secret other machines already copy.
	if HOME="$TEST_HOME" "$TESTD_BIN" init --caddyfile "" --tld "$TLD" </dev/null >"$TEST_HOME/init-again.log" 2>&1; then
		if [ "$(operator_secret)" = "$secret" ]; then
			pass 're-init keeps the operator secret'
		else
			fail 're-init keeps the operator secret'
		fi
	else
		fail 're-init'
		sed -n '1,120p' "$TEST_HOME/init-again.log" >&2
	fi

	# Keep the daemon off privileged and public ports for the throwaway run.
	config_set edge_addr "\"127.0.0.1:$EDGE_PORT\""
	config_set listen_addr "\"127.0.0.1:7737\""
}

check_token_requests() {
	section 'token requests'
	# The suite stores a leaf token before registering; a client with no
	# credential must ask the host and wait for approval.
	pass 'token requests are covered by the daemon suite'
}

check_daemon() {
	section 'daemon'
	if start_daemon; then pass 'testd host'; else fail 'testd host'; summary; fi
	if wait_for_tcp 127.0.0.1 7737 30; then pass 'client listener 7737'; else fail 'client listener 7737'; fi
	if [ "$(dns_query "testd.$TLD" "$DNS_PORT")" = '127.0.0.1' ]; then
		pass "DNS listener $DNS_PORT"
	else
		fail "DNS listener $DNS_PORT"
	fi
	if wait_for_tcp 127.0.0.1 "$EDGE_PORT" 30; then
		pass "HTTPS listener $EDGE_PORT"
	else
		fail "HTTPS listener $EDGE_PORT"
	fi

	if [ -f "$(control_path)" ]; then pass 'control channel file'; else fail 'control channel file'; fi
	if [ -f "$(control_path)" ] && [ "$(file_mode "$(control_path)")" = '600' ]; then
		pass 'control channel file is private'
	else
		fail 'control channel file is private'
	fi

	# The lock must reject a second daemon before it touches the CA or the ports.
	if HOME="$TEST_HOME" "$TESTD_BIN" host >"$TEST_HOME/second-host.log" 2>&1; then
		fail 'a second daemon is refused'
	elif grep -q 'another testd daemon is already running' "$TEST_HOME/second-host.log"; then
		pass 'a second daemon is refused'
	else
		fail 'a second daemon is refused'
		sed -n '1,60p' "$TEST_HOME/second-host.log" >&2
	fi
}

check_edge() {
	section 'edge'
	# The certificate is minted on demand; the name itself has no registration.
	if [ "$(http_status "testd.$TLD" /ok.svg)" = '404' ]; then
		pass "edge terminates TLS for testd.$TLD"
	else
		fail "edge terminates TLS for testd.$TLD"
	fi
	# The dashboard is loopback-only, not a proxied testd name.
	if http_get "testd.$TLD" / >/dev/null 2>&1; then
		fail 'the dashboard is not served through the edge'
	else
		pass 'the dashboard is not served through the edge'
	fi
	if http_get "testd.$TLD" /api/status >/dev/null 2>&1; then
		fail 'the dashboard is not proxied through the edge'
	else
		pass 'the dashboard is not proxied through the edge'
	fi
}

check_dashboard() {
	section 'local dashboard'
	if dashboard_get / | grep -q 'Active domains'; then
		pass 'loopback dashboard serves the page'
	else
		fail 'loopback dashboard serves the page'
	fi
	if dashboard_get / | grep -q 'Quick launches'; then
		pass 'dashboard shows quick launches'
	else
		fail 'dashboard shows quick launches'
	fi
	if dashboard_get /api/status | python3 -c '
import json, sys
value = json.load(sys.stdin)
assert value["tld"]
assert isinstance(value["domains"], list)
assert isinstance(value["shares"], list)
' 2>/dev/null; then
		pass 'loopback status document'
	else
		fail 'loopback status document'
	fi
	if dashboard_get /ca.crt | grep -q 'BEGIN CERTIFICATE'; then
		pass 'CA download from the dashboard'
	else
		fail 'CA download from the dashboard'
	fi
	if dashboard_get /api/local/launches \
		| python3 -c 'import json, sys; assert isinstance(json.load(sys.stdin), list)' 2>/dev/null; then
		pass 'quick launch endpoint'
	else
		fail 'quick launch endpoint'
	fi
	if dashboard_get /api/local/certificate | python3 -c '
import json, sys
value = json.load(sys.stdin)
assert isinstance(value["trusted"], bool)
assert value["fingerprint_sha256"]
assert value["summary"]
' 2>/dev/null; then
		pass 'certificate status endpoint'
	else
		fail 'certificate status endpoint'
	fi

	# Mutations need the custom header, and the Host header must stay loopback.
	if [ "$(curl --silent --max-time 10 --noproxy '*' -X POST --output /dev/null --write-out '%{http_code}' \
		"http://127.0.0.1:7737/unshare/none" 2>/dev/null || true)" = '403' ]; then
		pass 'dashboard mutations require the request header'
	else
		fail 'dashboard mutations require the request header'
	fi
	if [ "$(curl --silent --max-time 10 --noproxy '*' -H 'Host: example.com' --output /dev/null \
		--write-out '%{http_code}' "http://127.0.0.1:7737/" 2>/dev/null || true)" = '403' ]; then
		pass 'dashboard rejects a non-loopback Host header'
	else
		fail 'dashboard rejects a non-loopback Host header'
	fi
}

check_doctor_state() {
	section 'doctor state checks'
	HOME="$TEST_HOME" "$TESTD_BIN" doctor --json >"$TEST_HOME/doctor-state.json" 2>/dev/null || true
	if python3 - "$TEST_HOME/doctor-state.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
checks = {check['name']: check['ok'] for check in value['checks']}
assert checks.get('secret') is True, checks
assert checks.get('config') is True, checks
PY
	then pass 'doctor reports the operator secret'; else fail 'doctor reports the operator secret'; fi
}

check_dns() {
	section 'DNS'
	if [ "$(dns_query "testd.$TLD" "$DNS_PORT")" = '127.0.0.1' ]; then
		pass "testd.$TLD -> 127.0.0.1"
	else
		fail "testd.$TLD A record"
	fi
}

check_registration() {
	section 'registration'
	if ! ensure_app_server; then fail 'test upstream listener'; return; fi
	pass 'test upstream listener'

	# On the node itself the default loopback profile uses [host] secret; no
	# credential file or TESTD_TOKEN is needed.
	unset TESTD_TOKEN
	HOME="$TEST_HOME" "$TESTD_BIN" run "app.testdproj:$APP_PORT" >"$CLIENT_LOG" 2>&1 &
	CLIENT_PID=$!
	if wait_for_log '\[reg\]' "$CLIENT_LOG" 20; then
		pass 'client registered with the node operator secret'
	else
		fail 'client registered with the node operator secret'
		sed -n '1,80p' "$CLIENT_LOG" >&2
	fi
	if wait_for_proxy "app.testdproj.$TLD" 20; then
		pass 'proxied request'
	else
		fail 'proxied request'
	fi
	if [ "$(dns_query "app.testdproj.$TLD" "$DNS_PORT")" = '127.0.0.1' ]; then
		pass 'registered name in DNS'
	else
		fail 'registered name in DNS'
	fi

	# A named profile with no credential asks for a token. The loopback address
	# alone must not make the node's operator secret available to that profile.
	local access_log="$TEST_HOME/access-request.log"
	HOME="$TEST_HOME" "$TESTD_BIN" deregister app.testdproj --host 127.0.0.1:7737 \
		--token-profile access-test >"$access_log" 2>&1 &
	local access_pid=$!
	if wait_for_log 'requested access' "$access_log" 10; then
		pass 'a leaf with no credential requests a token'
	else
		fail 'a leaf with no credential requests a token'
		sed -n '1,40p' "$access_log" >&2
	fi
	local request_id
	request_id="$(sed -n 's/.*(request \([^)]*\)).*/\1/p' "$access_log" | head -1)"
	if [ -n "$request_id" ] && HOME="$TEST_HOME" "$TESTD_BIN" requests | grep -q "$request_id"; then
		pass 'testd requests lists the waiting request'
	else
		fail 'testd requests lists the waiting request'
	fi
	if [ -n "$request_id" ] && HOME="$TEST_HOME" "$TESTD_BIN" approve "$request_id" >/dev/null 2>&1; then
		pass 'testd approve delivers the token'
	else
		fail 'testd approve delivers the token'
	fi
	for _ in $(seq 1 50); do
		kill -0 "$access_pid" 2>/dev/null || break
		sleep 0.2
	done
	kill "$access_pid" 2>/dev/null || true
	wait "$access_pid" 2>/dev/null || true
	if [ -s "$TEST_HOME/.config/testd/credentials/access-test" ]; then
		pass 'the leaf saves the issued token'
	else
		fail 'the leaf saves the issued token'
	fi
	local token_line token_id
	token_line="$(HOME="$TEST_HOME" "$TESTD_BIN" tokens | head -1)"
	if [ -n "$token_line" ] && [ "$token_line" != 'no issued tokens' ]; then
		pass 'testd tokens lists the issued token'
	else
		fail 'testd tokens lists the issued token'
	fi
	token_id="$(printf '%s\n' "$token_line" | awk '{print $1}')"
	if [ -n "$token_id" ] && HOME="$TEST_HOME" "$TESTD_BIN" tokens --revoke "$token_id" >/dev/null 2>&1; then
		pass 'testd tokens --revoke withdraws the token'
	else
		fail 'testd tokens --revoke withdraws the token'
	fi

	stop_client
	local removed=0
	for _ in $(seq 1 20); do
		if ! http_get "app.testdproj.$TLD" / >/dev/null 2>&1; then removed=1; break; fi
		sleep 1
	done
	if [ "$removed" = '1' ]; then pass 'disconnect removes the name'; else fail 'disconnect removes the name'; fi
}

check_sharing() {
	section 'sharing'
	if ! ensure_app_server; then fail 'share fixture upstream'; return; fi
	unset TESTD_TOKEN
	HOME="$TEST_HOME" "$TESTD_BIN" run "share.testdproj:$APP_PORT" >"$TEST_HOME/share-client.log" 2>&1 &
	CLIENT_PID=$!
	if wait_for_log '\[reg\]' "$TEST_HOME/share-client.log" 20; then
		pass 'share fixture registered'
	else
		fail 'share fixture registered'
		sed -n '1,80p' "$TEST_HOME/share-client.log" >&2
		stop_client
		return
	fi
	if wait_for_proxy "share.testdproj.$TLD" 20; then
		pass 'share fixture reachable'
	else
		fail 'share fixture reachable'
	fi

	if HOME="$TEST_HOME" "$TESTD_BIN" share share.testdproj | grep -q 'https://fake-name.trycloudflare.com'; then
		pass 'share starts in the daemon and reports the URL'
	else
		fail 'share starts in the daemon and reports the URL'
	fi
	if HOME="$TEST_HOME" "$TESTD_BIN" share --list | grep -q 'share.testdproj.*public'; then
		pass 'share --list shows the share and its exposure'
	else
		fail 'share --list shows the share and its exposure'
	fi
	if HOME="$TEST_HOME" "$TESTD_BIN" share share.testdproj >/dev/null 2>"$TEST_HOME/share-again.err"; then
		fail 'a second share of one name is refused'
	else
		pass 'a second share of one name is refused'
	fi
	if dashboard_get /api/status | grep -q 'fake-name.trycloudflare.com'; then
		pass 'the dashboard lists the share'
	else
		fail 'the dashboard lists the share'
	fi
	if dashboard_post /unshare/share.testdproj >/dev/null 2>"$TEST_HOME/unshare.err" \
		&& ! dashboard_get /api/status | grep -q 'fake-name.trycloudflare.com'; then
		pass 'the dashboard stops the share'
	else
		fail 'the dashboard stops the share'
		sed -n '1,20p' "$TEST_HOME/unshare.err" >&2
	fi

	# Start again so the CLI stop path is exercised too.
	HOME="$TEST_HOME" "$TESTD_BIN" share share.testdproj >/dev/null 2>&1 || true
	if HOME="$TEST_HOME" "$TESTD_BIN" share --stop share.testdproj >/dev/null 2>&1 \
		&& ! HOME="$TEST_HOME" "$TESTD_BIN" share --list | grep -q share.testdproj; then
		pass 'share --stop withdraws it'
	else
		fail 'share --stop withdraws it'
	fi
	if HOME="$TEST_HOME" "$TESTD_BIN" share share.testdproj --provider mystery >/dev/null 2>&1; then
		fail 'an unknown provider is refused'
	else
		pass 'an unknown provider is refused'
	fi

	stop_client
	local removed=0
	for _ in $(seq 1 20); do
		if ! http_get "share.testdproj.$TLD" / >/dev/null 2>&1; then removed=1; break; fi
		sleep 1
	done
	if [ "$removed" = '1' ]; then
		pass 'removing the name stops the share'
	else
		fail 'removing the name stops the share'
	fi
	if HOME="$TEST_HOME" "$TESTD_BIN" share share.testdproj >/dev/null 2>"$TEST_HOME/share-gone.err"; then
		fail 'sharing an unregistered name is refused'
	elif grep -q 'not registered' "$TEST_HOME/share-gone.err"; then
		pass 'sharing an unregistered name is refused'
	else
		fail 'sharing an unregistered name is refused'
		sed -n '1,20p' "$TEST_HOME/share-gone.err" >&2
	fi
}

# A saved launch with an explicit target: the daemon starts the command, probes
# the target, registers the name, and stops both on request.
check_quick_launch() {
	section 'quick launches'
	if ! have python3; then
		skip 'python3 is needed to start a quick launch in this check'
		return
	fi

	local body id saved
	body="$(cat <<EOF
{
	"label": "host check",
	"program": "python3",
	"args": ["-m", "http.server", "$LAUNCH_PORT", "--bind", "127.0.0.1"],
	"entries": [{"domain": "launch.testdproj", "target": "127.0.0.1:$LAUNCH_PORT"}]
}
EOF
)"
	if ! saved="$(dashboard_post /api/local/launches/save "$body")"; then
		fail 'dashboard saves a quick launch'
		return
	fi
	if ! id="$(printf '%s' "$saved" | python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])')"; then
		fail 'dashboard saves a quick launch'
		return
	fi
	LAUNCH_ID="$id"
	if [ -n "$LAUNCH_ID" ]; then
		pass 'dashboard saves a quick launch'
	else
		fail 'dashboard saves a quick launch'
		return
	fi
	if [ -f "$(launches_path)" ]; then pass 'launch definitions are stored'; else fail 'launch definitions are stored'; fi

	if ! dashboard_post /api/local/launches/start "{\"id\":\"$id\"}" >/dev/null; then
		fail 'quick launch starts'
		return
	fi
	local started=0
	for _ in $(seq 1 30); do
		if dashboard_get /api/local/launches | python3 -c '
import json, sys
launch = next((item for item in json.load(sys.stdin) if item["id"] == sys.argv[1]), None)
assert launch and launch["running"]
assert any(state["state"] == "confirmed" for state in launch["states"])
' "$id" 2>/dev/null; then
			started=1
			break
		fi
		sleep 1
	done
	if [ "$started" = '1' ]; then
		pass 'quick launch reaches confirmed'
	else
		fail 'quick launch reaches confirmed'
	fi
	if wait_for_proxy "launch.testdproj.$TLD" 20; then
		pass 'quick launch name is proxied'
	else
		fail 'quick launch name is proxied'
	fi
	if [ "$(dns_query "launch.testdproj.$TLD" "$DNS_PORT")" = '127.0.0.1' ]; then
		pass 'quick launch name is in DNS'
	else
		fail 'quick launch name is in DNS'
	fi

	if ! dashboard_post /api/local/launches/stop "{\"id\":\"$id\"}" >/dev/null; then
		fail 'quick launch stops'
		return
	fi
	local stopped=0
	for _ in $(seq 1 20); do
		if ! http_get "launch.testdproj.$TLD" / >/dev/null 2>&1; then stopped=1; break; fi
		sleep 1
	done
	if [ "$stopped" = '1' ]; then
		pass 'stopping a launch removes the name'
	else
		fail 'stopping a launch removes the name'
	fi

	if dashboard_post /api/local/launches/delete "{\"id\":\"$id\"}" >/dev/null \
		&& ! dashboard_get /api/local/launches | grep -q "$id"; then
		pass 'dashboard deletes a quick launch'
	else
		fail 'dashboard deletes a quick launch'
	fi
	LAUNCH_ID=""
}

check_url_actions() {
	section 'url actions'
	if HOME="$TEST_HOME" "$TESTD_BIN" url testd://fix/unknown >"$TEST_HOME/url-unknown.log" 2>&1; then
		fail 'an unknown testd:// action is refused'
	elif grep -q 'unknown testd action' "$TEST_HOME/url-unknown.log"; then
		pass 'an unknown testd:// action is refused'
	else
		fail 'an unknown testd:// action is refused'
		sed -n '1,40p' "$TEST_HOME/url-unknown.log" >&2
	fi
}

check_hosts_helper() {
	section 'hosts helper'
	local script='scripts/testd-hosts-helper'
	if sh -n "$script"; then pass 'helper syntax'; else fail 'helper syntax'; fi

	local hosts="$TEST_HOME/hosts"
	cp /etc/hosts "$hosts"
	if printf '"app.testdproj.%s"\n' "$TLD" | sh "$script" --tld "$TLD" --hosts-path "$hosts" >/dev/null 2>&1 \
		&& grep -q "127.0.0.1 app.testdproj.$TLD" "$hosts" \
		&& grep -q "127.0.0.1 testd.$TLD" "$hosts"; then
		pass 'helper writes the managed block'
	else
		fail 'helper writes the managed block'
	fi
	if printf '"bad..name.%s"\n' "$TLD" | sh "$script" --tld "$TLD" --hosts-path "$hosts" >/dev/null 2>&1; then
		fail 'helper rejects invalid names'
	else
		pass 'helper rejects invalid names'
	fi
	if printf '"app.testdproj.%s"\n' "$TLD" | sh "$script" --tld "$TLD" --hosts-path "$hosts" >/dev/null 2>&1 \
		&& : | sh "$script" --tld "$TLD" --hosts-path "$hosts" >/dev/null 2>&1 \
		&& ! grep -q "app.testdproj.$TLD" "$hosts" \
		&& grep -q "testd.$TLD" "$hosts"; then
		pass 'empty input leaves only the dashboard name'
	else
		fail 'empty input leaves only the dashboard name'
	fi
}

check_launch_at_login() {
	section 'launch at login'
	local artifact
	artifact="$(autostart_path)"
	if [ -f "$artifact" ]; then
		if grep -qE '^(Exec=|ProgramArguments|<string>)' "$artifact"; then
			pass "launch-at-login entry ($artifact)"
		else
			fail "launch-at-login entry has no program: $artifact"
		fi
	else
		skip "launch at login not configured yet (start the tray once): $artifact"
	fi
}
