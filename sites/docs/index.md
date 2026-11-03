---
title: Documentation
description: 'Everything for running testd: quickstart, daily usage, advanced setups, reference, and the security model.'
---

# testd documentation

testd gives a project running in a container, VM, WSL distro, or remote box a stable HTTPS name on the machine with the browser. The host owns the naming authority, the local CA, and the reverse proxy; the dev environment only registers a name over one TCP connection.

Start with the [quickstart](quickstart.md) if you have not run a name yet.

## Start here

<div class="doc-grid">
	<a class="doc-card" href="./quickstart.html">
		<span class="doc-card__index">01</span>
		<strong>Quickstart</strong>
		<span>Install, prepare the host, start the daemon, and open the first name.</span>
	</a>
	<a class="doc-card" href="./usage.html">
		<span class="doc-card__index">02</span>
		<strong>Daily usage</strong>
		<span>Names, targets, lifetimes, the dashboard, sharing, access requests, and troubleshooting.</span>
	</a>
	<a class="doc-card" href="./advanced.html">
		<span class="doc-card__index">03</span>
		<strong>Advanced usage</strong>
		<span>Remote leaves, profiles, grants, quick launches, tunnels, external fronts, and PKI.</span>
	</a>
	<a class="doc-card" href="./reference.html">
		<span class="doc-card__index">04</span>
		<strong>Reference</strong>
		<span>Commands, options, configuration keys, files, endpoints, limits, and platform notes.</span>
	</a>
	<a class="doc-card" href="./security.html">
		<span class="doc-card__index">05</span>
		<strong>Security</strong>
		<span>Trust boundaries, credentials, exposure, hardening, and the incident checklist.</span>
	</a>
	<a class="doc-card" href="./dependency-policy.html">
		<span class="doc-card__index">06</span>
		<strong>Dependency policy</strong>
		<span>The advisory exceptions and MSRV constraints that the dependency gate accepts.</span>
	</a>
</div>

## The model in one paragraph

The host is the authority. It runs DNS for `.test`, terminates TLS with a local CA, stores the operator secret and issued tokens, and proxies each live name to the dev environment. A leaf keeps one outbound TCP connection open and registers names on it; the connection is the lease, so a crash or lost network releases the name without a cleanup job. A token is durable permission, and its grants are the exact names it may publish.

## Source and releases

The source, changelog, and release archives live at <https://github.com/testd/testd>. The product site is at <https://testd.dev>. testd is ISC licensed and has no account, telemetry, public DNS, or ACME dependency.
