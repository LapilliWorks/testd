#!/bin/sh
# Runs the stock Vite and VitePress dev servers inside the site container.
set -eu

if [ "${TESTD_IN_CONTAINER:-}" != 1 ]; then
	echo 'dev-servers: run through sites/bin/site.sh dev' >&2
	exit 1
fi

cd /src
export TESTD_DOCS_PORT=${TESTD_DOCS_PORT:-5174}

# Run the stock CLI entrypoints with Bun; the official image does not ship Node.
bun node_modules/vitepress/bin/vitepress.js dev sites/docs &
docs_pid=$!

cleanup() {
	kill "$docs_pid" 2>/dev/null || true
	wait "$docs_pid" 2>/dev/null || true
}
trap cleanup EXIT

bun node_modules/vite/bin/vite.js sites/product
