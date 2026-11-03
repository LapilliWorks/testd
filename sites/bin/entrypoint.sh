#!/bin/sh
# Runs inside the container. Installs the site dependencies into the mounted
# volume when the manifest or lockfile changes, then hands over to the action.
set -eu

action=${1:?usage: entrypoint.sh <dev|build|preview|check|links|shell>}
cd /src

stamp=node_modules/.installed
if [ ! -f "$stamp" ] || [ package.json -nt "$stamp" ] || [ bun.lock -nt "$stamp" ]; then
	echo 'installing site dependencies' >&2
	bun install --frozen-lockfile
	touch "$stamp"
fi

case $action in
dev) exec sh sites/bin/dev-servers.sh ;;
build) exec bun run build ;;
preview) exec bun run preview -- --host 0.0.0.0 ;;
check) exec bun run check ;;
links) exec bun run check:links ;;
shell) exec sh ;;
*)
	echo "unknown action: $action" >&2
	exit 2
	;;
esac
