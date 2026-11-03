#!/bin/sh
# Entry point for the site. The generator runs in a container, so the host needs
# no Bun, no node_modules and no build cache.
set -eu

usage() {
	echo 'usage: sites/bin/site.sh [--host <addr>] [--port <port>] <dev|build|preview|check|links|shell|clean>' >&2
	exit 2
}

# Flags may sit before or after the action.
action=''
host_arg=''
port_arg=''
while [ $# -gt 0 ]; do
	case $1 in
	--host)
		[ $# -ge 2 ] || usage
		host_arg=$2
		shift 2
		;;
	--host=*)
		host_arg=${1#--host=}
		shift
		;;
	--port)
		[ $# -ge 2 ] || usage
		port_arg=$2
		shift 2
		;;
	--port=*)
		port_arg=${1#--port=}
		shift
		;;
	-*)
		echo "unknown option: $1" >&2
		usage
		;;
	*)
		if [ -z "$action" ]; then
			action=$1
		else
			echo "unexpected argument: $1" >&2
			usage
		fi
		shift
		;;
	esac
done
[ -n "$action" ] || usage
case $action in
dev | build | preview | check | links | shell | clean) ;;
*) usage ;;
esac
if [ -n "$port_arg" ]; then
	case $action in
	dev | preview) ;;
	*)
		echo 'port: only dev and preview publish a port' >&2
		usage
		;;
	esac
	case $port_arg in
	'' | *[!0-9]*)
		echo "invalid port: $port_arg" >&2
		usage
		;;
	esac
	[ "$port_arg" -ge 1 ] && [ "$port_arg" -le 65535 ] || {
		echo "port out of range: $port_arg" >&2
		usage
	}
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

runtime=${TESTD_SITE_RUNTIME:-${CONTAINER_RUNTIME:-}}
if [ -z "$runtime" ]; then
	runtime=$(command -v podman || command -v docker || true)
fi
runtime=${runtime##*/}
[ -n "$runtime" ] || {
	echo 'needs podman or docker: install one, or set TESTD_SITE_RUNTIME' >&2
	exit 1
}
command -v "$runtime" >/dev/null 2>&1 || {
	echo "container runtime not found: $runtime" >&2
	exit 1
}

# A stock Bun image: the container supplies the toolchain, the site sources come
# from the mounted working tree, so the site needs no image of its own.
image=${TESTD_SITE_IMAGE:-oven/bun:1.4.4}
deps=${TESTD_SITE_VOLUME:-testd-site-node-modules}
cache=testd-site-bun-cache
out=testd-site-out
# The container listens on the ports the configs declare; only the host side moves.
dev_container_port=5173
preview_container_port=4173
dev_port=${port_arg:-${TESTD_SITE_PORT:-5173}}
preview_port=${port_arg:-${TESTD_SITE_PREVIEW_PORT:-4173}}
# 0.0.0.0 serves the site to the network, 127.0.0.1 serves it to this host only.
# A typed flag outranks the environment; both outrank the loopback default.
bind_host=${host_arg:-${TESTD_SITE_HOST:-127.0.0.1}}

# Files the container writes into the working tree must belong to the calling
# user. Rootless Podman maps container root to the host user already; Docker
# does not.
export_args=''
case $runtime in
docker) export_args="--user $(id -u):$(id -g)" ;;
esac

# An SELinux host needs the bind mounts relabelled.
dir_label=''
file_label=''
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = Enforcing ]; then
	dir_label=:Z
	file_label=,Z
fi

ensure_image() {
	$runtime image inspect "$image" >/dev/null 2>&1 && return 0
	$runtime pull "$image"
}

# An all-interface publish omits the host address, so the runtime binds every
# address family instead of IPv4 alone.
publish_spec() {
	if [ "$bind_host" = '0.0.0.0' ]; then
		printf '%s:%s' "$1" "$2"
	else
		printf '%s:%s:%s' "$bind_host" "$1" "$2"
	fi
}

run() {
	set -- run --rm
	if [ -t 0 ] && [ -t 1 ]; then set -- "$@" -it; fi
	set -- "$@" \
		--volume "$root/sites:/src/sites$dir_label" \
		--volume "$root/scripts:/src/scripts$dir_label" \
		--volume "$root/package.json:/src/package.json:ro$file_label" \
		--volume "$root/bun.lock:/src/bun.lock:ro$file_label" \
		--volume "$root/tsconfig.json:/src/tsconfig.json:ro$file_label" \
		--volume "$deps:/src/node_modules" \
		--volume "$cache:/bun-cache" \
		--volume "$out:/out" \
		--env HOME=/tmp \
		--env BUN_INSTALL_CACHE_DIR=/bun-cache \
		--env CI=true \
		--env TESTD_IN_CONTAINER=1 \
		--env TESTD_SITE_HOST=0.0.0.0 \
		--env TESTD_DOCS_CACHE_DIR=/tmp/vitepress-cache
	if [ -n "${TESTD_DOCS_PORT:-}" ]; then
		set -- "$@" --env "TESTD_DOCS_PORT=$TESTD_DOCS_PORT"
	fi
	if [ "$action" = build ]; then
		set -- "$@" --env TESTD_SITE_OUT_DIR=/out
	fi
	case $action in
	dev) set -- "$@" --publish "$(publish_spec "$dev_port" "$dev_container_port")" ;;
	preview)
		set -- "$@" --publish "$(publish_spec "$preview_port" "$preview_container_port")"
		set -- "$@" --volume "$root/dist:/src/dist$dir_label"
		;;
	links) set -- "$@" --volume "$root/dist:/src/dist$dir_label" ;;
	esac
	set -- "$@" --workdir /src \
		--entrypoint /src/sites/bin/entrypoint.sh \
		"$image" "$action"
	$runtime "$@"
}

# Copies the build out of its volume so the exported files belong to the host
# user.
export_build() {
	rm -rf "$root/dist"
	mkdir -p "$root/dist"
	# shellcheck disable=SC2086
	$runtime run --rm $export_args \
		--volume "$out:/out" \
		--volume "$root/dist:/dist$dir_label" \
		--entrypoint sh "$image" -c 'cp -a /out/. /dist/'
}

require_dist() {
	[ -d "$root/dist" ] || {
		echo 'no dist: run sites/bin/site.sh build first' >&2
		exit 1
	}
}

report_url() {
	if [ "$bind_host" = '0.0.0.0' ]; then
		echo "serving on port $1 of every interface" >&2
		echo "  local:   http://127.0.0.1:$1/" >&2
		echo "  network: this machine's address, port $1" >&2
	else
		echo "serving http://$bind_host:$1/ (--host 0.0.0.0 or TESTD_SITE_HOST=0.0.0.0 to serve the network)" >&2
	fi
}

clean() {
	# The image is stock, hence shared: only the volumes and the build are ours.
	for volume in "$deps" "$cache" "$out"; do
		$runtime volume rm --force "$volume" >/dev/null 2>&1 || true
	done
	rm -rf "$root/dist"
}

case $action in
dev)
	report_url "$dev_port"
	ensure_image
	run
	;;
preview)
	require_dist
	report_url "$preview_port"
	ensure_image
	run
	;;
build)
	ensure_image
	run
	export_build
	echo "built $root/dist" >&2
	;;
check | shell)
	ensure_image
	run
	;;
links)
	require_dist
	ensure_image
	run
	;;
clean) clean ;;
*) usage ;;
esac
