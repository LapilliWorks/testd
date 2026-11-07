#!/usr/bin/env bash
# Classifies the pushed or proposed change set into the job filters of ci.yml.
#
# Environment:
#   EVENT         github.event_name
#   BASE          base commit sha for the comparison (empty when unavailable)
#   GITHUB_REF    ref being built
#   GITHUB_OUTPUT file that receives the `rust`, `release`, and `site` booleans
set -euo pipefail

# Patterns are bash globs where `*` also matches `/`, so one level covers
# nested paths. Every filter includes `.github/**`: a workflow or action change
# must exercise everything it touches.
#
# Inputs of the compiled binaries: workspace sources, the tray app assets it
# embeds, and the files pulled in with include_str!.
rust=(
	'.github/**'
	'Cargo.toml' 'Cargo.lock' 'rust-toolchain.toml' 'rustfmt.toml' 'deny.toml'
	'src/**' 'crates/**' 'src-tauri/**' 'frontend/**'
	'tests/cli.rs' 'tests/host/**' 'tests/manual/**' 'tests/README.md'
	'README.md' 'config.example.toml' 'scripts/testd-elevated.ps1'
)
release=( '.github/**' 'scripts/**' 'tests/release/**' 'packaging/**' )
site=(
	'.github/**'
	'sites/**' 'docs/**' 'assets/**'
	'scripts/check-links.ts' 'package.json' 'bun.lock' 'tsconfig.json'
)

all_changed() {
	printf 'rust=true\nrelease=true\nsite=true\n' >> "$GITHUB_OUTPUT"
	exit 0
}

matches() {
	local file=$1 glob
	shift
	for glob in "$@"; do
		if [[ $file == $glob ]]; then
			return 0
		fi
	done
	return 1
}

# A release must build from scratch, and a manual run asks for everything.
if [[ $EVENT == workflow_dispatch || $GITHUB_REF == refs/tags/v* ]]; then
	all_changed
fi
# A new branch, a force push, or an unknown base has no comparison point.
if [[ -z $BASE || $BASE =~ ^0+$ ]] || ! git cat-file -e "$BASE^{commit}" 2>/dev/null; then
	all_changed
fi

changed=$(git diff --name-only "$BASE" HEAD)

# macOS ships Bash 3.2, so pass each glob list without namerefs.
filter_changes() {
	local name=$1 filtered=false file
	shift
	while IFS= read -r file; do
		if [[ -n $file ]] && matches "$file" "$@"; then
			filtered=true
			break
		fi
	done <<< "$changed"
	printf '%s=%s\n' "$name" "$filtered" >> "$GITHUB_OUTPUT"
}

filter_changes rust "${rust[@]}"
filter_changes release "${release[@]}"
filter_changes site "${site[@]}"
