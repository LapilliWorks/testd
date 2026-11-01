#!/usr/bin/env bash
# Rewrite the sha256 line of a Homebrew formula or cask from a local file or URL.
#
#   scripts/brew-sha256.sh packaging/homebrew/testd-gui.rb Testd_0.1.0_aarch64.dmg
#   scripts/brew-sha256.sh packaging/homebrew/testd.rb https://example/tag.tar.gz
#
# The file must already contain exactly one `sha256` line.

set -euo pipefail

if [ "$#" -ne 2 ]; then
	printf 'usage: %s <formula-or-cask.rb> <artifact-path-or-url>\n' "$0" >&2
	exit 2
fi

file="$1"
artifact="$2"

if [ ! -f "$file" ]; then
	printf 'no such formula or cask: %s\n' "$file" >&2
	exit 2
fi
if ! grep -qE '^[[:space:]]*sha256[[:space:]]' "$file"; then
	printf '%s has no sha256 line; add one where the digest belongs\n' "$file" >&2
	exit 2
fi
if [ "$(grep -cE '^[[:space:]]*sha256[[:space:]]' "$file")" -ne 1 ]; then
	printf '%s has more than one sha256 line; pass a file with a single artifact\n' "$file" >&2
	exit 2
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

case "$artifact" in
	http://*|https://*)
		curl --silent --show-error --fail --location --max-time 600 --output "$tmp" "$artifact"
		source_file="$tmp"
		;;
	*)
		if [ ! -f "$artifact" ]; then
			printf 'no such artifact: %s\n' "$artifact" >&2
			exit 2
		fi
		source_file="$artifact"
		;;
esac

if command -v shasum >/dev/null 2>&1; then
	digest="$(shasum -a 256 "$source_file" | awk '{print $1}')"
else
	digest="$(sha256sum "$source_file" | awk '{print $1}')"
fi

python3 - "$file" "$digest" <<'PY'
import re, sys
path, digest = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as handle:
    text = handle.read()
updated, count = re.subn(r'(?m)^(\s*sha256\s+)"[^"]*"', r'\1"' + digest + '"', text)
if count != 1:
    sys.exit(f"expected one sha256 line in {path}, found {count}")
with open(path, "w", encoding="utf-8") as handle:
    handle.write(updated)
print(f"{path}: sha256 {digest}")
PY
