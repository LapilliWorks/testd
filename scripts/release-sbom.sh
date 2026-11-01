#!/bin/sh
# Produce CycloneDX SBOMs for every crate in the workspace.
set -eu
cd "$(dirname "$0")/.."
cargo cyclonedx --all --format json --describe crate "$@"
echo 'wrote crate SBOMs (*.cdx.json)'
