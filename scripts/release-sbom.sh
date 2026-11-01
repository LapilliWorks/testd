#!/bin/sh
# Produce CycloneDX SBOMs for every crate in the workspace.
set -eu
cd "$(dirname "$0")/.."
cargo cyclonedx --format json --describe crate "$@"
echo "wrote sbom-*.cdx.json"
