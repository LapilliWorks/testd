#!/bin/sh
# Produce CycloneDX SBOMs for every crate in the workspace.
set -eu
cd "$(dirname "$0")/.."
python3 scripts/release.py require-clean-sbom
cargo cyclonedx --all --format json --describe crate "$@"
python3 scripts/release.py collect-sbom --output dist/sbom
