#!/usr/bin/env bash
# generate-sbom.sh — run by action.yml's "Generate SBOM" step.
# Reads INPUT_* env vars (set by the composite action), calls Syft, optionally
# gates on missing license metadata, and writes step outputs to $GITHUB_OUTPUT.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SYFT_BIN="${SYFT_BIN:-syft}"

artifact="${INPUT_ARTIFACT:-.}"
source_type="${INPUT_SOURCE_TYPE:-dir}"
raw_format="${INPUT_FORMAT:-cyclonedx-json}"
fail_on_missing="${INPUT_FAIL_ON_MISSING_LICENSE:-false}"

fmt="$(sbom_normalize_format "$raw_format")"
src="$(sbom_source_ref "$source_type" "$artifact")"

output="${INPUT_OUTPUT:-}"
if [ -z "$output" ]; then
  output="$(sbom_default_output "$fmt")"
fi

echo "sbom-action: scanning ${src} -> ${output} (${fmt})"
"$SYFT_BIN" scan "$src" -o "${fmt}=${output}"

if [ ! -s "$output" ]; then
  echo "sbom-action: expected SBOM at ${output} but it is missing or empty" >&2
  exit 1
fi

missing=0
if sbom_is_true "$fail_on_missing"; then
  # Produce a syft-json view we can introspect, reusing the primary file when possible.
  probe="$output"
  if [ "$fmt" != "syft-json" ]; then
    probe="$(mktemp)"
    "$SYFT_BIN" scan "$src" -o "syft-json=${probe}"
  fi
  missing="$(sbom_count_missing_licenses "$probe")"
  if [ "$missing" -gt 0 ]; then
    echo "sbom-action: ${missing} component(s) missing license metadata:" >&2
    sbom_list_missing_licenses "$probe" | sed 's/^/  - /' >&2
    exit 1
  fi
  echo "sbom-action: all components carry license metadata"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "sbom-path=${output}"
    echo "format=${fmt}"
    echo "missing-license-count=${missing}"
  } >> "$GITHUB_OUTPUT"
fi

echo "sbom-action: wrote ${output}"
