#!/usr/bin/env bash
# generate-sbom.sh — run by action.yml's "Generate SBOM" step.
# Reads INPUT_* env vars (set by the composite action), calls Syft, optionally
# gates on missing license metadata and on a license allow/deny policy, and
# writes step outputs to $GITHUB_OUTPUT.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SYFT_BIN="${SYFT_BIN:-syft}"

artifact="${INPUT_ARTIFACT:-.}"
source_type="${INPUT_SOURCE_TYPE:-dir}"
raw_format="${INPUT_FORMAT:-cyclonedx-json}"
fail_on_missing="${INPUT_FAIL_ON_MISSING_LICENSE:-false}"
license_allow="${INPUT_LICENSE_ALLOW:-}"
license_deny="${INPUT_LICENSE_DENY:-}"
license_exceptions="${INPUT_LICENSE_EXCEPTIONS:-}"
allow_unknown="${INPUT_ALLOW_UNKNOWN_LICENSE:-false}"
fail_on_mismatch="${INPUT_FAIL_ON_LICENSE_MISMATCH:-false}"
today="${SBOM_TODAY:-$(date -u +%F)}"

fmt="$(sbom_normalize_format "$raw_format")"
src="$(sbom_source_ref "$source_type" "$artifact")"
policy=false
if sbom_policy_active "$license_allow" "$license_deny"; then
  policy=true
  # Validate the waiver list before spending time on a scan.
  sbom_parse_exceptions "$license_exceptions" > /dev/null
fi

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

# Produce a syft-json view we can introspect, reusing the primary file when possible.
probe=""
if sbom_is_true "$fail_on_missing" || [ "$policy" = true ]; then
  probe="$output"
  if [ "$fmt" != "syft-json" ]; then
    probe="$(mktemp)"
    "$SYFT_BIN" scan "$src" -o "syft-json=${probe}"
  fi
fi

missing=0
if sbom_is_true "$fail_on_missing"; then
  missing="$(sbom_count_missing_licenses "$probe")"
  if [ "$missing" -gt 0 ]; then
    echo "sbom-action: ${missing} component(s) missing license metadata:" >&2
    sbom_list_missing_licenses "$probe" | sed 's/^/  - /' >&2
    exit 1
  fi
  echo "sbom-action: all components carry license metadata"
fi

violations=0
mismatches=0
report=""
if [ "$policy" = true ]; then
  report="${output}.license-report.json"
  sbom_license_report "$probe" "$license_allow" "$license_deny" \
    "$license_exceptions" "$today" "$allow_unknown" > "$report"
  violations="$(jq '.violations' "$report")"
  mismatches="$(jq '.mismatches' "$report")"

  jq -r '.expiredExceptions[] | "::warning::sbom-action: license exception for \(.name)\(if .version != "" then "@" + .version else "" end) expired on \(.until)"' "$report"
  jq -r '.unusedExceptions[] | "::notice::sbom-action: license exception for \(.name)\(if .version != "" then "@" + .version else "" end) matches no component"' "$report"
  jq -r '.packages[] | select(.status == "excepted") | "sbom-action: waived \(.name)@\(.version) until \(.exception.until)\(if .exception.reason != "" then " (" + .exception.reason + ")" else "" end)"' "$report"

  if [ "$mismatches" -gt 0 ]; then
    level=warning
    sbom_is_true "$fail_on_mismatch" && level=error
    echo "::${level}::sbom-action: ${mismatches} component(s) have a declared license that differs from the concluded one"
    sbom_list_license_mismatches "$report" | sed 's/^/  - /'
  fi
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "sbom-path=${output}"
    echo "format=${fmt}"
    echo "missing-license-count=${missing}"
    echo "license-violation-count=${violations}"
    echo "license-mismatch-count=${mismatches}"
    echo "license-report-path=${report}"
  } >> "$GITHUB_OUTPUT"
fi

if [ "$policy" = true ]; then
  if [ "$violations" -gt 0 ]; then
    echo "sbom-action: ${violations} component(s) violate the license policy:" >&2
    sbom_list_policy_violations "$report" | sed 's/^/  - /' >&2
    exit 1
  fi
  if [ "$mismatches" -gt 0 ] && sbom_is_true "$fail_on_mismatch"; then
    echo "sbom-action: failing on license mismatch (fail-on-license-mismatch: true)" >&2
    exit 1
  fi
  echo "sbom-action: all components pass the license policy"
fi

echo "sbom-action: wrote ${output}"
