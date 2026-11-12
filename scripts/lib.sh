#!/usr/bin/env bash
# lib.sh — pure, side-effect-free helpers for sbom-action.
# Every function here is unit-tested in tests/lib.bats. Keep it dependency-light
# (bash + jq only) so the logic can be exercised without Syft installed.

# Map a user-facing --format value to the canonical Syft output name.
# Prints the Syft name on stdout; returns non-zero for an unknown format.
sbom_normalize_format() {
  local fmt="${1:-}"
  case "$(printf '%s' "$fmt" | tr '[:upper:]' '[:lower:]')" in
    cyclonedx-json|cyclonedx|cdx) echo "cyclonedx-json" ;;
    cyclonedx-xml)                echo "cyclonedx-xml" ;;
    spdx-json|spdx)               echo "spdx-json" ;;
    spdx-tag-value|spdx-tag)      echo "spdx-tag-value" ;;
    syft-json|syft)               echo "syft-json" ;;
    table|text)                   echo "table" ;;
    *) echo "sbom-action: unknown format '${fmt}'" >&2; return 1 ;;
  esac
}

# File extension (no dot) for a canonical Syft output name.
sbom_format_extension() {
  case "${1:-}" in
    cyclonedx-json|spdx-json|syft-json) echo "json" ;;
    cyclonedx-xml)                      echo "xml" ;;
    spdx-tag-value)                     echo "spdx" ;;
    table)                              echo "txt" ;;
    *) echo "sbom-action: no extension for '${1:-}'" >&2; return 1 ;;
  esac
}

# Default output filename for a canonical Syft output name.
sbom_default_output() {
  local ext
  ext="$(sbom_format_extension "$1")" || return 1
  echo "sbom.${ext}"
}

# Build the Syft source reference from a source type and artifact path/ref.
# dir -> dir:<path>, file -> file:<path>, image/registry -> registry:<ref>,
# docker -> docker:<ref>. Returns non-zero for an unknown source type.
sbom_source_ref() {
  local kind="${1:-}" artifact="${2:-}"
  case "$(printf '%s' "$kind" | tr '[:upper:]' '[:lower:]')" in
    dir|directory)   echo "dir:${artifact}" ;;
    file)            echo "file:${artifact}" ;;
    image|registry)  echo "registry:${artifact}" ;;
    docker)          echo "docker:${artifact}" ;;
    *) echo "sbom-action: unknown source type '${kind}'" >&2; return 1 ;;
  esac
}

# Truthy test for GitHub Action boolean-ish inputs.
sbom_is_true() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    true|1|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

# Count artifacts in a syft-json document that carry no license metadata.
sbom_count_missing_licenses() {
  jq '[.artifacts[]? | select((.licenses // []) | length == 0)] | length' "${1:?syft-json path required}"
}

# List the names of artifacts with no license metadata, one per line.
sbom_list_missing_licenses() {
  jq -r '.artifacts[]? | select((.licenses // []) | length == 0) | .name' "${1:?syft-json path required}"
}

# --- License policy (allow/deny lists, waivers) ------------------------------
# The evaluation itself lives in scripts/license-policy.jq; see its header for
# the matching rules. These wrappers turn action inputs into jq arguments.

SBOM_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Turn a comma- or newline-separated input into a JSON array of trimmed,
# non-empty entries. Text after '#' on a line is a comment.
sbom_split_list() {
  printf '%s' "${1:-}" | jq -Rsc '
    split("\n") | map(sub("#.*$"; "")) | join(",") | split(",")
    | map(gsub("^\\s+|\\s+$"; "")) | map(select(. != ""))'
}

# Parse license waivers, one per line: `<name>[@<version>] <YYYY-MM-DD> [reason]`.
# The waiver applies through the given date. Blank lines and '#' comments are
# ignored. Prints a JSON array; returns non-zero and names the line on bad input.
sbom_parse_exceptions() {
  printf '%s' "${1:-}" | jq -Rsc '
    split("\n") | map(gsub("^\\s+|\\s+$"; "")) | map(select(. != "" and (startswith("#") | not)))
    | map(. as $line
      | (capture("^(?<name>@?[^@\\s]+)(@(?<version>\\S+))?\\s+(?<until>[0-9]{4}-[0-9]{2}-[0-9]{2})(\\s+(?<reason>.*))?$")
         // error("sbom-action: bad license exception line: \($line)"))
      | (.until | split("-") | map(tonumber)) as [$y, $m, $d]
      | if $m < 1 or $m > 12 or $d < 1 or $d > 31
        then error("sbom-action: bad date in license exception line: \($line)") else . end
      | {name, version: (.version // ""), until, reason: (.reason // "")})'
}

# True when an allow or deny list is configured (i.e. the policy gate runs).
sbom_policy_active() {
  [ "$(sbom_split_list "${1:-}")" != "[]" ] || [ "$(sbom_split_list "${2:-}")" != "[]" ]
}

# Evaluate a syft-json document against a license policy and print the JSON
# report (packages with per-license evidence, counts, expired/unused waivers).
# Args: <syft-json> <allow> <deny> <exceptions> <today YYYY-MM-DD> <allow-unknown>
sbom_license_report() {
  local file="${1:?syft-json path required}" allow deny exceptions unknown=false
  allow="$(sbom_split_list "${2:-}")" || return 1
  deny="$(sbom_split_list "${3:-}")" || return 1
  exceptions="$(sbom_parse_exceptions "${4:-}")" || return 1
  sbom_is_true "${6:-}" && unknown=true
  jq --argjson allow "$allow" --argjson deny "$deny" \
     --argjson exceptions "$exceptions" --arg today "${5:?today required}" \
     --argjson allowUnknown "$unknown" \
     --slurpfile spdx "${SBOM_LIB_DIR}/spdx-licenses.json" \
     -f "${SBOM_LIB_DIR}/license-policy.jq" "$file"
}

# One line per failing package from a report: name@version, then each failing
# license with its type and the file Syft read it from.
sbom_list_policy_violations() {
  jq -r '.packages[] | select(.status == "violation" or .status == "unknown")
    | "\(.name)@\(.version): " + (
        if (.licenses | length) == 0 then "no license metadata"
        else [.licenses[] | select(.pass | not)
               | "\(if .expression == "" then .value else .expression end)"
                 + " [" + ([.terms[] | select(.status != "allowed") | "\(.term)=\(.status)"] | join(", ")) + "]"
                 + (if .type != "" then " (\(.type)" + (if .location != "" then " from \(.location)" else "" end) + ")" else "" end)
             ] | join("; ")
        end)' "${1:?report path required}"
}

# One line per package whose declared and concluded licenses disagree.
sbom_list_license_mismatches() {
  jq -r '.packages[] | select(.mismatch)
    | "\(.name)@\(.version): declared "
      + ([.licenses[] | select(.type == "declared") | .expression] | join(" + "))
      + ", concluded "
      + ([.licenses[] | select(.type == "concluded")
          | .expression + (if .location != "" then " from \(.location)" else "" end)] | join(" + "))' \
    "${1:?report path required}"
}
