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
