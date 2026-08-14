#!/usr/bin/env bats
# Unit tests for scripts/lib.sh — no Syft required.

setup() {
  DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
  source "$DIR/scripts/lib.sh"
  FIX="$DIR/tests/fixtures"
}

@test "normalize_format: friendly cyclonedx maps to cyclonedx-json" {
  run sbom_normalize_format cyclonedx
  [ "$status" -eq 0 ]
  [ "$output" = "cyclonedx-json" ]
}

@test "normalize_format: spdx maps to spdx-json and is case-insensitive" {
  run sbom_normalize_format SPDX
  [ "$status" -eq 0 ]
  [ "$output" = "spdx-json" ]
}

@test "normalize_format: passthrough of canonical names" {
  run sbom_normalize_format spdx-tag-value
  [ "$output" = "spdx-tag-value" ]
  run sbom_normalize_format syft-json
  [ "$output" = "syft-json" ]
}

@test "normalize_format: unknown format fails" {
  run sbom_normalize_format nonsense
  [ "$status" -ne 0 ]
}

@test "format_extension: json/xml/spdx/txt" {
  run sbom_format_extension cyclonedx-json
  [ "$output" = "json" ]
  run sbom_format_extension cyclonedx-xml
  [ "$output" = "xml" ]
  run sbom_format_extension spdx-tag-value
  [ "$output" = "spdx" ]
  run sbom_format_extension table
  [ "$output" = "txt" ]
}

@test "default_output derives filename from format" {
  run sbom_default_output spdx-json
  [ "$output" = "sbom.json" ]
  run sbom_default_output cyclonedx-xml
  [ "$output" = "sbom.xml" ]
}

@test "source_ref builds dir/file/registry/docker schemes" {
  run sbom_source_ref dir ./dist
  [ "$output" = "dir:./dist" ]
  run sbom_source_ref file ./app.jar
  [ "$output" = "file:./app.jar" ]
  run sbom_source_ref image ghcr.io/moveeeax/app:1.0
  [ "$output" = "registry:ghcr.io/moveeeax/app:1.0" ]
  run sbom_source_ref docker localimage:latest
  [ "$output" = "docker:localimage:latest" ]
}

@test "source_ref rejects unknown source type" {
  run sbom_source_ref satellite ./x
  [ "$status" -ne 0 ]
}

@test "is_true recognizes truthy values only" {
  run sbom_is_true true;  [ "$status" -eq 0 ]
  run sbom_is_true YES;   [ "$status" -eq 0 ]
  run sbom_is_true 1;     [ "$status" -eq 0 ]
  run sbom_is_true false; [ "$status" -ne 0 ]
  run sbom_is_true "";    [ "$status" -ne 0 ]
}

@test "count_missing_licenses counts components without licenses" {
  run sbom_count_missing_licenses "$FIX/syft-with-missing-licenses.json"
  [ "$status" -eq 0 ]
  [ "$output" -eq 2 ]
}

@test "count_missing_licenses is zero when all licensed" {
  run sbom_count_missing_licenses "$FIX/syft-all-licensed.json"
  [ "$output" -eq 0 ]
}

@test "list_missing_licenses names the offenders" {
  run sbom_list_missing_licenses "$FIX/syft-with-missing-licenses.json"
  [[ "$output" == *"mystery-lib"* ]]
  [[ "$output" == *"vendored-blob"* ]]
  [[ "$output" != *"left-pad"* ]]
}
