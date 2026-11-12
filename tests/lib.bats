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

# --- license policy ---------------------------------------------------------

# Evaluate the policy fixture and print "<name> <status>" per package.
policy_statuses() {
  sbom_license_report "$FIX/syft-license-policy.json" "$@" \
    | jq -r '.packages[] | "\(.name) \(.status)"'
}

@test "split_list accepts commas, newlines and comments" {
  run sbom_split_list $'MIT, Apache-2.0\nBSD-3-Clause # vetted\n\n'
  [ "$status" -eq 0 ]
  [ "$output" = '["MIT","Apache-2.0","BSD-3-Clause"]' ]
  run sbom_split_list ""
  [ "$output" = "[]" ]
}

@test "parse_exceptions reads name, scoped name, version, date and reason" {
  run sbom_parse_exceptions $'# waivers\n@scope/pkg@1.2.3 2026-12-31 legal sign-off\nfoo 2027-01-01\n'
  [ "$status" -eq 0 ]
  [ "$(jq -r '.[0].name' <<<"$output")" = "@scope/pkg" ]
  [ "$(jq -r '.[0].version' <<<"$output")" = "1.2.3" ]
  [ "$(jq -r '.[0].reason' <<<"$output")" = "legal sign-off" ]
  [ "$(jq -r '.[1].version' <<<"$output")" = "" ]
  [ "$(jq -r '.[1].until' <<<"$output")" = "2027-01-01" ]
}

@test "parse_exceptions rejects a line without a valid date" {
  run sbom_parse_exceptions "foo tomorrow"
  [ "$status" -ne 0 ]
  [[ "$output" == *"bad license exception line: foo tomorrow"* ]]
  run sbom_parse_exceptions "foo 2026-13-01"
  [ "$status" -ne 0 ]
}

@test "policy_active only when an allow or deny list is set" {
  run sbom_policy_active "" ""
  [ "$status" -ne 0 ]
  run sbom_policy_active " , " ""
  [ "$status" -ne 0 ]
  run sbom_policy_active "" "AGPL-3.0-only"
  [ "$status" -eq 0 ]
}

@test "allow list: unlisted, unknown and missing licenses fail" {
  run policy_statuses "MIT,Apache-2.0" "" "" 2026-11-12 false
  [ "$status" -eq 0 ]
  [[ "$output" == *"left-pad ok"* ]]
  [[ "$output" == *"copyleft-deep violation"* ]]
  [[ "$output" == *"liar violation"* ]]
  [[ "$output" == *"custom-blob violation"* ]]
  [[ "$output" == *"mystery-lib unknown"* ]]
}

@test "free-text license value is normalized to its SPDX id" {
  run policy_statuses "Apache-2.0" "" "" 2026-11-12 false
  [[ "$output" == *"requests ok"* ]]
}

@test "OR expression passes when one alternative is allowed" {
  run policy_statuses "MIT" "" "" 2026-11-12 false
  [[ "$output" == *"dual-lib ok"* ]]
}

@test "deny only: deprecated id in SBOM and policy both normalize" {
  # Syft reports AGPL-3.0 (deprecated); the policy names it AGPL-3.0 too.
  run policy_statuses "" "AGPL-3.0" "" 2026-11-12 true
  [[ "$output" == *"copyleft-deep violation"* ]]
  [[ "$output" == *"left-pad ok"* ]]
  [[ "$output" == *"liar ok"* ]]
}

@test "deny only: unknown licenses fail unless allow-unknown is set" {
  run policy_statuses "" "AGPL-3.0-only" "" 2026-11-12 false
  [[ "$output" == *"custom-blob violation"* ]]
  [[ "$output" == *"mystery-lib unknown"* ]]
  run policy_statuses "" "AGPL-3.0-only" "" 2026-11-12 true
  [[ "$output" == *"custom-blob ok"* ]]
  [[ "$output" == *"mystery-lib ok"* ]]
}

@test "a LicenseRef named in the allow list passes" {
  run policy_statuses "MIT,Apache-2.0,LicenseRef-Proprietary" "" "" 2026-11-12 false
  [[ "$output" == *"custom-blob ok"* ]]
}

@test "deny wins over allow for the same id" {
  run policy_statuses "MIT,AGPL-3.0-only" "AGPL-3.0-only" "" 2026-11-12 false
  [[ "$output" == *"copyleft-deep violation"* ]]
}

@test "active waiver excuses a package, expired waiver does not" {
  run sbom_license_report "$FIX/syft-license-policy.json" "MIT,Apache-2.0" "" \
    $'liar 2026-11-12 relicense pending\ncustom-blob@2.0.0 2026-11-11\nghost 2027-01-01' 2026-11-12 false
  [ "$status" -eq 0 ]
  [ "$(jq -r '.packages[] | select(.name == "liar") | .status' <<<"$output")" = "excepted" ]
  [ "$(jq -r '.packages[] | select(.name == "custom-blob") | .status' <<<"$output")" = "violation" ]
  [ "$(jq -r '.expiredExceptions[0].name' <<<"$output")" = "custom-blob" ]
  [ "$(jq -r '.unusedExceptions[0].name' <<<"$output")" = "ghost" ]
}

@test "waiver pinned to another version does not apply" {
  run sbom_license_report "$FIX/syft-license-policy.json" "MIT,Apache-2.0" "" \
    "liar@2.0.0 2027-01-01" 2026-11-12 false
  [ "$(jq -r '.packages[] | select(.name == "liar") | .status' <<<"$output")" = "violation" ]
}

@test "declared vs concluded mismatch is flagged with the evidence file" {
  report="$BATS_TEST_TMPDIR/report.json"
  sbom_license_report "$FIX/syft-license-policy.json" "" "AGPL-3.0-only" "" 2026-11-12 true > "$report"
  [ "$(jq '.mismatches' "$report")" -eq 1 ]
  run sbom_list_license_mismatches "$report"
  [ "$output" = "liar@1.0.0: declared MIT, concluded GPL-3.0-only from /node_modules/liar/vendor/COPYING" ]
}

@test "list_policy_violations names license, status and source" {
  report="$BATS_TEST_TMPDIR/report.json"
  sbom_license_report "$FIX/syft-license-policy.json" "MIT,Apache-2.0" "AGPL-3.0-only" "" 2026-11-12 false > "$report"
  [ "$(jq '.violations' "$report")" -eq 4 ]
  run sbom_list_policy_violations "$report"
  [[ "$output" == *"copyleft-deep@0.9.1: AGPL-3.0-only [AGPL-3.0-only=denied] (concluded from /go/pkg/mod/example.com/copyleft-deep@v0.9.1/LICENSE)"* ]]
  [[ "$output" == *"mystery-lib@0.1.0: no license metadata"* ]]
  [[ "$output" != *"left-pad"* ]]
}

# Single-package syft-json with one license expression.
expr_status() {
  local f="$BATS_TEST_TMPDIR/expr.json"
  jq -n --arg e "$1" '{artifacts: [{name: "x", version: "1", licenses: [{value: $e, spdxExpression: $e, type: "declared"}]}]}' > "$f"
  sbom_license_report "$f" "$2" "$3" "" 2026-11-12 false | jq -r '.packages[0].status'
}

@test "expressions: AND needs every id, nested parentheses are strict" {
  run expr_status "MIT AND GPL-3.0-only" "MIT" ""
  [ "$output" = "violation" ]
  run expr_status "MIT OR Apache-2.0 AND GPL-3.0-only" "MIT" ""
  [ "$output" = "ok" ]
  run expr_status "(MIT OR GPL-3.0-only)" "MIT" ""
  [ "$output" = "ok" ]
  run expr_status "MIT AND (Apache-2.0 OR GPL-3.0-only)" "MIT,Apache-2.0" ""
  [ "$output" = "violation" ]
}

@test "expressions: WITH exception can be allowed while the base id is denied" {
  run expr_status "GPL-2.0-only WITH Classpath-exception-2.0" "GPL-2.0-only WITH Classpath-exception-2.0" "GPL-2.0-only"
  [ "$output" = "ok" ]
  run expr_status "GPL-2.0-only" "GPL-2.0-only WITH Classpath-exception-2.0" "GPL-2.0-only"
  [ "$output" = "violation" ]
  run expr_status "gpl-2.0-only with Classpath-exception-2.0" "" "GPL-2.0-only"
  [ "$output" = "violation" ]
}
