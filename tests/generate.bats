#!/usr/bin/env bats
# Smoke tests for scripts/generate-sbom.sh using a fake Syft binary.

setup() {
  DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
  FIX="$DIR/tests/fixtures"
  WORK="$(mktemp -d)"
  cp "$FIX/fake-syft" "$WORK/fake-syft"
  chmod +x "$WORK/fake-syft"
  export SYFT_BIN="$WORK/fake-syft"
  export GITHUB_OUTPUT="$WORK/output.txt"
  : > "$GITHUB_OUTPUT"
  cd "$WORK"
}

teardown() {
  rm -rf "$WORK"
}

@test "generates an SBOM and records step outputs" {
  export FAKE_SYFT_JSON="$FIX/syft-all-licensed.json"
  export INPUT_ARTIFACT="." INPUT_SOURCE_TYPE="dir" INPUT_FORMAT="cyclonedx-json"
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -eq 0 ]
  [ -s "$WORK/sbom.json" ]
  grep -q "sbom-path=sbom.json" "$GITHUB_OUTPUT"
  grep -q "format=cyclonedx-json" "$GITHUB_OUTPUT"
  grep -q "missing-license-count=0" "$GITHUB_OUTPUT"
}

@test "honors a custom output path" {
  export FAKE_SYFT_JSON="$FIX/syft-all-licensed.json"
  export INPUT_FORMAT="spdx-json" INPUT_OUTPUT="out/bom.spdx.json"
  mkdir -p out
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -eq 0 ]
  [ -s "$WORK/out/bom.spdx.json" ]
  grep -q "sbom-path=out/bom.spdx.json" "$GITHUB_OUTPUT"
}

@test "passes the license gate when all components are licensed" {
  export FAKE_SYFT_JSON="$FIX/syft-all-licensed.json"
  export INPUT_FORMAT="cyclonedx-json" INPUT_FAIL_ON_MISSING_LICENSE="true"
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -eq 0 ]
  grep -q "missing-license-count=0" "$GITHUB_OUTPUT"
}

@test "fails the license gate and names offenders" {
  export FAKE_SYFT_JSON="$FIX/syft-with-missing-licenses.json"
  export INPUT_FORMAT="cyclonedx-json" INPUT_FAIL_ON_MISSING_LICENSE="true"
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"mystery-lib"* ]]
}

@test "rejects an unknown format before invoking syft" {
  export FAKE_SYFT_JSON="$FIX/syft-all-licensed.json"
  export INPUT_FORMAT="jpeg"
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown format"* ]]
}

@test "license policy passes and records zero violations" {
  export FAKE_SYFT_JSON="$FIX/syft-all-licensed.json"
  export INPUT_FORMAT="cyclonedx-json" INPUT_LICENSE_ALLOW="MIT, Apache-2.0"
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"all components pass the license policy"* ]]
  grep -q "license-violation-count=0" "$GITHUB_OUTPUT"
  grep -q "license-report-path=sbom.json.license-report.json" "$GITHUB_OUTPUT"
  [ -s "$WORK/sbom.json.license-report.json" ]
}

@test "license policy fails, names offenders and still writes outputs" {
  export FAKE_SYFT_JSON="$FIX/syft-license-policy.json" SBOM_TODAY="2026-11-12"
  export INPUT_FORMAT="cyclonedx-json" INPUT_LICENSE_ALLOW="MIT,Apache-2.0" INPUT_LICENSE_DENY="AGPL-3.0-only"
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"4 component(s) violate the license policy"* ]]
  [[ "$output" == *"copyleft-deep@0.9.1: AGPL-3.0-only"* ]]
  [[ "$output" == *"::warning::sbom-action: 1 component(s) have a declared license"* ]]
  grep -q "license-violation-count=4" "$GITHUB_OUTPUT"
  grep -q "license-mismatch-count=1" "$GITHUB_OUTPUT"
}

@test "license waivers clear violations until they expire" {
  export FAKE_SYFT_JSON="$FIX/syft-license-policy.json"
  export INPUT_FORMAT="syft-json" INPUT_LICENSE_ALLOW="MIT,Apache-2.0" INPUT_LICENSE_DENY="AGPL-3.0-only"
  export INPUT_LICENSE_EXCEPTIONS=$'copyleft-deep 2026-12-31 replacing in Q1\nliar 2026-12-31\ncustom-blob 2026-12-31\nmystery-lib@0.1.0 2026-12-31'
  SBOM_TODAY="2026-12-31" run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"waived copyleft-deep@0.9.1 until 2026-12-31 (replacing in Q1)"* ]]
  SBOM_TODAY="2027-01-01" run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"::warning::sbom-action: license exception for copyleft-deep expired on 2026-12-31"* ]]
}

@test "fail-on-license-mismatch turns the mismatch warning into a failure" {
  export FAKE_SYFT_JSON="$FIX/syft-license-policy.json"
  export INPUT_FORMAT="cyclonedx-json" INPUT_LICENSE_DENY="AGPL-3.0-only"
  export INPUT_ALLOW_UNKNOWN_LICENSE="true" INPUT_LICENSE_EXCEPTIONS="copyleft-deep 2099-01-01"
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -eq 0 ]
  export INPUT_FAIL_ON_LICENSE_MISMATCH="true"
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"::error::sbom-action: 1 component(s) have a declared license"* ]]
}

@test "malformed waiver fails before scanning" {
  export FAKE_SYFT_JSON="$FIX/syft-all-licensed.json"
  export INPUT_LICENSE_ALLOW="MIT" INPUT_LICENSE_EXCEPTIONS="left-pad soon"
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"bad license exception line"* ]]
  [ ! -e "$WORK/sbom.json" ]
}

@test "no policy inputs: no report and zero counts" {
  export FAKE_SYFT_JSON="$FIX/syft-license-policy.json"
  run "$DIR/scripts/generate-sbom.sh"
  [ "$status" -eq 0 ]
  grep -q "license-violation-count=0" "$GITHUB_OUTPUT"
  grep -qx "license-report-path=" "$GITHUB_OUTPUT"
  [ ! -e "$WORK/sbom.json.license-report.json" ]
}
