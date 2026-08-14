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
