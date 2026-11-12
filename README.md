# sbom-action

[![ci](https://github.com/moveeeax/sbom-action/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/sbom-action/actions/workflows/ci.yml)
![shell](https://img.shields.io/badge/action-composite-blue)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> Ship an SBOM with every release — automatically.

A composite GitHub Action that generates a Software Bill of Materials with
[Syft](https://github.com/anchore/syft), optionally **fails the build when a
component is missing license metadata or uses a license outside your allow
list**, signs the SBOM with
[Cosign](https://github.com/sigstore/cosign), and attaches it to the GitHub
Release.

## How it works

1. Installs a pinned Syft (and Cosign when signing is enabled) from the
   upstream GitHub release, verifying the sha256 against the release's
   checksums file.
2. Normalizes your `format`/`source-type` inputs into a Syft scan and writes the
   SBOM to `output` (default `sbom.<ext>`).
3. If `fail-on-missing-license: true`, it takes a `syft-json` view of the same
   scan and fails with the offending component names if any lack a license.
4. If `license-allow` or `license-deny` is set, evaluates every component in
   the same `syft-json` view against that policy (see
   [License policy](#license-policy)) and writes a JSON report next to the SBOM.
5. Signs the SBOM (keyless Cosign) when `sign: true` and writes a Sigstore
   bundle next to it (`<sbom>.sigstore.json`, signature and certificate in one
   file).
6. When the workflow runs on a tag and `upload-release: true`, uploads the SBOM
   (and the `.sigstore.json` bundle) to the matching release with
   `gh release upload`.

The scan/format/license logic lives in `scripts/lib.sh` and is fully unit-tested
with [bats](https://github.com/bats-core/bats-core) — no Syft required to test.

## Usage

```yaml
permissions:
  contents: write   # upload the SBOM to the release
  id-token: write   # keyless Cosign signing

steps:
  - uses: actions/checkout@v7
  - uses: moveeeax/sbom-action@v0
    with:
      artifact: .
      format: cyclonedx-json
      fail-on-missing-license: "false"
      sign: "true"
```

Scan a container image instead of the source tree:

```yaml
  - uses: moveeeax/sbom-action@v0
    with:
      artifact: ghcr.io/moveeeax/app:1.2.3
      source-type: image
      format: spdx-json
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `artifact` | `.` | Path or reference to scan. |
| `source-type` | `dir` | `dir` \| `file` \| `image` \| `docker`. |
| `format` | `cyclonedx-json` | `cyclonedx-json` \| `cyclonedx-xml` \| `spdx-json` \| `spdx-tag-value` \| `syft-json` \| `table`. |
| `output` | *(auto)* | Output path; defaults to `sbom.<ext>`. |
| `fail-on-missing-license` | `false` | Fail when a component has no license metadata. |
| `license-allow` | *(empty)* | SPDX ids allowed, comma- or newline-separated. Anything else fails. |
| `license-deny` | *(empty)* | SPDX ids that fail the run. Deny wins over allow for the same id. |
| `license-exceptions` | *(empty)* | Waivers, one per line: `<name>[@<version>] <YYYY-MM-DD> [reason]`. |
| `allow-unknown-license` | `false` | Let missing and non-SPDX licenses pass the policy. |
| `fail-on-license-mismatch` | `false` | Fail when the declared license differs from the concluded one. |
| `upload-release` | `true` | Attach the SBOM to the release on a tag push. |
| `sign` | `false` | Sign the SBOM with Cosign (keyless). |
| `syft-version` | `v1.56.0` | Syft version to install. |
| `cosign-version` | `v3.1.4` | Cosign version to install when signing. |
| `github-token` | `${{ github.token }}` | Token for the release upload. |

## Outputs

| Output | Description |
|--------|-------------|
| `sbom-path` | Path to the generated SBOM file. |
| `format` | Canonical Syft format produced. |
| `missing-license-count` | Components missing license metadata (0 unless the gate ran). |
| `license-violation-count` | Components failing the license policy, waivers excluded (0 unless the policy ran). |
| `license-mismatch-count` | Components whose declared and concluded licenses differ (0 unless the policy ran). |
| `license-report-path` | `<sbom>.license-report.json` when the policy ran, empty otherwise. |
| `bundle-path` | Path to the Sigstore bundle when `sign: true`, empty otherwise. |

## License policy

```yaml
  - uses: moveeeax/sbom-action@v0
    with:
      license-allow: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC
      license-deny: AGPL-3.0-only, AGPL-3.0-or-later
      license-exceptions: |
        # name[@version]   valid through   reason
        @acme/legacy-sdk@4.2.0 2026-12-31 vendor relicensing, ticket LEGAL-112
        github.com/foo/bar     2027-03-01
```

The policy runs on the license data Syft records for each package (declared
in the package manifest, or concluded by Syft from license files), across
every package in the SBOM, transitive dependencies included. Rules:

- Ids are SPDX license ids and compare case-insensitively. Common malformed
  spellings (`Apache 2.0`, `Apache License, Version 2.0`, `GPLv3`, `New BSD`)
  and deprecated ids (`GPL-3.0`, `AGPL-3.0`) are mapped to the current id,
  both in the SBOM and in your lists. The list of valid ids is
  [SPDX License List](https://github.com/spdx/license-list-data) 3.29.0,
  bundled as `scripts/spdx-licenses.json`.
- `A OR B` passes when one side passes; `A AND B` needs both. An expression
  with nested parentheses is checked strictly: every id in it must pass.
- `X WITH exception` matches a list entry for the full term first, then for
  `X`, so you can allow `GPL-2.0-only WITH Classpath-exception-2.0` while
  denying `GPL-2.0-only`.
- A package with several license entries must pass on each of them.
- Anything that is not a SPDX id (`LicenseRef-*`, `NOASSERTION`, free text)
  and packages with no license at all count as unknown and fail, unless
  `allow-unknown-license: true` or the exact term is in `license-allow`.
- With only `license-deny` set, every SPDX id outside the deny list passes.
- A waiver applies through its date (UTC). After that the package fails again
  and the run prints a warning naming the expired waiver. Waivers that match
  no package are reported as notices. A waiver without `@version` covers
  every version of that package.
- When a package has both declared and concluded licenses and they differ
  (a `package.json` saying MIT over a bundled GPL `COPYING`), the run prints
  a warning with the file Syft read; `fail-on-license-mismatch: true` makes
  it fail.

Failures list each package with the failing license, its status
(`denied`, `not-allowed`, `unknown`) and where Syft found it. The full
per-package report is written to `<sbom>.license-report.json`
(`license-report-path`) before the gate fails, so a later `if: failure()`
step can upload it by that path.

## Verifying a signed SBOM

Cosign 3 writes signatures as a Sigstore bundle, so releases carry
`sbom.json.sigstore.json` instead of the separate `.sig`/`.pem` files that
earlier versions of this action uploaded:

```bash
cosign verify-blob \
  --bundle sbom.json.sigstore.json \
  --certificate-identity-regexp '^https://github.com/OWNER/REPO/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sbom.json
```

## Local development

```bash
shellcheck -x scripts/*.sh
bats tests/
```

## License

MIT — see [LICENSE](LICENSE).
