# sbom-action

[![ci](https://github.com/moveeeax/sbom-action/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/sbom-action/actions/workflows/ci.yml)
![shell](https://img.shields.io/badge/action-composite-blue)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> Ship an SBOM with every release — automatically.

A composite GitHub Action that generates a Software Bill of Materials with
[Syft](https://github.com/anchore/syft), optionally **fails the build when a
component is missing license metadata**, signs the SBOM with
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
4. Signs the SBOM (keyless Cosign) when `sign: true` and writes a Sigstore
   bundle next to it (`<sbom>.sigstore.json`, signature and certificate in one
   file).
5. When the workflow runs on a tag and `upload-release: true`, uploads the SBOM
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
| `bundle-path` | Path to the Sigstore bundle when `sign: true`, empty otherwise. |

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
