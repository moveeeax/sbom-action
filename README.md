# sbom-action

> Ship an SBOM with every release — automatically.

**Status:** 🚧 In development

## Overview

Generate and attach a Software Bill of Materials (Syft) on every release.

## Features

- Generates SPDX/CycloneDX via Syft
- Attaches SBOM to the GitHub Release
- Optional attestation + Cosign signing
- Works for source and container artifacts
- Fails on missing license metadata (optional)

## Stack

Composite Action + Syft + Cosign.

## Usage

```yaml
- uses: moveeeax/sbom-action@v1
  with:
    artifact: ./dist
    format: cyclonedx-json
```

## License

MIT
