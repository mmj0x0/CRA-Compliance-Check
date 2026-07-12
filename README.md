# cra-compliance-check

A CLI that scores a project against Cyber Resilience Act (CRA) Annex I requirements, from either an SBOM file or a public GitHub/GitLab repo URL.

## Install

```bash
pip install .
```

## Usage

```bash
# From an SBOM file (CycloneDX or SPDX JSON)
cra-check ./sbom.json

# From a public repo (clones, finds/generates an SBOM, and scans repo-level signals)
cra-check https://github.com/example/example-project

# Export a machine-readable report for CI
cra-check ./sbom.json --json report.json --fail-under 70

# Skip network-dependent checks (e.g. OSV.dev)
cra-check ./sbom.json --offline
```

## What it checks

Nine independently-scored checks spanning CRA Annex I: SBOM presence and completeness, known-vulnerability handling (via [OSV.dev](https://osv.dev)), vulnerability disclosure policy, secure update mechanism signals, default secure configuration, data minimization signals, security-relevant logging capability, and support-period/EOL documentation.

This is a heuristic self-assessment tool, not a certified compliance authority — treat results as a starting point for review, not a legal determination.

## Development

```bash
pip install -e ".[dev]"
python -m pytest -v
```
