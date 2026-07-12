from cra_check.checks.sbom_completeness import SbomCompletenessCheck
from cra_check.context import ScanContext


def test_not_applicable_when_no_sbom():
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=None, source="x")
    result = SbomCompletenessCheck().run(ctx)
    assert result.status == "not_applicable"


def test_warn_when_no_components():
    ctx = ScanContext(sbom={"bomFormat": "CycloneDX", "components": []}, sbom_format="cyclonedx", repo_path=None, source="x")
    result = SbomCompletenessCheck().run(ctx)
    assert result.status == "warn"


def test_pass_when_all_components_complete_cyclonedx():
    sbom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "requests", "version": "2.31.0", "licenses": [{"license": {"id": "Apache-2.0"}}]},
        ],
    }
    ctx = ScanContext(sbom=sbom, sbom_format="cyclonedx", repo_path=None, source="x")
    result = SbomCompletenessCheck().run(ctx)
    assert result.status == "pass"


def test_warn_when_some_components_incomplete_cyclonedx():
    sbom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "requests", "version": "2.31.0", "licenses": [{"license": {"id": "Apache-2.0"}}]},
            {"name": "unknown-lib"},
        ],
    }
    ctx = ScanContext(sbom=sbom, sbom_format="cyclonedx", repo_path=None, source="x")
    result = SbomCompletenessCheck().run(ctx)
    assert result.status == "warn"
    assert "1 of 2" in result.message


def test_pass_when_all_components_complete_spdx():
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {"name": "requests", "versionInfo": "2.31.0", "licenseConcluded": "Apache-2.0"},
        ],
    }
    ctx = ScanContext(sbom=sbom, sbom_format="spdx", repo_path=None, source="x")
    result = SbomCompletenessCheck().run(ctx)
    assert result.status == "pass"


def test_warn_when_spdx_license_noassertion():
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {"name": "requests", "versionInfo": "2.31.0", "licenseConcluded": "NOASSERTION"},
        ],
    }
    ctx = ScanContext(sbom=sbom, sbom_format="spdx", repo_path=None, source="x")
    result = SbomCompletenessCheck().run(ctx)
    assert result.status == "warn"
