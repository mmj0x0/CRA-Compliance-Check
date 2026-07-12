from cra_check.checks.sbom_presence import SbomPresenceCheck
from cra_check.context import ScanContext


def test_pass_when_sbom_present():
    ctx = ScanContext(sbom={"bomFormat": "CycloneDX"}, sbom_format="cyclonedx", repo_path=None, source="x")
    result = SbomPresenceCheck().run(ctx)
    assert result.status == "pass"
    assert result.check_id == "sbom_presence"


def test_fail_when_sbom_absent():
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=None, source="x")
    result = SbomPresenceCheck().run(ctx)
    assert result.status == "fail"
