# tests/checks/test_vuln_disclosure_policy.py
from cra_check.checks.vuln_disclosure_policy import VulnDisclosurePolicyCheck
from cra_check.context import ScanContext


def test_not_applicable_without_repo():
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=None, source="x")
    result = VulnDisclosurePolicyCheck().run(ctx)
    assert result.status == "not_applicable"


def test_pass_when_security_md_present(tmp_path):
    (tmp_path / "SECURITY.md").write_text("Report vulnerabilities to security@example.com")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = VulnDisclosurePolicyCheck().run(ctx)
    assert result.status == "pass"


def test_fail_when_no_policy_file(tmp_path):
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = VulnDisclosurePolicyCheck().run(ctx)
    assert result.status == "fail"


def test_fail_when_policy_file_empty(tmp_path):
    (tmp_path / "SECURITY.md").write_text("")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = VulnDisclosurePolicyCheck().run(ctx)
    assert result.status == "fail"
