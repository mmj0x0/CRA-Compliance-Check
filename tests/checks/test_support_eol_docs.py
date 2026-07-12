from cra_check.checks.support_eol_docs import SupportEolDocsCheck
from cra_check.context import ScanContext


def test_not_applicable_without_repo():
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=None, source="x")
    result = SupportEolDocsCheck().run(ctx)
    assert result.status == "not_applicable"


def test_pass_when_changelog_and_support_policy_present(tmp_path):
    (tmp_path / "CHANGELOG.md").write_text("## 1.0.0\n- initial release\n")
    (tmp_path / "README.md").write_text("## Supported Versions\nWe support the last 2 LTS releases.\n")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = SupportEolDocsCheck().run(ctx)
    assert result.status == "pass"


def test_warn_when_only_changelog_present(tmp_path):
    (tmp_path / "CHANGELOG.md").write_text("## 1.0.0\n- initial release\n")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = SupportEolDocsCheck().run(ctx)
    assert result.status == "warn"


def test_fail_when_neither_present(tmp_path):
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = SupportEolDocsCheck().run(ctx)
    assert result.status == "fail"
