from cra_check.checks.data_minimization import DataMinimizationCheck
from cra_check.context import ScanContext


def test_not_applicable_without_repo():
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=None, source="x")
    result = DataMinimizationCheck().run(ctx)
    assert result.status == "not_applicable"


def test_pass_when_no_pii_fields(tmp_path):
    (tmp_path / "models.py").write_text("class User:\n    username: str\n    email: str\n")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = DataMinimizationCheck().run(ctx)
    assert result.status == "pass"


def test_warn_when_pii_field_found(tmp_path):
    (tmp_path / "models.py").write_text("class User:\n    ssn: str\n")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = DataMinimizationCheck().run(ctx)
    assert result.status == "warn"
    assert "models.py" in result.message
