from cra_check.checks.security_logging import SecurityLoggingCheck
from cra_check.context import ScanContext


def test_not_applicable_without_repo():
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=None, source="x")
    result = SecurityLoggingCheck().run(ctx)
    assert result.status == "not_applicable"


def test_pass_when_python_logging_import_found(tmp_path):
    (tmp_path / "app.py").write_text("import logging\n\nlogging.info('started')\n")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = SecurityLoggingCheck().run(ctx)
    assert result.status == "pass"


def test_warn_when_no_logging_found(tmp_path):
    (tmp_path / "app.py").write_text("print('started')\n")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = SecurityLoggingCheck().run(ctx)
    assert result.status == "warn"
