# tests/checks/test_default_secure_config.py
from cra_check.checks.default_secure_config import DefaultSecureConfigCheck
from cra_check.context import ScanContext


def test_not_applicable_without_repo():
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=None, source="x")
    result = DefaultSecureConfigCheck().run(ctx)
    assert result.status == "not_applicable"


def test_pass_when_no_insecure_defaults(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services:\n  app:\n    image: myapp:latest\n")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = DefaultSecureConfigCheck().run(ctx)
    assert result.status == "pass"


def test_warn_when_default_password_found(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services:\n  db:\n    environment:\n      - password=admin\n")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = DefaultSecureConfigCheck().run(ctx)
    assert result.status == "warn"
    assert "docker-compose.yml" in result.message


def test_skips_git_directory(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config.yml").write_text("password=admin")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = DefaultSecureConfigCheck().run(ctx)
    assert result.status == "pass"


def test_pass_when_similar_but_not_matching_value(tmp_path):
    # Values like "administrator" and "secretsManagerArn" should not match
    # because they don't have word boundaries after "admin" and "secret"
    (tmp_path / "config.yml").write_text(
        "password: administrator\nsecret: secretsManagerArn\n"
    )
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = DefaultSecureConfigCheck().run(ctx)
    assert result.status == "pass"
