import os
import sys

import pytest

from cra_check.checks.secure_update_mechanism import SecureUpdateMechanismCheck
from cra_check.context import ScanContext


def test_not_applicable_without_repo():
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=None, source="x")
    result = SecureUpdateMechanismCheck().run(ctx)
    assert result.status == "not_applicable"


def test_pass_when_dependabot_config_present(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "dependabot.yml").write_text("version: 2")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = SecureUpdateMechanismCheck().run(ctx)
    assert result.status == "pass"


def test_pass_when_release_workflow_present(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text("name: Release\non:\n  push:\n    tags: ['v*']")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = SecureUpdateMechanismCheck().run(ctx)
    assert result.status == "pass"


def test_warn_when_no_signals_found(tmp_path):
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
    result = SecureUpdateMechanismCheck().run(ctx)
    assert result.status == "warn"


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="requires POSIX permission enforcement and a non-root user",
)
def test_unreadable_workflow_file_is_skipped_not_raised(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    unreadable = workflows / "aaa-unreadable.yml"
    unreadable.write_text("name: release\non: push")
    unreadable.chmod(0o000)
    try:
        ctx = ScanContext(sbom=None, sbom_format=None, repo_path=tmp_path, source="x")
        result = SecureUpdateMechanismCheck().run(ctx)
        # unreadable workflow should be skipped, not raise; with no other signals, warn
        assert result.status == "warn"
    finally:
        unreadable.chmod(0o644)
