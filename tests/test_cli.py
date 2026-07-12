import json
from unittest.mock import MagicMock

import pytest

from cra_check.cli import main
from cra_check.context import ScanContext
from cra_check.report import CheckResult, Report


def _patch_pipeline(monkeypatch, score, results=None):
    ctx = ScanContext(sbom={"bomFormat": "CycloneDX", "components": []}, sbom_format="cyclonedx", repo_path=None, source="x")
    report = Report(
        results=results or [CheckResult("a", "A", "ref", "pass", "ok")],
        score=score,
        band="Strong" if score >= 80 else "Weak",
        checks_evaluated=1,
        checks_total=1,
    )
    monkeypatch.setattr("cra_check.cli.resolve_input", lambda source, offline=False: ctx)
    monkeypatch.setattr("cra_check.cli.run_checks", lambda checks, ctx: report)
    return report


def test_main_returns_0_when_score_meets_threshold(monkeypatch, tmp_path, capsys):
    _patch_pipeline(monkeypatch, score=90.0)
    exit_code = main([str(tmp_path / "sbom.json")])
    assert exit_code == 0


def test_main_returns_1_when_score_below_threshold(monkeypatch, tmp_path):
    _patch_pipeline(monkeypatch, score=10.0)
    exit_code = main([str(tmp_path / "sbom.json"), "--fail-under", "60"])
    assert exit_code == 1


def test_main_writes_json_when_requested(monkeypatch, tmp_path):
    _patch_pipeline(monkeypatch, score=90.0)
    json_path = tmp_path / "out.json"
    exit_code = main([str(tmp_path / "sbom.json"), "--json", str(json_path)])
    assert exit_code == 0
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert data["score"] == 90.0


def test_main_handles_resolve_input_errors_gracefully(monkeypatch, capsys):
    def raise_not_found(source, offline=False):
        raise FileNotFoundError(f"'{source}' is not a valid file path or recognized repo URL.")

    monkeypatch.setattr("cra_check.cli.resolve_input", raise_not_found)
    exit_code = main(["/nonexistent/sbom.json"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "not a valid file path" in captured.err


def test_main_calls_cleanup_scan_context_after_scan(monkeypatch, tmp_path):
    _patch_pipeline(monkeypatch, score=90.0)
    cleanup_mock = MagicMock()
    monkeypatch.setattr("cra_check.cli.cleanup_scan_context", cleanup_mock)
    exit_code = main([str(tmp_path / "sbom.json")])
    assert exit_code == 0
    cleanup_mock.assert_called_once()
