import json
import pytest
from pathlib import Path

from cra_check.context import (
    ScanContext,
    cleanup_scan_context,
    detect_sbom_format,
    parse_sbom_file,
    is_repo_url,
    resolve_input,
)


def test_detect_cyclonedx_format():
    assert detect_sbom_format({"bomFormat": "CycloneDX", "components": []}) == "cyclonedx"


def test_detect_spdx_format():
    assert detect_sbom_format({"spdxVersion": "SPDX-2.3", "packages": []}) == "spdx"


def test_detect_unknown_format():
    assert detect_sbom_format({"foo": "bar"}) is None


def test_parse_sbom_file(tmp_path):
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    data, fmt = parse_sbom_file(sbom_path)
    assert fmt == "cyclonedx"
    assert data["bomFormat"] == "CycloneDX"


def test_is_repo_url():
    assert is_repo_url("https://github.com/mmj0x0/PentestNotes") is True
    assert is_repo_url("git@github.com:mmj0x0/PentestNotes.git") is True
    assert is_repo_url("./sbom.json") is False
    assert is_repo_url("/tmp/sbom.json") is False


def test_resolve_input_from_sbom_file(tmp_path):
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    ctx = resolve_input(str(sbom_path))
    assert isinstance(ctx, ScanContext)
    assert ctx.sbom_format == "cyclonedx"
    assert ctx.repo_path is None
    assert ctx.offline is False


def test_resolve_input_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        resolve_input("/nonexistent/path/sbom.json")


def test_resolve_input_malformed_json_raises(tmp_path):
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{not valid json")
    with pytest.raises(ValueError):
        resolve_input(str(bad_path))


import subprocess
from unittest.mock import MagicMock

from cra_check.context import clone_repo, find_sbom_in_repo, generate_sbom_with_syft


def test_clone_repo_success(tmp_path):
    runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))
    dest = tmp_path / "clone"
    clone_repo("https://github.com/mmj0x0/PentestNotes", dest, runner=runner)
    runner.assert_called_once()
    called_args = runner.call_args[0][0]
    assert called_args[:2] == ["git", "clone"]


def test_clone_repo_failure_raises(tmp_path):
    runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="fatal: repo not found"))
    with pytest.raises(RuntimeError, match="fatal: repo not found"):
        clone_repo("https://github.com/nope/nope", tmp_path / "clone", runner=runner)


def test_find_sbom_in_repo_found(tmp_path):
    (tmp_path / "sbom.json").write_text(json.dumps({"bomFormat": "CycloneDX"}))
    found = find_sbom_in_repo(tmp_path)
    assert found == tmp_path / "sbom.json"


def test_find_sbom_in_repo_not_found(tmp_path):
    assert find_sbom_in_repo(tmp_path) is None


def test_generate_sbom_with_syft_not_installed(tmp_path):
    result = generate_sbom_with_syft(tmp_path, which=lambda name: None)
    assert result is None


def test_generate_sbom_with_syft_success(tmp_path):
    output = json.dumps({"bomFormat": "CycloneDX", "components": []})
    runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr=""))
    result = generate_sbom_with_syft(tmp_path, runner=runner, which=lambda name: "/usr/bin/syft")
    assert result["bomFormat"] == "CycloneDX"


def test_resolve_input_repo_url_with_existing_sbom(tmp_path, monkeypatch):
    def fake_clone(url, dest, runner=subprocess.run):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "sbom.json").write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))

    monkeypatch.setattr("cra_check.context.clone_repo", fake_clone)
    ctx = resolve_input("https://github.com/mmj0x0/PentestNotes", workdir=tmp_path / "clone")
    assert ctx.sbom_format == "cyclonedx"
    assert ctx.repo_path == tmp_path / "clone"


def test_resolve_input_repo_url_clone_failure(tmp_path, monkeypatch):
    def fake_clone(url, dest, runner=subprocess.run):
        raise RuntimeError("git clone failed for https://bad: fatal: not found")

    monkeypatch.setattr("cra_check.context.clone_repo", fake_clone)
    with pytest.raises(RuntimeError):
        resolve_input("https://bad", workdir=tmp_path / "clone")


def test_resolve_input_repo_url_falls_back_to_syft(tmp_path, monkeypatch):
    def fake_clone(url, dest, runner=subprocess.run):
        dest.mkdir(parents=True, exist_ok=True)

    fake_sbom = {"bomFormat": "CycloneDX", "components": []}
    monkeypatch.setattr("cra_check.context.clone_repo", fake_clone)
    monkeypatch.setattr("cra_check.context.generate_sbom_with_syft", lambda repo_path: fake_sbom)
    ctx = resolve_input("https://github.com/mmj0x0/PentestNotes", workdir=tmp_path / "clone")
    assert ctx.sbom == fake_sbom
    assert ctx.sbom_format == "cyclonedx"
    assert ctx.repo_path == tmp_path / "clone"


def test_resolve_input_repo_url_syft_also_fails(tmp_path, monkeypatch):
    def fake_clone(url, dest, runner=subprocess.run):
        dest.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("cra_check.context.clone_repo", fake_clone)
    monkeypatch.setattr("cra_check.context.generate_sbom_with_syft", lambda repo_path: None)
    ctx = resolve_input("https://github.com/mmj0x0/PentestNotes", workdir=tmp_path / "clone")
    assert ctx.sbom is None
    assert ctx.sbom_format is None
    assert ctx.repo_path == tmp_path / "clone"


def test_cleanup_scan_context_removes_self_owned_temp_dir(tmp_path):
    repo_path = tmp_path / "owned-clone"
    repo_path.mkdir()
    (repo_path / "marker.txt").write_text("hello")
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=repo_path, source="https://example.com/repo", _owns_repo_path=True)
    assert repo_path.exists()
    cleanup_scan_context(ctx)
    assert not repo_path.exists()


def test_cleanup_scan_context_does_not_remove_explicit_workdir(tmp_path):
    repo_path = tmp_path / "explicit-workdir"
    repo_path.mkdir()
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=repo_path, source="https://example.com/repo", _owns_repo_path=False)
    cleanup_scan_context(ctx)
    assert repo_path.exists()


def test_cleanup_scan_context_noop_when_repo_path_is_none():
    ctx = ScanContext(sbom={"bomFormat": "CycloneDX"}, sbom_format="cyclonedx", repo_path=None, source="sbom.json", _owns_repo_path=False)
    cleanup_scan_context(ctx)  # should not raise


def test_resolve_input_repo_url_without_workdir_owns_repo_path(tmp_path, monkeypatch):
    def fake_clone(url, dest, runner=subprocess.run):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "sbom.json").write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))

    monkeypatch.setattr("cra_check.context.clone_repo", fake_clone)
    monkeypatch.setattr("cra_check.context.tempfile.mkdtemp", lambda prefix="": str(tmp_path / "auto-clone"))
    ctx = resolve_input("https://github.com/mmj0x0/PentestNotes")
    assert ctx._owns_repo_path is True

    ctx_explicit = resolve_input("https://github.com/mmj0x0/PentestNotes", workdir=tmp_path / "explicit-clone")
    assert ctx_explicit._owns_repo_path is False
