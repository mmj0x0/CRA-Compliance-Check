import json
import pytest
from pathlib import Path

from cra_check.context import (
    ScanContext,
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
