# tests/checks/test_known_vulnerabilities.py
from unittest.mock import MagicMock
import requests

from cra_check.checks.known_vulnerabilities import KnownVulnerabilitiesCheck, query_osv
from cra_check.context import ScanContext


def _sbom_with_purls(purls):
    return {
        "bomFormat": "CycloneDX",
        "components": [{"name": f"pkg{i}", "purl": p} for i, p in enumerate(purls)],
    }


def test_not_applicable_when_offline():
    ctx = ScanContext(sbom=_sbom_with_purls(["pkg:pypi/requests@2.31.0"]), sbom_format="cyclonedx", repo_path=None, source="x", offline=True)
    result = KnownVulnerabilitiesCheck().run(ctx)
    assert result.status == "not_applicable"


def test_not_applicable_when_no_sbom():
    ctx = ScanContext(sbom=None, sbom_format=None, repo_path=None, source="x")
    result = KnownVulnerabilitiesCheck().run(ctx)
    assert result.status == "not_applicable"


def test_warn_when_no_purls():
    ctx = ScanContext(sbom={"bomFormat": "CycloneDX", "components": [{"name": "x"}]}, sbom_format="cyclonedx", repo_path=None, source="x")
    result = KnownVulnerabilitiesCheck().run(ctx)
    assert result.status == "warn"


def test_pass_when_no_vulns_found(monkeypatch):
    ctx = ScanContext(sbom=_sbom_with_purls(["pkg:pypi/requests@2.31.0"]), sbom_format="cyclonedx", repo_path=None, source="x")
    monkeypatch.setattr(
        "cra_check.checks.known_vulnerabilities.query_osv",
        lambda purls, session=None: {"results": [{}]},
    )
    result = KnownVulnerabilitiesCheck().run(ctx)
    assert result.status == "pass"


def test_fail_when_vulns_found(monkeypatch):
    ctx = ScanContext(sbom=_sbom_with_purls(["pkg:pypi/requests@2.31.0"]), sbom_format="cyclonedx", repo_path=None, source="x")
    monkeypatch.setattr(
        "cra_check.checks.known_vulnerabilities.query_osv",
        lambda purls, session=None: {"results": [{"vulns": [{"id": "GHSA-xxxx"}]}]},
    )
    result = KnownVulnerabilitiesCheck().run(ctx)
    assert result.status == "fail"
    assert "1 of 1" in result.message


def test_error_when_osv_unreachable(monkeypatch):
    ctx = ScanContext(sbom=_sbom_with_purls(["pkg:pypi/requests@2.31.0"]), sbom_format="cyclonedx", repo_path=None, source="x")

    def raise_error(purls, session=None):
        raise requests.ConnectionError("network down")

    monkeypatch.setattr("cra_check.checks.known_vulnerabilities.query_osv", raise_error)
    result = KnownVulnerabilitiesCheck().run(ctx)
    assert result.status == "error"
    assert "network down" in result.message


def test_query_osv_posts_batch_request():
    session = MagicMock()
    session.post.return_value.raise_for_status.return_value = None
    session.post.return_value.json.return_value = {"results": []}
    result = query_osv(["pkg:pypi/requests@2.31.0"], session=session)
    assert result == {"results": []}
    called_url = session.post.call_args[0][0]
    assert called_url == "https://api.osv.dev/v1/querybatch"
    body = session.post.call_args[1]["json"]
    assert body["queries"] == [{"package": {"purl": "pkg:pypi/requests@2.31.0"}}]
