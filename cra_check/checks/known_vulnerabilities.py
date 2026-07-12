# cra_check/checks/known_vulnerabilities.py
import requests

from cra_check.checks.base import Check
from cra_check.report import CheckResult

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


class KnownVulnerabilitiesCheck(Check):
    id = "known_vulnerabilities"
    title = "Known Vulnerability Handling"
    annex_ref = "Annex I, Part I, 2(2)"
    weight = 3

    def run(self, ctx) -> CheckResult:
        if ctx.offline:
            return CheckResult(self.id, self.title, self.annex_ref, "not_applicable", "Skipped: --offline flag set.")
        if ctx.sbom is None:
            return CheckResult(self.id, self.title, self.annex_ref, "not_applicable", "No SBOM available to check for known vulnerabilities.")

        purls = _extract_purls(ctx.sbom, ctx.sbom_format)
        if not purls:
            return CheckResult(self.id, self.title, self.annex_ref, "warn", "SBOM has no components with package URLs (purl) to check.")

        try:
            data = query_osv(purls)
        except requests.RequestException as exc:
            return CheckResult(self.id, self.title, self.annex_ref, "error", f"Could not reach OSV.dev: {exc}")

        vulnerable = [r for r in data.get("results", []) if r.get("vulns")]
        if not vulnerable:
            return CheckResult(self.id, self.title, self.annex_ref, "pass", f"No known vulnerabilities found across {len(purls)} components.")
        return CheckResult(
            self.id, self.title, self.annex_ref, "fail",
            f"{len(vulnerable)} of {len(purls)} components have known vulnerabilities in OSV.dev.",
        )


def _extract_purls(sbom: dict, fmt: str) -> list:
    if fmt != "cyclonedx":
        return []
    return [c["purl"] for c in sbom.get("components", []) if c.get("purl")]


def query_osv(purls: list, session=requests) -> dict:
    queries = [{"package": {"purl": purl}} for purl in purls]
    response = session.post(OSV_BATCH_URL, json={"queries": queries}, timeout=15)
    response.raise_for_status()
    return response.json()
