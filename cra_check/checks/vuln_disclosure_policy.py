# cra_check/checks/vuln_disclosure_policy.py
from cra_check.checks.base import Check
from cra_check.report import CheckResult

CANDIDATE_PATHS = ["SECURITY.md", ".github/SECURITY.md", "security.txt", ".well-known/security.txt"]


class VulnDisclosurePolicyCheck(Check):
    id = "vuln_disclosure_policy"
    title = "Vulnerability Disclosure Policy"
    annex_ref = "Annex I, Part II, 5"
    weight = 2

    def run(self, ctx) -> CheckResult:
        if ctx.repo_path is None:
            return CheckResult(self.id, self.title, self.annex_ref, "not_applicable", "No repository available to check for a disclosure policy.")

        for rel in CANDIDATE_PATHS:
            candidate = ctx.repo_path / rel
            if candidate.is_file() and candidate.stat().st_size > 0:
                return CheckResult(self.id, self.title, self.annex_ref, "pass", f"Found vulnerability disclosure policy at {rel}.")
        return CheckResult(self.id, self.title, self.annex_ref, "fail", "No SECURITY.md or security.txt found in the repository.")
