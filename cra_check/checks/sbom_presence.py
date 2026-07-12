from cra_check.checks.base import Check
from cra_check.report import CheckResult


class SbomPresenceCheck(Check):
    id = "sbom_presence"
    title = "SBOM Presence"
    annex_ref = "Annex I, Part I, 2(1)"
    weight = 3

    def run(self, ctx) -> CheckResult:
        if ctx.sbom is not None:
            return CheckResult(self.id, self.title, self.annex_ref, "pass", "SBOM found and parsed successfully.")
        return CheckResult(self.id, self.title, self.annex_ref, "fail", "No SBOM was found or could be generated for this project.")
