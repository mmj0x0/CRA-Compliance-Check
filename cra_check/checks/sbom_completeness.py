from cra_check.checks.base import Check
from cra_check.report import CheckResult


class SbomCompletenessCheck(Check):
    id = "sbom_completeness"
    title = "SBOM Completeness"
    annex_ref = "Annex I, Part I, 2(1)"
    weight = 2

    def run(self, ctx) -> CheckResult:
        if ctx.sbom is None:
            return CheckResult(self.id, self.title, self.annex_ref, "not_applicable", "No SBOM available to evaluate completeness.")

        components = _extract_components(ctx.sbom, ctx.sbom_format)
        if not components:
            return CheckResult(self.id, self.title, self.annex_ref, "warn", "SBOM present but lists no components.")

        incomplete = [c for c in components if not _is_complete(c, ctx.sbom_format)]
        if not incomplete:
            return CheckResult(self.id, self.title, self.annex_ref, "pass", f"All {len(components)} components have name, version, and license metadata.")
        return CheckResult(
            self.id, self.title, self.annex_ref, "warn",
            f"{len(incomplete)} of {len(components)} components are missing name, version, or license metadata.",
        )


def _extract_components(sbom: dict, fmt: str) -> list:
    if fmt == "cyclonedx":
        return sbom.get("components", [])
    if fmt == "spdx":
        return sbom.get("packages", [])
    return []


def _is_complete(component: dict, fmt: str) -> bool:
    if fmt == "cyclonedx":
        return bool(component.get("name")) and bool(component.get("version")) and bool(component.get("licenses"))
    if fmt == "spdx":
        return (
            bool(component.get("name"))
            and bool(component.get("versionInfo"))
            and component.get("licenseConcluded") not in (None, "", "NOASSERTION")
        )
    return False
