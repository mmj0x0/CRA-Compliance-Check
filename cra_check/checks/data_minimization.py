import re

from cra_check.checks.base import Check
from cra_check.report import CheckResult

CODE_GLOBS = ["*.py", "*.js", "*.ts", "*.sql", "*.json"]
PII_FIELD_PATTERN = re.compile(r"\b(ssn|social_security|credit_card|creditcard|passport_number|national_id)\b", re.IGNORECASE)


class DataMinimizationCheck(Check):
    id = "data_minimization"
    title = "Data Minimization Signals"
    annex_ref = "Annex I, Part I, 2(3)(c)"
    weight = 1

    def run(self, ctx) -> CheckResult:
        if ctx.repo_path is None:
            return CheckResult(self.id, self.title, self.annex_ref, "not_applicable", "No repository available to check for data minimization signals.")

        hits = []
        for pattern_glob in CODE_GLOBS:
            for path in ctx.repo_path.rglob(pattern_glob):
                if ".git" in path.parts:
                    continue
                try:
                    text = path.read_text(errors="ignore")
                except OSError:
                    continue
                if PII_FIELD_PATTERN.search(text):
                    hits.append(str(path.relative_to(ctx.repo_path)))

        if not hits:
            return CheckResult(self.id, self.title, self.annex_ref, "pass", "No obviously sensitive PII-shaped field names found.")
        return CheckResult(
            self.id, self.title, self.annex_ref, "warn",
            f"Found PII-shaped field names in: {', '.join(hits[:10])}. Manually confirm these are justified and documented.",
        )
