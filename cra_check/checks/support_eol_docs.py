import re

from cra_check.checks.base import Check
from cra_check.report import CheckResult

CHANGELOG_CANDIDATES = ["CHANGELOG.md", "CHANGELOG", "HISTORY.md"]
SUPPORT_KEYWORDS = re.compile(r"\b(end.of.life|EOL|support policy|supported versions|LTS)\b", re.IGNORECASE)


class SupportEolDocsCheck(Check):
    id = "support_eol_docs"
    title = "Support Period / EOL Documentation"
    annex_ref = "Annex I, Part II, 3"
    weight = 1

    def run(self, ctx) -> CheckResult:
        if ctx.repo_path is None:
            return CheckResult(self.id, self.title, self.annex_ref, "not_applicable", "No repository available to check for support/EOL documentation.")

        has_changelog = any((ctx.repo_path / name).is_file() for name in CHANGELOG_CANDIDATES)
        readme = ctx.repo_path / "README.md"
        has_support_policy = bool(readme.is_file() and SUPPORT_KEYWORDS.search(readme.read_text(errors="ignore")))

        if has_changelog and has_support_policy:
            return CheckResult(self.id, self.title, self.annex_ref, "pass", "Found both a changelog and support/EOL policy documentation.")
        if has_changelog or has_support_policy:
            return CheckResult(self.id, self.title, self.annex_ref, "warn", "Found partial support documentation (changelog or support policy, not both).")
        return CheckResult(self.id, self.title, self.annex_ref, "fail", "No changelog or support/EOL policy documentation found.")
