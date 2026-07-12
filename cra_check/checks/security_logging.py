import re

from cra_check.checks.base import Check
from cra_check.report import CheckResult

LOGGING_SIGNALS = {
    "*.py": re.compile(r"^\s*(import logging\b|from logging\b)", re.MULTILINE),
    "*.js": re.compile(r"require\(['\"](winston|pino|bunyan)['\"]\)|from ['\"](winston|pino|bunyan)['\"]"),
    "*.ts": re.compile(r"from ['\"](winston|pino|bunyan)['\"]"),
    "*.java": re.compile(r"import (org\.slf4j|org\.apache\.log4j)"),
}


class SecurityLoggingCheck(Check):
    id = "security_logging"
    title = "Security-Relevant Logging Capability"
    annex_ref = "Annex I, Part I, 2(3)(f)"
    weight = 1

    def run(self, ctx) -> CheckResult:
        if ctx.repo_path is None:
            return CheckResult(self.id, self.title, self.annex_ref, "not_applicable", "No repository available to check for logging capability.")

        for glob, pattern in LOGGING_SIGNALS.items():
            for path in ctx.repo_path.rglob(glob):
                if ".git" in path.parts:
                    continue
                try:
                    text = path.read_text(errors="ignore")
                except OSError:
                    continue
                if pattern.search(text):
                    return CheckResult(self.id, self.title, self.annex_ref, "pass", f"Found logging library usage in {path.relative_to(ctx.repo_path)}.")

        return CheckResult(self.id, self.title, self.annex_ref, "warn", "No recognized logging library usage found; security-relevant events may not be captured.")
