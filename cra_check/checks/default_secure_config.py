import re

from cra_check.checks.base import Check
from cra_check.report import CheckResult

CONFIG_GLOBS = ["*.yml", "*.yaml", "*.env", "*.env.example"]
INSECURE_PATTERNS = [
    re.compile(r"password\s*[:=]\s*['\"]?(admin|password|changeme|123456)\b['\"]?", re.IGNORECASE),
    re.compile(r"secret\s*[:=]\s*['\"]?(changeme|secret|default)\b['\"]?", re.IGNORECASE),
]


class DefaultSecureConfigCheck(Check):
    id = "default_secure_config"
    title = "Default Secure Configuration"
    annex_ref = "Annex I, Part I, 2(3)(b)"
    weight = 1

    def run(self, ctx) -> CheckResult:
        if ctx.repo_path is None:
            return CheckResult(self.id, self.title, self.annex_ref, "not_applicable", "No repository available to check for default configuration values.")

        offenders = []
        for pattern_glob in CONFIG_GLOBS:
            for path in ctx.repo_path.rglob(pattern_glob):
                if ".git" in path.parts:
                    continue
                try:
                    text = path.read_text(errors="ignore")
                except OSError:
                    continue
                if any(pattern.search(text) for pattern in INSECURE_PATTERNS):
                    offenders.append(str(path.relative_to(ctx.repo_path)))

        if not offenders:
            return CheckResult(self.id, self.title, self.annex_ref, "pass", "No obviously insecure default credentials found in config files.")
        return CheckResult(
            self.id, self.title, self.annex_ref, "warn",
            f"Possible insecure default credentials found in: {', '.join(offenders)}.",
        )
