import re

from cra_check.checks.base import Check
from cra_check.report import CheckResult

UPDATE_CONFIG_FILES = [".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", ".renovaterc.json"]
RELEASE_KEYWORD = re.compile(r"\brelease\b", re.IGNORECASE)


class SecureUpdateMechanismCheck(Check):
    id = "secure_update_mechanism"
    title = "Secure Update Mechanism Signals"
    annex_ref = "Annex I, Part I, 2(3)"
    weight = 2

    def run(self, ctx) -> CheckResult:
        if ctx.repo_path is None:
            return CheckResult(self.id, self.title, self.annex_ref, "not_applicable", "No repository available to check for update mechanism signals.")

        for rel in UPDATE_CONFIG_FILES:
            if (ctx.repo_path / rel).is_file():
                return CheckResult(self.id, self.title, self.annex_ref, "pass", f"Found automated dependency update config at {rel}.")

        workflows_dir = ctx.repo_path / ".github" / "workflows"
        if workflows_dir.is_dir():
            for workflow in sorted(workflows_dir.glob("*.y*ml")):
                try:
                    text = workflow.read_text(errors="ignore")
                except OSError:
                    continue
                if RELEASE_KEYWORD.search(text):
                    return CheckResult(
                        self.id, self.title, self.annex_ref, "pass",
                        f"Found release automation in {workflow.relative_to(ctx.repo_path)}.",
                    )

        return CheckResult(self.id, self.title, self.annex_ref, "warn", "No automated dependency update config or release workflow found.")
