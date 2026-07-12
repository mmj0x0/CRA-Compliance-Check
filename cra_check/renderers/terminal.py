from rich.console import Console
from rich.table import Table

STATUS_RANK = {"not_applicable": 0, "pass": 0, "warn": 1, "fail": 2, "error": 2}
THRESHOLD_RANK = {"pass": 0, "warn": 1, "fail": 2}
STATUS_STYLES = {"pass": "green", "warn": "yellow", "fail": "red", "error": "red bold", "not_applicable": "dim"}
STATUS_LABELS = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "error": "ERROR", "not_applicable": "N/A"}


def render_terminal(report, severity_threshold: str = "pass", console=None) -> Console:
    console = console or Console()
    min_rank = THRESHOLD_RANK.get(severity_threshold, 0)

    table = Table(title="CRA Compliance Report")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Annex Ref")
    table.add_column("Message")

    for result in report.results:
        if STATUS_RANK[result.status] < min_rank:
            continue
        style = STATUS_STYLES[result.status]
        table.add_row(result.title, f"[{style}]{STATUS_LABELS[result.status]}[/{style}]", result.annex_ref, result.message)

    console.print(table)
    console.print(f"\nOverall score: {report.score}/100 ({report.band}) - {report.checks_evaluated}/{report.checks_total} checks evaluated")
    return console
