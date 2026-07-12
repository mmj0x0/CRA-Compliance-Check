from rich.console import Console

from cra_check.report import CheckResult, Report
from cra_check.renderers.terminal import render_terminal


def _make_report():
    results = [
        CheckResult("a", "Check A", "ref-a", "pass", "all good"),
        CheckResult("b", "Check B", "ref-b", "warn", "needs attention"),
        CheckResult("c", "Check C", "ref-c", "fail", "broken"),
        CheckResult("d", "Check D", "ref-d", "not_applicable", "skipped"),
    ]
    return Report(results=results, score=62.5, band="Partial", checks_evaluated=3, checks_total=4)


def test_render_terminal_shows_all_by_default():
    console = Console(record=True, width=120)
    render_terminal(_make_report(), console=console)
    output = console.export_text()
    assert "Check A" in output
    assert "Check B" in output
    assert "Check C" in output
    assert "Check D" in output
    assert "62.5/100" in output
    assert "Partial" in output


def test_render_terminal_severity_threshold_warn_hides_pass():
    console = Console(record=True, width=120)
    render_terminal(_make_report(), severity_threshold="warn", console=console)
    output = console.export_text()
    assert "Check A" not in output
    assert "Check B" in output
    assert "Check C" in output


def test_render_terminal_severity_threshold_fail_hides_pass_and_warn():
    console = Console(record=True, width=120)
    render_terminal(_make_report(), severity_threshold="fail", console=console)
    output = console.export_text()
    assert "Check A" not in output
    assert "Check B" not in output
    assert "Check C" in output


def test_render_terminal_does_not_mutate_score():
    report = _make_report()
    render_terminal(report, severity_threshold="fail", console=Console(record=True, width=120))
    assert report.score == 62.5


def test_render_terminal_escapes_bracket_markup_in_message():
    results = [
        CheckResult("a", "Check A", "ref-a", "warn", "Found issues in: models[v2].py"),
    ]
    report = Report(results=results, score=50.0, band="Partial", checks_evaluated=1, checks_total=1)
    console = Console(record=True, width=120)
    render_terminal(report, console=console)  # should not raise MarkupError
    output = console.export_text()
    assert "Found issues in: models[v2].py" in output
