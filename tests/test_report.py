from cra_check.report import CheckResult, Report, compute_score


def test_all_pass_scores_100():
    results = [
        CheckResult("a", "A", "ref", "pass", "ok"),
        CheckResult("b", "B", "ref", "pass", "ok"),
    ]
    weights = {"a": 1, "b": 1}
    score, band, evaluated, total = compute_score(results, weights)
    assert score == 100.0
    assert band == "Strong"
    assert evaluated == 2
    assert total == 2


def test_not_applicable_excluded_from_denominator():
    results = [
        CheckResult("a", "A", "ref", "pass", "ok"),
        CheckResult("b", "B", "ref", "not_applicable", "skip"),
    ]
    weights = {"a": 1, "b": 5}
    score, band, evaluated, total = compute_score(results, weights)
    assert score == 100.0
    assert evaluated == 1
    assert total == 2


def test_error_excluded_from_denominator():
    results = [
        CheckResult("a", "A", "ref", "pass", "ok"),
        CheckResult("b", "B", "ref", "error", "osv.dev network failure"),
    ]
    weights = {"a": 1, "b": 5}
    score, band, evaluated, total = compute_score(results, weights)
    assert score == 100.0
    assert evaluated == 1
    assert total == 2


def test_warn_counts_as_half_credit():
    results = [
        CheckResult("a", "A", "ref", "warn", "meh"),
    ]
    weights = {"a": 1}
    score, band, evaluated, total = compute_score(results, weights)
    assert score == 50.0
    assert band == "Partial"


def test_fail_counts_as_zero_credit_weighted():
    results = [
        CheckResult("a", "A", "ref", "pass", "ok"),
        CheckResult("b", "B", "ref", "fail", "bad"),
    ]
    weights = {"a": 1, "b": 3}
    score, band, evaluated, total = compute_score(results, weights)
    assert score == 25.0
    assert band == "Weak"


def test_empty_results_scores_zero():
    score, band, evaluated, total = compute_score([], {})
    assert score == 0.0
    assert band == "Weak"
    assert evaluated == 0
    assert total == 0


def test_report_is_constructible():
    report = Report(results=[], score=0.0, band="Weak", checks_evaluated=0, checks_total=0)
    assert report.score == 0.0
