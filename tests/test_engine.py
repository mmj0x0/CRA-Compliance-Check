from cra_check.checks.base import Check
from cra_check.report import CheckResult
from cra_check.engine import run_checks


class PassingCheck(Check):
    id = "passing"
    title = "Passing"
    annex_ref = "ref"
    weight = 1

    def run(self, ctx):
        return CheckResult(self.id, self.title, self.annex_ref, "pass", "ok")


class FailingCheck(Check):
    id = "failing"
    title = "Failing"
    annex_ref = "ref"
    weight = 1

    def run(self, ctx):
        return CheckResult(self.id, self.title, self.annex_ref, "fail", "bad")


class ExplodingCheck(Check):
    id = "exploding"
    title = "Exploding"
    annex_ref = "ref"
    weight = 1

    def run(self, ctx):
        raise RuntimeError("boom")


class AnotherPassingCheck(Check):
    id = "another_passing"
    title = "Another Passing"
    annex_ref = "ref"
    weight = 1

    def run(self, ctx):
        return CheckResult(self.id, self.title, self.annex_ref, "pass", "ok")


def test_run_checks_aggregates_results():
    report = run_checks([PassingCheck(), FailingCheck()], ctx=None)
    assert len(report.results) == 2
    assert report.checks_total == 2
    statuses = {r.check_id: r.status for r in report.results}
    assert statuses == {"passing": "pass", "failing": "fail"}


def test_run_checks_isolates_exceptions():
    report = run_checks([PassingCheck(), ExplodingCheck(), AnotherPassingCheck()], ctx=None)
    assert len(report.results) == 3

    # Assert first check passed
    passing_result = next(r for r in report.results if r.check_id == "passing")
    assert passing_result.status == "pass"

    # Assert middle check was caught and isolated
    exploding_result = next(r for r in report.results if r.check_id == "exploding")
    assert exploding_result.status == "error"
    assert "boom" in exploding_result.message

    # Assert the check after the exception still ran (proves loop continued)
    another_result = next(r for r in report.results if r.check_id == "another_passing")
    assert another_result.status == "pass"


def test_run_checks_empty_list():
    report = run_checks([], ctx=None)
    assert report.results == []
    assert report.score == 0.0
