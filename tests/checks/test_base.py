import pytest
from cra_check.checks.base import Check
from cra_check.report import CheckResult


def test_check_is_abstract():
    with pytest.raises(TypeError):
        Check()


def test_concrete_check_must_implement_run():
    class Incomplete(Check):
        id = "x"
        title = "X"
        annex_ref = "ref"

    with pytest.raises(TypeError):
        Incomplete()


def test_concrete_check_works():
    class Concrete(Check):
        id = "x"
        title = "X"
        annex_ref = "ref"
        weight = 2

        def run(self, ctx):
            return CheckResult(self.id, self.title, self.annex_ref, "pass", "ok")

    check = Concrete()
    result = check.run(None)
    assert result.status == "pass"
    assert check.weight == 2
