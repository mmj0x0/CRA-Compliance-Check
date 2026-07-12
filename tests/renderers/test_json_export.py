import json

from cra_check.report import CheckResult, Report
from cra_check.renderers.json_export import render_json


def _make_report():
    results = [
        CheckResult("a", "Check A", "ref-a", "pass", "all good"),
        CheckResult("b", "Check B", "ref-b", "not_applicable", "skipped"),
    ]
    return Report(results=results, score=100.0, band="Strong", checks_evaluated=1, checks_total=2)


def test_render_json_writes_file(tmp_path):
    out_path = tmp_path / "report.json"
    data = render_json(_make_report(), str(out_path))

    assert out_path.exists()
    on_disk = json.loads(out_path.read_text())
    assert on_disk == data


def test_render_json_includes_all_results_regardless_of_filtering(tmp_path):
    out_path = tmp_path / "report.json"
    data = render_json(_make_report(), str(out_path))

    assert len(data["results"]) == 2
    assert data["score"] == 100.0
    assert data["band"] == "Strong"
    assert data["checks_evaluated"] == 1
    assert data["checks_total"] == 2


def test_render_json_result_schema(tmp_path):
    out_path = tmp_path / "report.json"
    data = render_json(_make_report(), str(out_path))

    first = data["results"][0]
    assert set(first.keys()) == {"check_id", "title", "annex_ref", "status", "message", "evidence"}
