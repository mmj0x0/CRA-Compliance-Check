import json
from dataclasses import asdict
from pathlib import Path


def render_json(report, path: str) -> dict:
    data = {
        "score": report.score,
        "band": report.band,
        "checks_evaluated": report.checks_evaluated,
        "checks_total": report.checks_total,
        "results": [asdict(result) for result in report.results],
    }
    Path(path).write_text(json.dumps(data, indent=2))
    return data
