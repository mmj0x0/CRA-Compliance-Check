from dataclasses import dataclass


@dataclass
class CheckResult:
    check_id: str
    title: str
    annex_ref: str
    status: str  # "pass" | "fail" | "warn" | "not_applicable" | "error"
    message: str
    evidence: str = ""


@dataclass
class Report:
    results: list
    score: float
    band: str
    checks_evaluated: int
    checks_total: int


def _band_for(score: float) -> str:
    if score >= 80:
        return "Strong"
    if score >= 50:
        return "Partial"
    return "Weak"


def compute_score(results: list, weights: dict) -> tuple:
    total_weight = 0.0
    earned_weight = 0.0
    evaluated = 0

    for result in results:
        if result.status == "not_applicable":
            continue
        evaluated += 1
        weight = weights.get(result.check_id, 1)
        total_weight += weight
        if result.status == "pass":
            earned_weight += weight
        elif result.status == "warn":
            earned_weight += weight * 0.5

    score = round((earned_weight / total_weight) * 100, 1) if total_weight else 0.0
    return score, _band_for(score), evaluated, len(results)
