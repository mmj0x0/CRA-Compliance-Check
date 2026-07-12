from cra_check.report import CheckResult, Report, compute_score


def run_checks(checks: list, ctx) -> Report:
    results = []
    for check in checks:
        try:
            result = check.run(ctx)
        except Exception as exc:  # noqa: BLE001 — intentional: isolate any check failure
            result = CheckResult(
                check_id=check.id,
                title=check.title,
                annex_ref=check.annex_ref,
                status="error",
                message=f"Check raised an exception: {exc}",
            )
        results.append(result)

    weights = {check.id: check.weight for check in checks}
    score, band, evaluated, total = compute_score(results, weights)
    return Report(results=results, score=score, band=band, checks_evaluated=evaluated, checks_total=total)
