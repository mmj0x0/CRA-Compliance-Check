from cra_check.checks import ALL_CHECKS
from cra_check.checks.base import Check


def test_all_checks_are_check_instances():
    assert len(ALL_CHECKS) == 9
    for check in ALL_CHECKS:
        assert isinstance(check, Check)


def test_all_check_ids_are_unique():
    ids = [check.id for check in ALL_CHECKS]
    assert len(ids) == len(set(ids))


def test_expected_check_ids_present():
    ids = {check.id for check in ALL_CHECKS}
    assert ids == {
        "sbom_presence",
        "sbom_completeness",
        "known_vulnerabilities",
        "vuln_disclosure_policy",
        "secure_update_mechanism",
        "default_secure_config",
        "data_minimization",
        "security_logging",
        "support_eol_docs",
    }
