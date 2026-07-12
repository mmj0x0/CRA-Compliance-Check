from cra_check.checks.sbom_presence import SbomPresenceCheck
from cra_check.checks.sbom_completeness import SbomCompletenessCheck
from cra_check.checks.known_vulnerabilities import KnownVulnerabilitiesCheck
from cra_check.checks.vuln_disclosure_policy import VulnDisclosurePolicyCheck
from cra_check.checks.secure_update_mechanism import SecureUpdateMechanismCheck
from cra_check.checks.default_secure_config import DefaultSecureConfigCheck
from cra_check.checks.data_minimization import DataMinimizationCheck
from cra_check.checks.security_logging import SecurityLoggingCheck
from cra_check.checks.support_eol_docs import SupportEolDocsCheck

ALL_CHECKS = [
    SbomPresenceCheck(),
    SbomCompletenessCheck(),
    KnownVulnerabilitiesCheck(),
    VulnDisclosurePolicyCheck(),
    SecureUpdateMechanismCheck(),
    DefaultSecureConfigCheck(),
    DataMinimizationCheck(),
    SecurityLoggingCheck(),
    SupportEolDocsCheck(),
]
