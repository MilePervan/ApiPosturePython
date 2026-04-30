"""AP007: Sensitive route keywords."""

import re
from collections.abc import Iterator

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import SecurityClassification, Severity
from apiposture.core.models.finding import Finding
from apiposture.rules.base import SecurityRule

# Sensitive keywords in routes that suggest admin/debug functionality
SENSITIVE_KEYWORDS = {
    "admin",
    "debug",
    "internal",
    "private",
    "secret",
    "config",
    "configuration",
    "settings",
    "system",
    "management",
    "manage",
    "export",
    "import",
    "backup",
    "restore",
    "dump",
    "logs",
    "metrics",
    # NOTE: "health" intentionally omitted — health-check endpoints are public
    # by cloud-native convention (K8s liveness/readiness probes, load balancers).
    "status",
    "diagnose",
    "diagnostic",
    "test",
    "dev",
    "staging",
    "sudo",
    "superuser",
    "root",
}

# Pattern to match sensitive keywords in route paths
SENSITIVE_PATTERN = re.compile(
    r"(?:^|/)(" + "|".join(SENSITIVE_KEYWORDS) + r")(?:/|$|-|_)",
    re.IGNORECASE,
)


class AP007SensitiveKeywords(SecurityRule):
    """
    AP007: Sensitive route keywords.

    Triggers when a public endpoint's route contains keywords suggesting
    admin, debug, or internal functionality.
    """

    @property
    def rule_id(self) -> str:
        return "AP007"

    @property
    def name(self) -> str:
        return "Sensitive keywords in public route"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return (
            "Public endpoint route contains sensitive keywords suggesting "
            "admin, debug, or internal functionality."
        )

    def evaluate(self, endpoint: Endpoint) -> Iterator[Finding]:
        """Check for sensitive keywords in public routes."""
        # Only check public endpoints
        if endpoint.classification != SecurityClassification.PUBLIC:
            return

        route = endpoint.full_route.lower()

        # Find matching keywords
        matches = SENSITIVE_PATTERN.findall(route)

        if matches:
            keywords = list(set(matches))
            yield self.create_finding(
                endpoint,
                message=(
                    f"Public endpoint '{endpoint.full_route}' contains sensitive keywords: "
                    f"{', '.join(keywords)}"
                ),
                recommendation=(
                    "Verify this endpoint should be public. "
                    "Admin and debug endpoints typically require authentication."
                ),
            )
