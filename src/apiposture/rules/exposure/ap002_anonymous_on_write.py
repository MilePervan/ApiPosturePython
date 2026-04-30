"""AP002: AllowAnonymous on write endpoint."""

from collections.abc import Iterator

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import Severity
from apiposture.core.models.finding import Finding
from apiposture.rules.base import SecurityRule


class AP002AnonymousOnWrite(SecurityRule):
    """
    AP002: AllowAnonymous on write endpoint.

    Triggers when an endpoint that handles write operations (POST, PUT, DELETE, PATCH)
    explicitly allows anonymous access.
    """

    @property
    def rule_id(self) -> str:
        return "AP002"

    @property
    def name(self) -> str:
        return "Anonymous access on write endpoint"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "Write endpoints (POST, PUT, DELETE, PATCH) with explicit anonymous access. "
            "This can allow unauthorized data modification."
        )

    def evaluate(self, endpoint: Endpoint) -> Iterator[Finding]:
        """Check if write endpoint allows anonymous access."""
        # Only check write endpoints
        if not endpoint.is_write_endpoint:
            return

        # Only flag if explicitly allowing anonymous
        if not endpoint.authorization.allows_anonymous:
            return

        yield self.create_finding(
            endpoint,
            message=(
                f"Write endpoint '{endpoint.full_route}' [{endpoint.display_methods}] "
                f"explicitly allows anonymous access"
            ),
            recommendation=(
                "Remove AllowAnonymous/AllowAny from write endpoints, "
                "or add rate limiting and validation if public access is required"
            ),
        )
