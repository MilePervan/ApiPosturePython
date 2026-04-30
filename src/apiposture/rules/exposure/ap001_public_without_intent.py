"""AP001: Public endpoint without explicit intent."""

from collections.abc import Iterator

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import SecurityClassification, Severity
from apiposture.core.models.finding import Finding
from apiposture.rules.base import SecurityRule, is_known_public_endpoint


class AP001PublicWithoutIntent(SecurityRule):
    """
    AP001: Public endpoint without explicit intent.

    Triggers when an endpoint is public (no authentication) but doesn't have
    an explicit marker indicating this is intentional (e.g., AllowAny, AllowAnonymous).
    """

    @property
    def rule_id(self) -> str:
        return "AP001"

    @property
    def name(self) -> str:
        return "Public without explicit intent"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "Public endpoint without explicit authorization intent. "
            "Endpoints should explicitly declare their authorization requirements."
        )

    def evaluate(self, endpoint: Endpoint) -> Iterator[Finding]:
        """Check if endpoint is public without explicit AllowAnonymous/AllowAny."""
        if endpoint.classification != SecurityClassification.PUBLIC:
            return

        # "/public/" as a URL path segment is a developer convention signalling
        # intentional public access (e.g. /api/public/files). Don't flag these.
        route = endpoint.full_route.lower()
        if "/public/" in route or route.startswith("/public"):
            return

        # Well-known intentionally public endpoints (auth entry points and
        # infrastructure probes) are exempt — flagging them produces noise
        # without actionable security value.
        if is_known_public_endpoint(endpoint):
            return

        auth = endpoint.authorization

        # If explicitly marked as anonymous/public, this is intentional
        if auth.allows_anonymous:
            return

        # If there's any auth configuration at all, skip
        if auth.requires_auth or auth.auth_dependencies or auth.has_specific_requirements:
            return

        yield self.create_finding(
            endpoint,
            message=(
                f"Endpoint '{endpoint.full_route}' is public without "
                "explicit authorization intent"
            ),
            recommendation=(
                "Add explicit authorization: use AllowAny (DRF), "
                "or document why no authentication is needed"
            ),
        )
