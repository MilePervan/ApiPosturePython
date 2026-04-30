"""AP008: Endpoint without authentication."""

from collections.abc import Iterator

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import Framework, SecurityClassification, Severity
from apiposture.core.models.finding import Finding
from apiposture.rules.base import SecurityRule, is_known_public_endpoint


class AP008EndpointWithoutAuth(SecurityRule):
    """
    AP008: Endpoint without authentication.

    Triggers for endpoints that have no authentication configuration,
    particularly focused on FastAPI endpoints missing Depends/Security.
    """

    @property
    def rule_id(self) -> str:
        return "AP008"

    @property
    def name(self) -> str:
        return "Endpoint without authentication"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def description(self) -> str:
        return (
            "Endpoint has no authentication configuration. "
            "Consider adding authentication dependencies."
        )

    def evaluate(self, endpoint: Endpoint) -> Iterator[Finding]:
        """Check if endpoint lacks authentication."""
        # Only check public endpoints
        if endpoint.classification != SecurityClassification.PUBLIC:
            return

        # Skip if explicitly allowing anonymous
        if endpoint.authorization.allows_anonymous:
            return

        # Well-known intentionally public endpoints (auth entry points and
        # infrastructure probes) are exempt — they have no auth by design.
        if is_known_public_endpoint(endpoint):
            return

        auth = endpoint.authorization

        # Check if there's any auth configuration
        if auth.requires_auth or auth.auth_dependencies or auth.has_specific_requirements:
            return

        # Framework-specific messages
        if endpoint.framework == Framework.FASTAPI:
            recommendation = (
                "Add authentication: use Depends(get_current_user) or "
                "Security(oauth2_scheme) to protect this endpoint"
            )
        elif endpoint.framework == Framework.FLASK:
            recommendation = (
                "Add authentication: use @login_required (flask-login) or "
                "@jwt_required() (flask-jwt-extended)"
            )
        elif endpoint.framework == Framework.DJANGO_DRF:
            recommendation = (
                "Add authentication: set permission_classes = [IsAuthenticated] "
                "on the view class or use @permission_classes decorator"
            )
        else:
            recommendation = "Add authentication to protect this endpoint"

        yield self.create_finding(
            endpoint,
            message=f"Endpoint '{endpoint.full_route}' has no authentication configuration",
            recommendation=recommendation,
        )
