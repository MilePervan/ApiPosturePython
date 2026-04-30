"""AP003: Authorization conflict between class and method."""

from collections.abc import Iterator

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import EndpointType, Severity
from apiposture.core.models.finding import Finding
from apiposture.rules.base import SecurityRule


class AP003AuthConflict(SecurityRule):
    """
    AP003: Authorization conflict between class and method.

    Triggers when a method-level AllowAnonymous overrides class-level authentication,
    potentially indicating a configuration mistake or security weakness.
    """

    @property
    def rule_id(self) -> str:
        return "AP003"

    @property
    def name(self) -> str:
        return "Class/method authorization conflict"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def description(self) -> str:
        return (
            "Method-level AllowAnonymous/AllowAny overrides class-level authentication. "
            "This may indicate a configuration mistake."
        )

    def evaluate(self, endpoint: Endpoint) -> Iterator[Finding]:
        """Check for class/method authorization conflicts."""
        # Only applies to class-based views
        if endpoint.endpoint_type != EndpointType.CONTROLLER_ACTION:
            return

        auth = endpoint.authorization

        # Check if method allows anonymous but inherited auth requires it
        if auth.allows_anonymous and auth.inherited:
            # This means class required auth but method overrode it
            yield self.create_finding(
                endpoint,
                message=(
                    f"Method '{endpoint.function_name}' in '{endpoint.class_name}' "
                    f"allows anonymous access, overriding class-level authentication"
                ),
                recommendation=(
                    "Verify this override is intentional. If the method should be public, "
                    "consider documenting why with a comment"
                ),
            )
