"""AP006: Weak role naming."""

from collections.abc import Iterator

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import Severity
from apiposture.core.models.finding import Finding
from apiposture.rules.base import SecurityRule

# Generic role names that should be more specific
WEAK_ROLE_NAMES = {
    "user",
    "users",
    "admin",
    "admins",
    "guest",
    "guests",
    "member",
    "members",
    "default",
    "basic",
    "standard",
    "normal",
    "regular",
}


class AP006WeakRoleNaming(SecurityRule):
    """
    AP006: Weak role naming.

    Triggers when roles have generic names that don't convey
    specific permissions or responsibilities.
    """

    @property
    def rule_id(self) -> str:
        return "AP006"

    @property
    def name(self) -> str:
        return "Weak role naming"

    @property
    def severity(self) -> Severity:
        return Severity.LOW

    @property
    def description(self) -> str:
        return (
            "Role names are too generic. "
            "Consider using more descriptive names that indicate specific permissions."
        )

    def evaluate(self, endpoint: Endpoint) -> Iterator[Finding]:
        """Check for weak role names."""
        roles = endpoint.authorization.roles

        weak_roles = [r for r in roles if r.lower() in WEAK_ROLE_NAMES]

        if weak_roles:
            yield self.create_finding(
                endpoint,
                message=(
                    f"Endpoint '{endpoint.full_route}' uses generic role names: "
                    f"{', '.join(weak_roles)}"
                ),
                recommendation=(
                    "Use more descriptive role names that indicate permissions, "
                    "e.g., 'billing_admin', 'content_editor', 'report_viewer'"
                ),
            )
