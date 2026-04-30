"""AP005: Excessive role access."""

from collections.abc import Iterator

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import Severity
from apiposture.core.models.finding import Finding
from apiposture.rules.base import SecurityRule

# Maximum number of roles before triggering
MAX_ROLES = 3


class AP005ExcessiveRoles(SecurityRule):
    """
    AP005: Excessive role access.

    Triggers when an endpoint allows access to more than 3 roles,
    suggesting the authorization model may be too permissive.
    """

    @property
    def rule_id(self) -> str:
        return "AP005"

    @property
    def name(self) -> str:
        return "Excessive role access"

    @property
    def severity(self) -> Severity:
        return Severity.LOW

    @property
    def description(self) -> str:
        return (
            f"Endpoint allows access to more than {MAX_ROLES} roles. "
            "Consider consolidating roles or using permission-based access."
        )

    def evaluate(self, endpoint: Endpoint) -> Iterator[Finding]:
        """Check if endpoint has too many roles."""
        roles = endpoint.authorization.roles

        if len(roles) > MAX_ROLES:
            yield self.create_finding(
                endpoint,
                message=(
                    f"Endpoint '{endpoint.full_route}' allows {len(roles)} roles: "
                    f"{', '.join(roles)}"
                ),
                recommendation=(
                    "Consider consolidating roles into a single role, "
                    "or use permission-based authorization instead"
                ),
            )
