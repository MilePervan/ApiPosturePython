"""Base class for security rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import Severity
from apiposture.core.models.finding import Finding

# Route segments and function names for endpoints that are intentionally public
# by design.  Covers two categories:
#
#   Authentication entry points — these endpoints ARE the auth mechanism and
#   must accept unauthenticated requests (login, register, OAuth flows, etc.).
#
#   Infrastructure / operational endpoints — publicly accessible by cloud-native
#   convention so that load balancers, orchestrators (Kubernetes liveness /
#   readiness probes), and monitoring systems can reach them without credentials.
#
# Rules use is_known_public_endpoint() to skip these endpoints rather than
# reporting them as security findings.
KNOWN_PUBLIC_ROUTE_SEGMENTS: frozenset[str] = frozenset(
    {
        # --- Authentication entry points ---
        "login",
        "signin",
        "sign-in",
        "sign_in",
        "logout",
        "signout",
        "sign-out",
        "sign_out",
        "register",
        "signup",
        "sign-up",
        "sign_up",
        "token",  # OAuth2 token endpoint
        "authorize",  # OAuth2 authorization endpoint
        "callback",  # OAuth2 / SSO callback
        "verify",  # Email / account verification
        "confirm",  # Account confirmation
        "reset-password",
        "reset_password",
        "forgot-password",
        "forgot_password",
        "password-recovery",
        "password_recovery",
        "request-verify",
        "request_verify",
        "webhook",  # Externally-called; typically uses its own HMAC / token auth
        # --- Infrastructure / operational endpoints ---
        "health",  # Health check (K8s liveness / readiness probes, load balancers)
        "healthz",  # K8s-style abbreviated health endpoint
        "health-check",
        "health_check",
        "ping",  # Simple connectivity probe
        "alive",  # Liveness probe
        "ready",  # Readiness probe
        "readiness",
        "liveness",
    }
)


def is_known_public_endpoint(endpoint: Endpoint) -> bool:
    """Return True if this endpoint is a well-known intentionally public route.

    Matches against both the full route path and the function name so that
    non-standard URL layouts (e.g. ``/api/v1/auth`` with function ``login``)
    are also recognised.
    """
    route_lower = endpoint.full_route.lower()
    func_lower = (endpoint.function_name or "").lower()
    return any(
        segment in route_lower or segment in func_lower
        for segment in KNOWN_PUBLIC_ROUTE_SEGMENTS
    )


class SecurityRule(ABC):
    """Base class for security rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier (e.g., 'AP001')."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable rule name."""
        ...

    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Default severity level."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Rule description."""
        ...

    @abstractmethod
    def evaluate(self, endpoint: Endpoint) -> Iterator[Finding]:
        """
        Evaluate the rule against an endpoint.

        Args:
            endpoint: The endpoint to evaluate

        Yields:
            Findings for any violations
        """
        ...

    def create_finding(
        self,
        endpoint: Endpoint,
        message: str,
        recommendation: str = "",
        severity: Severity | None = None,
    ) -> Finding:
        """Helper to create a finding with standard fields."""
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=severity or self.severity,
            message=message,
            endpoint=endpoint,
            recommendation=recommendation or self._default_recommendation(),
        )

    def _default_recommendation(self) -> str:
        """Default recommendation for this rule."""
        return ""
