"""Enumerations for ApiPosture."""

from enum import Enum


class HttpMethod(str, Enum):
    """HTTP methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

    def is_write_method(self) -> bool:
        """Check if this is a write method (modifies state)."""
        return self in (HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE, HttpMethod.PATCH)


class Framework(str, Enum):
    """Supported Python API frameworks."""

    FASTAPI = "fastapi"
    FLASK = "flask"
    DJANGO_DRF = "django_drf"
    STARLETTE = "starlette"
    UNKNOWN = "unknown"


class SecurityClassification(str, Enum):
    """Security classification of an endpoint."""

    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    ROLE_RESTRICTED = "role_restricted"
    POLICY_RESTRICTED = "policy_restricted"


class Severity(str, Enum):
    """Severity level of a security finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def order(self) -> int:
        """Return numeric order for sorting (higher = more severe)."""
        order_map = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order_map[self]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.order < other.order

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.order <= other.order

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.order > other.order

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.order >= other.order


class EndpointType(str, Enum):
    """Type of endpoint definition."""

    CONTROLLER_ACTION = "controller_action"  # Class-based views
    FUNCTION = "function"  # Function-based views
    ROUTER = "router"  # Router-based (FastAPI APIRouter, Flask Blueprint)
