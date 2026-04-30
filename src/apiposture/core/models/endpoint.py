"""Endpoint model representing a discovered API endpoint."""

from dataclasses import dataclass, field
from pathlib import Path

from apiposture.core.models.authorization import AuthorizationInfo
from apiposture.core.models.enums import (
    EndpointType,
    Framework,
    HttpMethod,
    SecurityClassification,
)


@dataclass
class Endpoint:
    """Represents a discovered API endpoint."""

    # Route path (e.g., "/api/users/{id}")
    route: str

    # HTTP method(s) this endpoint handles
    methods: list[HttpMethod]

    # Source file path
    file_path: Path

    # Line number where the endpoint is defined
    line_number: int

    # Framework that defines this endpoint
    framework: Framework

    # Type of endpoint definition
    endpoint_type: EndpointType

    # Name of the function/method
    function_name: str

    # Name of the class (for class-based views)
    class_name: str | None = None

    # Authorization information
    authorization: AuthorizationInfo = field(default_factory=AuthorizationInfo)

    # Security classification (computed)
    classification: SecurityClassification = SecurityClassification.PUBLIC

    # Router/blueprint prefix (if any)
    router_prefix: str = ""

    # Tags for grouping (FastAPI tags, etc.)
    tags: list[str] = field(default_factory=list)

    # Additional metadata
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def full_route(self) -> str:
        """Get the full route including router prefix."""
        if self.router_prefix:
            prefix = self.router_prefix.rstrip("/")
            route = self.route if self.route.startswith("/") else f"/{self.route}"
            return f"{prefix}{route}"
        return self.route

    @property
    def display_methods(self) -> str:
        """Get a display string for the HTTP methods."""
        return ", ".join(m.value for m in self.methods)

    @property
    def location(self) -> str:
        """Get a display string for the file location."""
        return f"{self.file_path}:{self.line_number}"

    @property
    def is_write_endpoint(self) -> bool:
        """Check if this endpoint handles any write methods."""
        return any(m.is_write_method() for m in self.methods)

    def __hash__(self) -> int:
        """Hash based on route, methods, and file location."""
        methods_tuple = tuple(sorted(m.value for m in self.methods))
        return hash((self.route, methods_tuple, str(self.file_path), self.line_number))

    def __eq__(self, other: object) -> bool:
        """Equality based on route, methods, and file location."""
        if not isinstance(other, Endpoint):
            return False
        return (
            self.route == other.route
            and set(self.methods) == set(other.methods)
            and self.file_path == other.file_path
            and self.line_number == other.line_number
        )
