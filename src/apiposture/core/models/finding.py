"""Security finding model."""

from dataclasses import dataclass

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import Severity


@dataclass
class Finding:
    """Represents a security finding for an endpoint."""

    # Rule ID (e.g., "AP001")
    rule_id: str

    # Rule name
    rule_name: str

    # Finding severity
    severity: Severity

    # Human-readable message
    message: str

    # The endpoint this finding relates to
    endpoint: Endpoint

    # Recommendation for fixing the issue
    recommendation: str = ""

    # Whether this finding is suppressed by configuration
    suppressed: bool = False

    # Suppression reason (if suppressed)
    suppression_reason: str = ""

    @property
    def location(self) -> str:
        """Get a display string for the finding location."""
        return self.endpoint.location

    @property
    def route(self) -> str:
        """Get the endpoint route."""
        return self.endpoint.full_route

    def to_dict(self) -> dict[str, object]:
        """Convert to a dictionary for JSON serialization."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "message": self.message,
            "recommendation": self.recommendation,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "endpoint": {
                "route": self.endpoint.full_route,
                "methods": [m.value for m in self.endpoint.methods],
                "file_path": str(self.endpoint.file_path),
                "line_number": self.endpoint.line_number,
                "framework": self.endpoint.framework.value,
                "function_name": self.endpoint.function_name,
                "class_name": self.endpoint.class_name,
                "classification": self.endpoint.classification.value,
            },
        }
