"""Security classification logic for endpoints."""

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import SecurityClassification


class SecurityClassifier:
    """Classifies endpoints based on their authorization configuration."""

    def classify(self, endpoint: Endpoint) -> SecurityClassification:
        """
        Determine the security classification of an endpoint.

        Classifications:
        - PUBLIC: No authorization required (AllowAnonymous or no auth)
        - AUTHENTICATED: Requires authentication but no specific roles/permissions
        - ROLE_RESTRICTED: Requires specific roles
        - POLICY_RESTRICTED: Requires specific policies/permissions/scopes
        """
        auth = endpoint.authorization

        # Check if explicitly public
        if auth.allows_anonymous:
            return SecurityClassification.PUBLIC

        # Check if no auth required
        if not auth.requires_auth and not auth.has_specific_requirements:
            return SecurityClassification.PUBLIC

        # Check for policy/permission restrictions
        if auth.policies or auth.permissions or auth.scopes:
            return SecurityClassification.POLICY_RESTRICTED

        # Check for role restrictions
        if auth.roles:
            return SecurityClassification.ROLE_RESTRICTED

        # Has auth but no specific requirements
        if auth.requires_auth or auth.auth_dependencies:
            return SecurityClassification.AUTHENTICATED

        return SecurityClassification.PUBLIC

    def classify_all(self, endpoints: list[Endpoint]) -> None:
        """Classify all endpoints in place."""
        for endpoint in endpoints:
            endpoint.classification = self.classify(endpoint)
