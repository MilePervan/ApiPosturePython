"""Rule engine for evaluating security rules against endpoints."""

from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.finding import Finding
from apiposture.rules.base import SecurityRule
from apiposture.rules.consistency.ap003_auth_conflict import AP003AuthConflict
from apiposture.rules.consistency.ap004_missing_auth_writes import AP004MissingAuthWrites
from apiposture.rules.exposure.ap001_public_without_intent import AP001PublicWithoutIntent
from apiposture.rules.exposure.ap002_anonymous_on_write import AP002AnonymousOnWrite
from apiposture.rules.privilege.ap005_excessive_roles import AP005ExcessiveRoles
from apiposture.rules.privilege.ap006_weak_role_naming import AP006WeakRoleNaming
from apiposture.rules.surface.ap007_sensitive_keywords import AP007SensitiveKeywords
from apiposture.rules.surface.ap008_endpoint_without_auth import AP008EndpointWithoutAuth


class RuleEngine:
    """Engine for evaluating security rules against endpoints."""

    def __init__(self, enabled_rules: list[str] | None = None) -> None:
        """
        Initialize the rule engine.

        Args:
            enabled_rules: List of rule IDs to enable. If None, all rules are enabled.
        """
        self._all_rules: list[SecurityRule] = [
            AP001PublicWithoutIntent(),
            AP002AnonymousOnWrite(),
            AP003AuthConflict(),
            AP004MissingAuthWrites(),
            AP005ExcessiveRoles(),
            AP006WeakRoleNaming(),
            AP007SensitiveKeywords(),
            AP008EndpointWithoutAuth(),
        ]

        if enabled_rules is not None:
            self._rules = [r for r in self._all_rules if r.rule_id in enabled_rules]
        else:
            self._rules = self._all_rules

    @property
    def rules(self) -> list[SecurityRule]:
        """Get all enabled rules."""
        return self._rules

    def evaluate(self, endpoint: Endpoint) -> list[Finding]:
        """
        Evaluate all enabled rules against an endpoint.

        Args:
            endpoint: The endpoint to evaluate

        Returns:
            List of findings from all rules
        """
        findings: list[Finding] = []
        for rule in self._rules:
            for finding in rule.evaluate(endpoint):
                findings.append(finding)
        return findings

    def evaluate_all(self, endpoints: list[Endpoint]) -> list[Finding]:
        """
        Evaluate all enabled rules against all endpoints.

        Args:
            endpoints: List of endpoints to evaluate

        Returns:
            List of all findings
        """
        findings: list[Finding] = []
        for endpoint in endpoints:
            findings.extend(self.evaluate(endpoint))
        return findings

    def get_rule(self, rule_id: str) -> SecurityRule | None:
        """Get a rule by its ID."""
        for rule in self._all_rules:
            if rule.rule_id == rule_id:
                return rule
        return None
