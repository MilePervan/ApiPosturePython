"""Tests for consistency rules (AP003, AP004)."""

from pathlib import Path

from apiposture.core.models.authorization import AuthorizationInfo
from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import (
    EndpointType,
    Framework,
    HttpMethod,
    SecurityClassification,
)
from apiposture.rules.consistency.ap003_auth_conflict import AP003AuthConflict
from apiposture.rules.consistency.ap004_missing_auth_writes import AP004MissingAuthWrites


class TestAP003AuthConflict:
    """Tests for AP003 rule."""

    def test_triggers_on_class_method_conflict(self):
        """Test that rule triggers when method overrides class auth."""
        endpoint = Endpoint(
            route="/users",
            methods=[HttpMethod.GET],
            file_path=Path("test.py"),
            line_number=10,
            framework=Framework.DJANGO_DRF,
            endpoint_type=EndpointType.CONTROLLER_ACTION,
            function_name="get",
            class_name="UserView",
            authorization=AuthorizationInfo(
                allows_anonymous=True,
                inherited=True,  # Indicates it was inherited but overridden
                source="method",
            ),
            classification=SecurityClassification.PUBLIC,
        )

        rule = AP003AuthConflict()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 1
        assert findings[0].rule_id == "AP003"

    def test_does_not_trigger_on_function_endpoint(self):
        """Test that rule doesn't trigger on function-based views."""
        endpoint = Endpoint(
            route="/users",
            methods=[HttpMethod.GET],
            file_path=Path("test.py"),
            line_number=10,
            framework=Framework.FASTAPI,
            endpoint_type=EndpointType.FUNCTION,
            function_name="get_users",
            authorization=AuthorizationInfo(allows_anonymous=True),
            classification=SecurityClassification.PUBLIC,
        )

        rule = AP003AuthConflict()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 0

    def test_does_not_trigger_without_inherited_auth(self):
        """Test that rule doesn't trigger when no inherited auth."""
        endpoint = Endpoint(
            route="/users",
            methods=[HttpMethod.GET],
            file_path=Path("test.py"),
            line_number=10,
            framework=Framework.DJANGO_DRF,
            endpoint_type=EndpointType.CONTROLLER_ACTION,
            function_name="get",
            class_name="UserView",
            authorization=AuthorizationInfo(
                allows_anonymous=True,
                inherited=False,
                source="method",
            ),
            classification=SecurityClassification.PUBLIC,
        )

        rule = AP003AuthConflict()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 0


class TestAP004MissingAuthWrites:
    """Tests for AP004 rule."""

    def test_triggers_on_unprotected_post(self):
        """Test that rule triggers on POST without auth."""
        endpoint = Endpoint(
            route="/users",
            methods=[HttpMethod.POST],
            file_path=Path("test.py"),
            line_number=10,
            framework=Framework.FASTAPI,
            endpoint_type=EndpointType.FUNCTION,
            function_name="create_user",
            authorization=AuthorizationInfo(),
            classification=SecurityClassification.PUBLIC,
        )

        rule = AP004MissingAuthWrites()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 1
        assert findings[0].rule_id == "AP004"
        assert findings[0].severity.value == "critical"

    def test_triggers_on_unprotected_delete(self):
        """Test that rule triggers on DELETE without auth."""
        endpoint = Endpoint(
            route="/users/{id}",
            methods=[HttpMethod.DELETE],
            file_path=Path("test.py"),
            line_number=10,
            framework=Framework.FASTAPI,
            endpoint_type=EndpointType.FUNCTION,
            function_name="delete_user",
            authorization=AuthorizationInfo(),
            classification=SecurityClassification.PUBLIC,
        )

        rule = AP004MissingAuthWrites()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 1

    def test_does_not_trigger_on_get(self):
        """Test that rule doesn't trigger on GET endpoint."""
        endpoint = Endpoint(
            route="/users",
            methods=[HttpMethod.GET],
            file_path=Path("test.py"),
            line_number=10,
            framework=Framework.FASTAPI,
            endpoint_type=EndpointType.FUNCTION,
            function_name="get_users",
            authorization=AuthorizationInfo(),
            classification=SecurityClassification.PUBLIC,
        )

        rule = AP004MissingAuthWrites()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 0

    def test_does_not_trigger_on_protected_post(self):
        """Test that rule doesn't trigger on protected POST."""
        endpoint = Endpoint(
            route="/users",
            methods=[HttpMethod.POST],
            file_path=Path("test.py"),
            line_number=10,
            framework=Framework.FASTAPI,
            endpoint_type=EndpointType.FUNCTION,
            function_name="create_user",
            authorization=AuthorizationInfo(
                requires_auth=True,
                auth_dependencies=["get_current_user"],
            ),
            classification=SecurityClassification.AUTHENTICATED,
        )

        rule = AP004MissingAuthWrites()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 0

    def test_does_not_trigger_on_explicit_allow_anonymous(self):
        """Test that rule doesn't trigger on explicit AllowAnonymous (AP002 handles this)."""
        endpoint = Endpoint(
            route="/users",
            methods=[HttpMethod.POST],
            file_path=Path("test.py"),
            line_number=10,
            framework=Framework.FASTAPI,
            endpoint_type=EndpointType.FUNCTION,
            function_name="create_user",
            authorization=AuthorizationInfo(allows_anonymous=True),
            classification=SecurityClassification.PUBLIC,
        )

        rule = AP004MissingAuthWrites()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 0
