"""Tests for exposure rules (AP001, AP002)."""

from pathlib import Path

import pytest

from apiposture.core.models.authorization import AuthorizationInfo
from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import (
    EndpointType,
    Framework,
    HttpMethod,
    SecurityClassification,
)
from apiposture.rules.exposure.ap001_public_without_intent import AP001PublicWithoutIntent
from apiposture.rules.exposure.ap002_anonymous_on_write import AP002AnonymousOnWrite


@pytest.fixture
def public_endpoint():
    """Create a public endpoint fixture."""
    return Endpoint(
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


@pytest.fixture
def authenticated_endpoint():
    """Create an authenticated endpoint fixture."""
    return Endpoint(
        route="/users",
        methods=[HttpMethod.GET],
        file_path=Path("test.py"),
        line_number=10,
        framework=Framework.FASTAPI,
        endpoint_type=EndpointType.FUNCTION,
        function_name="get_users",
        authorization=AuthorizationInfo(
            requires_auth=True,
            auth_dependencies=["get_current_user"],
        ),
        classification=SecurityClassification.AUTHENTICATED,
    )


class TestAP001PublicWithoutIntent:
    """Tests for AP001 rule."""

    def test_triggers_on_public_without_explicit_intent(self, public_endpoint):
        """Test that rule triggers on public endpoint without AllowAnonymous."""
        rule = AP001PublicWithoutIntent()
        findings = list(rule.evaluate(public_endpoint))

        assert len(findings) == 1
        assert findings[0].rule_id == "AP001"

    def test_does_not_trigger_on_explicit_allow_anonymous(self, public_endpoint):
        """Test that rule doesn't trigger when AllowAnonymous is explicit."""
        public_endpoint.authorization = AuthorizationInfo(allows_anonymous=True)

        rule = AP001PublicWithoutIntent()
        findings = list(rule.evaluate(public_endpoint))

        assert len(findings) == 0

    def test_does_not_trigger_on_authenticated(self, authenticated_endpoint):
        """Test that rule doesn't trigger on authenticated endpoint."""
        rule = AP001PublicWithoutIntent()
        findings = list(rule.evaluate(authenticated_endpoint))

        assert len(findings) == 0


class TestAP002AnonymousOnWrite:
    """Tests for AP002 rule."""

    def test_triggers_on_post_with_allow_anonymous(self):
        """Test that rule triggers on POST with AllowAnonymous."""
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

        rule = AP002AnonymousOnWrite()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 1
        assert findings[0].rule_id == "AP002"

    def test_triggers_on_delete_with_allow_anonymous(self):
        """Test that rule triggers on DELETE with AllowAnonymous."""
        endpoint = Endpoint(
            route="/users/{id}",
            methods=[HttpMethod.DELETE],
            file_path=Path("test.py"),
            line_number=10,
            framework=Framework.FASTAPI,
            endpoint_type=EndpointType.FUNCTION,
            function_name="delete_user",
            authorization=AuthorizationInfo(allows_anonymous=True),
            classification=SecurityClassification.PUBLIC,
        )

        rule = AP002AnonymousOnWrite()
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
            authorization=AuthorizationInfo(allows_anonymous=True),
            classification=SecurityClassification.PUBLIC,
        )

        rule = AP002AnonymousOnWrite()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 0

    def test_does_not_trigger_without_allow_anonymous(self):
        """Test that rule doesn't trigger without AllowAnonymous."""
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

        rule = AP002AnonymousOnWrite()
        findings = list(rule.evaluate(endpoint))

        assert len(findings) == 0
