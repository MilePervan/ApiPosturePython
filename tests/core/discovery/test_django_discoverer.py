"""Tests for Django REST Framework endpoint discoverer."""

from pathlib import Path

import pytest

from apiposture.core.discovery.django_drf import DjangoRESTFrameworkDiscoverer
from apiposture.core.models.enums import Framework, HttpMethod


@pytest.fixture
def discoverer():
    """Create a Django DRF discoverer."""
    return DjangoRESTFrameworkDiscoverer()


class TestDjangoDiscoverer:
    """Tests for DjangoRESTFrameworkDiscoverer."""

    def test_can_handle_drf_import(self, discoverer, parse_code):
        """Test that discoverer recognizes DRF imports."""
        code = """
from rest_framework.views import APIView

class UserView(APIView):
    pass
"""
        source = parse_code(code)
        assert discoverer.can_handle(source)

    def test_cannot_handle_non_drf(self, discoverer, parse_code):
        """Test that discoverer rejects non-DRF code."""
        code = """
from fastapi import FastAPI

app = FastAPI()
"""
        source = parse_code(code)
        assert not discoverer.can_handle(source)

    def test_discover_apiview_get(self, discoverer, parse_code):
        """Test discovering APIView with get method."""
        code = """
from rest_framework.views import APIView

class UserView(APIView):
    def get(self, request):
        return Response([])
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].methods == [HttpMethod.GET]
        assert endpoints[0].function_name == "get"
        assert endpoints[0].class_name == "UserView"
        assert endpoints[0].framework == Framework.DJANGO_DRF

    def test_discover_apiview_multiple_methods(self, discoverer, parse_code):
        """Test discovering APIView with multiple HTTP methods."""
        code = """
from rest_framework.views import APIView

class UserView(APIView):
    def get(self, request):
        return Response([])

    def post(self, request):
        return Response({})

    def delete(self, request, pk):
        return Response(status=204)
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 3
        methods = {e.methods[0] for e in endpoints}
        assert methods == {HttpMethod.GET, HttpMethod.POST, HttpMethod.DELETE}

    def test_discover_apiview_with_permission_classes(self, discoverer, parse_code):
        """Test discovering APIView with permission_classes."""
        code = """
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

class UserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response([])
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth
        assert "IsAuthenticated" in endpoints[0].authorization.permissions

    def test_discover_apiview_with_allowany(self, discoverer, parse_code):
        """Test discovering APIView with AllowAny permission."""
        code = """
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

class PublicView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response([])
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.allows_anonymous

    def test_discover_function_based_view(self, discoverer, parse_code):
        """Test discovering function-based view with @api_view."""
        code = """
from rest_framework.decorators import api_view

@api_view(["GET", "POST"])
def user_list(request):
    return Response([])
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert set(endpoints[0].methods) == {HttpMethod.GET, HttpMethod.POST}
        assert endpoints[0].function_name == "user_list"

    def test_discover_function_with_permission_classes(self, discoverer, parse_code):
        """Test discovering function view with @permission_classes."""
        code = """
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_detail(request):
    return Response({})
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth

    def test_discover_viewset(self, discoverer, parse_code):
        """Test discovering ModelViewSet."""
        code = """
from rest_framework.viewsets import ModelViewSet

class UserViewSet(ModelViewSet):
    def list(self, request):
        return Response([])

    def create(self, request):
        return Response({})

    def retrieve(self, request, pk):
        return Response({})
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 3
        functions = {e.function_name for e in endpoints}
        assert functions == {"list", "create", "retrieve"}

    def test_discover_action_decorator(self, discoverer, parse_code):
        """Test discovering @action decorated methods."""
        code = """
from rest_framework.viewsets import ModelViewSet
from rest_framework.decorators import action

class UserViewSet(ModelViewSet):
    @action(detail=True, methods=["post"])
    def activate(self, request, pk):
        return Response({})

    @action(detail=False, methods=["get"])
    def recent(self, request):
        return Response([])
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 2
        functions = {e.function_name for e in endpoints}
        assert functions == {"activate", "recent"}

    def test_permission_classes_tuple_syntax(self, discoverer, parse_code):
        """Test that tuple-syntax permission_classes = (IsAuthenticated,) is recognized."""
        code = """
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

class UserView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response([])
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth
        assert "IsAuthenticated" in endpoints[0].authorization.permissions

    def test_custom_viewset_base_with_action_and_tuple_permissions(self, discoverer, parse_code):
        """Test ViewSet with custom base class, @action, and tuple permission_classes."""
        code = """
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

class WorkOperationsViewSet(ValidatedGenericViewSet,
                            mixins.RetrieveModelMixin,
                            viewsets.GenericViewSet):
    permission_classes = (IsAuthenticated,)

    @action(detail=True, methods=['patch'], url_path='start')
    def start(self, request, pk=None):
        return Response({})

    @action(detail=True, methods=['patch'], url_path='complete')
    def complete(self, request, pk=None):
        return Response({})
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 2
        for ep in endpoints:
            assert ep.authorization.requires_auth, (
                f"Expected requires_auth on {ep.function_name}, got {ep.authorization}"
            )
            assert "IsAuthenticated" in ep.authorization.permissions
