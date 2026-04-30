"""Tests for FastAPI endpoint discoverer."""

from pathlib import Path

import pytest

from apiposture.core.discovery.fastapi import FastAPIEndpointDiscoverer
from apiposture.core.models.enums import Framework, HttpMethod


@pytest.fixture
def discoverer():
    """Create a FastAPI discoverer."""
    return FastAPIEndpointDiscoverer()


class TestFastAPIDiscoverer:
    """Tests for FastAPIEndpointDiscoverer."""

    def test_can_handle_fastapi_import(self, discoverer, parse_code):
        """Test that discoverer recognizes FastAPI imports."""
        code = """
from fastapi import FastAPI

app = FastAPI()
"""
        source = parse_code(code)
        assert discoverer.can_handle(source)

    def test_cannot_handle_non_fastapi(self, discoverer, parse_code):
        """Test that discoverer rejects non-FastAPI code."""
        code = """
from flask import Flask

app = Flask(__name__)
"""
        source = parse_code(code)
        assert not discoverer.can_handle(source)

    def test_discover_get_endpoint(self, discoverer, parse_code):
        """Test discovering a simple GET endpoint."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
async def get_users():
    return []
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].route == "/users"
        assert endpoints[0].methods == [HttpMethod.GET]
        assert endpoints[0].function_name == "get_users"
        assert endpoints[0].framework == Framework.FASTAPI

    def test_discover_post_endpoint(self, discoverer, parse_code):
        """Test discovering a POST endpoint."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.post("/users")
async def create_user(data: dict):
    return data
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].route == "/users"
        assert endpoints[0].methods == [HttpMethod.POST]

    def test_discover_multiple_endpoints(self, discoverer, parse_code):
        """Test discovering multiple endpoints."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
async def get_users():
    return []

@app.post("/users")
async def create_user(data: dict):
    return data

@app.delete("/users/{user_id}")
async def delete_user(user_id: int):
    return {"deleted": user_id}
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 3
        routes = {e.route for e in endpoints}
        assert "/users" in routes
        assert "/users/{user_id}" in routes

    def test_discover_endpoint_with_depends(self, discoverer, parse_code):
        """Test discovering endpoint with auth dependency."""
        code = """
from fastapi import FastAPI, Depends

app = FastAPI()

async def get_current_user():
    return {"id": 1}

@app.get("/profile")
async def get_profile(user = Depends(get_current_user)):
    return user
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth
        assert "get_current_user" in endpoints[0].authorization.auth_dependencies

    def test_discover_router_with_prefix(self, discoverer, parse_code):
        """Test discovering endpoints from router with prefix."""
        code = """
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1")

@router.get("/items")
async def get_items():
    return []
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].route == "/items"
        assert endpoints[0].router_prefix == "/api/v1"
        assert endpoints[0].full_route == "/api/v1/items"

    def test_discover_router_with_dependencies(self, discoverer, parse_code):
        """Test discovering endpoints from router with auth dependencies."""
        code = """
from fastapi import APIRouter, Depends

async def get_current_user():
    return {"id": 1}

router = APIRouter(prefix="/api", dependencies=[Depends(get_current_user)])

@router.get("/items")
async def get_items():
    return []
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth
        assert endpoints[0].authorization.inherited

    def test_discover_endpoint_with_security_scopes(self, discoverer, parse_code):
        """Test discovering endpoint with Security and scopes."""
        code = """
from fastapi import FastAPI, Security
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/admin")
async def admin(token: str = Security(oauth2_scheme, scopes=["admin:read"])):
    return {}
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth
        assert "admin:read" in endpoints[0].authorization.scopes

    def test_discover_annotated_type_alias(self, discoverer, parse_code):
        """Test that Annotated type alias resolves auth.

        e.g. CurrentUser = Annotated[User, Depends(...)]
        """
        code = """
from typing import Annotated
from fastapi import FastAPI, Depends

app = FastAPI()

def get_current_user():
    pass

CurrentUser = Annotated[dict, Depends(get_current_user)]

@app.get("/me")
async def get_me(user: CurrentUser):
    return user
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth
        assert "get_current_user" in endpoints[0].authorization.auth_dependencies

    def test_discover_imported_alias_heuristic(self, discoverer, parse_code):
        """Test that imported auth alias names are detected via heuristic."""
        code = """
from fastapi import FastAPI
from app.deps import CurrentUser

app = FastAPI()

@app.get("/me")
async def get_me(user: CurrentUser):
    return user
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth

    def test_discover_route_level_dependencies(self, discoverer, parse_code):
        """Test that dependencies= in route decorator is detected."""
        code = """
from fastapi import APIRouter, Depends

router = APIRouter()

def get_current_active_superuser():
    pass

@router.get("/users", dependencies=[Depends(get_current_active_superuser)])
async def read_users():
    return []
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth
        assert "get_current_active_superuser" in endpoints[0].authorization.auth_dependencies

    def test_non_auth_annotation_not_flagged(self, discoverer, parse_code):
        """Test that non-auth type annotations don't trigger false positives."""
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/items")
async def get_items(limit: int, name: str):
    return []
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert not endpoints[0].authorization.requires_auth
