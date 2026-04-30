"""FastAPI endpoint discoverer."""

import ast
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from apiposture.core.analysis.source_loader import ASTHelpers, ParsedSource
from apiposture.core.authorization.fastapi_auth import FastAPIAuthExtractor
from apiposture.core.discovery.base import EndpointDiscoverer
from apiposture.core.models.authorization import AuthorizationInfo
from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import EndpointType, Framework, HttpMethod

# FastAPI route decorator patterns
FASTAPI_ROUTE_DECORATORS = {
    "get": HttpMethod.GET,
    "post": HttpMethod.POST,
    "put": HttpMethod.PUT,
    "delete": HttpMethod.DELETE,
    "patch": HttpMethod.PATCH,
    "head": HttpMethod.HEAD,
    "options": HttpMethod.OPTIONS,
    "api_route": None,  # Generic route, methods from argument
}

# FastAPI import indicators
FASTAPI_IMPORTS = {"fastapi", "FastAPI", "APIRouter"}


class FastAPIEndpointDiscoverer(EndpointDiscoverer):
    """Discovers endpoints in FastAPI applications."""

    def __init__(self) -> None:
        self.auth_extractor = FastAPIAuthExtractor()

    @property
    def framework(self) -> Framework:
        return Framework.FASTAPI

    def can_handle(self, source: ParsedSource) -> bool:
        """Check if the source imports FastAPI."""
        for node in ast.walk(source.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in FASTAPI_IMPORTS or alias.name.startswith("fastapi"):
                        return True
            elif isinstance(node, ast.ImportFrom):
                if node.module and (node.module == "fastapi" or node.module.startswith("fastapi.")):
                    return True
        return False

    def discover(self, source: ParsedSource, file_path: Path) -> Iterator[Endpoint]:
        """Discover FastAPI endpoints."""
        # Track router variables and their prefixes/dependencies
        routers = self._find_routers(source)

        # Resolve type aliases like CurrentUser = Annotated[User, Depends(...)]
        type_aliases = self.auth_extractor.resolve_type_aliases(source)

        # Find all decorated functions
        for node in ast.walk(source.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield from self._process_function(node, source, file_path, routers, type_aliases)

    def _find_routers(self, source: ParsedSource) -> dict[str, dict[str, object]]:
        """
        Find APIRouter instantiations and their configurations.

        Returns dict mapping variable name to router config (prefix, dependencies, tags).
        """
        routers: dict[str, dict[str, object]] = {}

        for node in ast.walk(source.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        call_name = ASTHelpers.get_call_name(node.value)
                        if call_name and call_name.endswith("APIRouter"):
                            routers[target.id] = self._extract_router_config(node.value)

        return routers

    def _extract_router_config(self, call: ast.Call) -> dict[str, object]:
        """Extract configuration from an APIRouter() call."""
        config: dict[str, object] = {
            "prefix": "",
            "dependencies": [],
            "tags": [],
        }

        # Extract prefix
        prefix_arg = ASTHelpers.find_keyword_arg(call, "prefix")
        if prefix_arg:
            prefix = ASTHelpers.get_string_value(prefix_arg)
            if prefix:
                config["prefix"] = prefix

        # Extract tags
        tags_arg = ASTHelpers.find_keyword_arg(call, "tags")
        if tags_arg:
            config["tags"] = ASTHelpers.get_list_of_strings(tags_arg)

        # Extract dependencies (for auth)
        deps_arg = ASTHelpers.find_keyword_arg(call, "dependencies")
        if deps_arg and isinstance(deps_arg, ast.List):
            config["dependencies"] = self.auth_extractor.extract_dependencies_list(deps_arg)

        return config

    def _process_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        source: ParsedSource,
        file_path: Path,
        routers: dict[str, dict[str, object]],
        type_aliases: dict[str, Any] | None = None,
    ) -> Iterator[Endpoint]:
        """Process a function definition for route decorators."""
        for decorator in node.decorator_list:
            endpoint = self._extract_endpoint_from_decorator(
                node, decorator, source, file_path, routers, type_aliases
            )
            if endpoint:
                yield endpoint

    def _extract_endpoint_from_decorator(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        decorator: ast.expr,
        source: ParsedSource,
        file_path: Path,
        routers: dict[str, dict[str, object]],
        type_aliases: dict[str, Any] | None = None,
    ) -> Endpoint | None:
        """Extract endpoint info from a route decorator."""
        if not isinstance(decorator, ast.Call):
            return None

        # Get the decorator name (e.g., "app.get", "router.post")
        decorator_name = ASTHelpers.get_decorator_name(decorator)
        if not decorator_name:
            return None

        # Parse decorator: could be "app.get", "router.post", "get", etc.
        parts = decorator_name.split(".")
        method_name = parts[-1].lower()

        if method_name not in FASTAPI_ROUTE_DECORATORS:
            return None

        # Determine HTTP method(s)
        http_method = FASTAPI_ROUTE_DECORATORS[method_name]
        methods: list[HttpMethod]

        if http_method is None:
            # api_route - get methods from argument
            methods_arg = ASTHelpers.find_keyword_arg(decorator, "methods")
            if methods_arg:
                method_strs = ASTHelpers.get_list_of_strings(methods_arg)
                methods = [
                    HttpMethod(m.upper())
                    for m in method_strs
                    if m.upper() in HttpMethod.__members__
                ]
            else:
                methods = [HttpMethod.GET]  # Default
        else:
            methods = [http_method]

        # Extract route path (first argument)
        route = "/"
        if decorator.args:
            route_arg = ASTHelpers.get_string_value(decorator.args[0])
            if route_arg:
                route = route_arg

        # Determine router prefix
        router_prefix = ""
        router_auth: AuthorizationInfo | None = None
        tags: list[str] = []

        if len(parts) > 1:
            router_var = parts[-2]
            if router_var in routers:
                router_config = routers[router_var]
                router_prefix = str(router_config.get("prefix", ""))
                tags = list(router_config.get("tags", []))  # type: ignore
                router_deps = router_config.get("dependencies", [])
                if router_deps:
                    router_auth = AuthorizationInfo(
                        requires_auth=True,
                        auth_dependencies=list(router_deps),  # type: ignore
                        inherited=True,
                        source="router",
                    )

        # Extract tags from decorator
        tags_arg = ASTHelpers.find_keyword_arg(decorator, "tags")
        if tags_arg:
            tags.extend(ASTHelpers.get_list_of_strings(tags_arg))

        # Extract route-level dependencies= (e.g. @router.get("/", dependencies=[Depends(...)]))
        decorator_auth: AuthorizationInfo | None = None
        deps_arg = ASTHelpers.find_keyword_arg(decorator, "dependencies")
        if deps_arg and isinstance(deps_arg, ast.List):
            dep_names = self.auth_extractor.extract_dependencies_list(deps_arg)
            if dep_names:
                decorator_auth = AuthorizationInfo(
                    requires_auth=True,
                    auth_dependencies=dep_names,
                    source="decorator",
                )

        # Extract authorization info from function
        func_auth = self.auth_extractor.extract_from_function(
            node, source, type_aliases=type_aliases
        )

        # Merge auth: router → decorator → function
        authorization = func_auth
        if decorator_auth:
            authorization = decorator_auth.merge(authorization)
        if router_auth:
            authorization = router_auth.merge(authorization)

        return Endpoint(
            route=route,
            methods=methods,
            file_path=file_path,
            line_number=node.lineno,
            framework=Framework.FASTAPI,
            endpoint_type=EndpointType.FUNCTION,
            function_name=node.name,
            authorization=authorization,
            router_prefix=router_prefix,
            tags=tags,
        )
