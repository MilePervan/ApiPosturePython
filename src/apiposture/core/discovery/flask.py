"""Flask endpoint discoverer."""

import ast
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from apiposture.core.analysis.source_loader import ASTHelpers, ParsedSource
from apiposture.core.authorization.flask_auth import FlaskAuthExtractor
from apiposture.core.discovery.base import EndpointDiscoverer
from apiposture.core.models.authorization import AuthorizationInfo
from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import EndpointType, Framework, HttpMethod

# Flask route decorator patterns
FLASK_ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}

# Flask import indicators
FLASK_IMPORTS = {"flask", "Flask", "Blueprint"}

# HTTP methods supported by MethodView
_METHODVIEW_HTTP_METHODS: dict[str, HttpMethod] = {
    "get": HttpMethod.GET,
    "post": HttpMethod.POST,
    "put": HttpMethod.PUT,
    "delete": HttpMethod.DELETE,
    "patch": HttpMethod.PATCH,
    "head": HttpMethod.HEAD,
    "options": HttpMethod.OPTIONS,
}

# Known MethodView base classes
_METHODVIEW_BASES = {"MethodView", "View"}


class FlaskEndpointDiscoverer(EndpointDiscoverer):
    """Discovers endpoints in Flask applications."""

    def __init__(self) -> None:
        self.auth_extractor = FlaskAuthExtractor()

    @property
    def framework(self) -> Framework:
        return Framework.FLASK

    def can_handle(self, source: ParsedSource) -> bool:
        """Check if the source imports Flask."""
        for node in ast.walk(source.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in FLASK_IMPORTS or alias.name.startswith("flask"):
                        return True
            elif isinstance(node, ast.ImportFrom):
                if node.module and (node.module == "flask" or node.module.startswith("flask")):
                    return True
        return False

    def discover(self, source: ParsedSource, file_path: Path) -> Iterator[Endpoint]:
        """Discover Flask endpoints."""
        # Track blueprint variables and their prefixes
        blueprints = self._find_blueprints(source)

        # Find all decorated functions
        for node in ast.walk(source.tree):
            if isinstance(node, ast.FunctionDef):
                yield from self._process_function(node, source, file_path, blueprints)

        # Find MethodView class-based views
        yield from self._discover_method_views(source, file_path, blueprints)

    def _find_blueprints(self, source: ParsedSource) -> dict[str, dict[str, str]]:
        """
        Find Blueprint instantiations and their configurations.

        Returns dict mapping variable name to blueprint config (url_prefix).
        """
        blueprints: dict[str, dict[str, str]] = {}

        for node in ast.walk(source.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        call_name = ASTHelpers.get_call_name(node.value)
                        if call_name and call_name.endswith("Blueprint"):
                            blueprints[target.id] = self._extract_blueprint_config(node.value)

        return blueprints

    def _extract_blueprint_config(self, call: ast.Call) -> dict[str, str]:
        """Extract configuration from a Blueprint() call."""
        config: dict[str, str] = {
            "url_prefix": "",
        }

        # url_prefix can be a keyword argument
        prefix_arg = ASTHelpers.find_keyword_arg(call, "url_prefix")
        if prefix_arg:
            prefix = ASTHelpers.get_string_value(prefix_arg)
            if prefix:
                config["url_prefix"] = prefix

        return config

    def _process_function(
        self,
        node: ast.FunctionDef,
        source: ParsedSource,
        file_path: Path,
        blueprints: dict[str, dict[str, str]],
    ) -> Iterator[Endpoint]:
        """Process a function definition for route decorators."""
        # Extract all route decorators and auth decorators
        route_decorators: list[ast.Call] = []
        auth_info = AuthorizationInfo(source="function")

        for decorator in node.decorator_list:
            # Check if it's a route decorator
            if isinstance(decorator, ast.Call):
                dec_name = ASTHelpers.get_decorator_name(decorator)
                if dec_name:
                    parts = dec_name.split(".")
                    method_name = parts[-1].lower()
                    if method_name in FLASK_ROUTE_DECORATORS:
                        route_decorators.append(decorator)
                        continue

            # Extract auth info from this decorator
            dec_auth = self.auth_extractor.extract_from_decorator(decorator)
            if dec_auth.requires_auth or dec_auth.allows_anonymous:
                auth_info = auth_info.merge(dec_auth)

        # Create endpoints for each route decorator
        for route_dec in route_decorators:
            endpoint = self._extract_endpoint_from_decorator(
                node, route_dec, file_path, blueprints, auth_info
            )
            if endpoint:
                yield endpoint

    def _extract_endpoint_from_decorator(
        self,
        node: ast.FunctionDef,
        decorator: ast.Call,
        file_path: Path,
        blueprints: dict[str, dict[str, str]],
        auth_info: AuthorizationInfo,
    ) -> Endpoint | None:
        """Extract endpoint info from a route decorator."""
        decorator_name = ASTHelpers.get_decorator_name(decorator)
        if not decorator_name:
            return None

        parts = decorator_name.split(".")
        method_name = parts[-1].lower()

        # Determine HTTP methods
        methods: list[HttpMethod]
        if method_name == "route":
            # Get methods from keyword argument
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
        elif method_name == "get":
            methods = [HttpMethod.GET]
        elif method_name == "post":
            methods = [HttpMethod.POST]
        elif method_name == "put":
            methods = [HttpMethod.PUT]
        elif method_name == "delete":
            methods = [HttpMethod.DELETE]
        elif method_name == "patch":
            methods = [HttpMethod.PATCH]
        else:
            return None

        # Extract route path
        route = "/"
        if decorator.args:
            route_arg = ASTHelpers.get_string_value(decorator.args[0])
            if route_arg:
                route = route_arg

        # Determine blueprint prefix
        router_prefix = ""
        if len(parts) > 1:
            blueprint_var = parts[-2]
            if blueprint_var in blueprints:
                router_prefix = blueprints[blueprint_var].get("url_prefix", "")

        return Endpoint(
            route=route,
            methods=methods,
            file_path=file_path,
            line_number=node.lineno,
            framework=Framework.FLASK,
            endpoint_type=EndpointType.FUNCTION,
            function_name=node.name,
            authorization=auth_info,
            router_prefix=router_prefix,
        )

    # ---- MethodView support ----

    def _discover_method_views(
        self,
        source: ParsedSource,
        file_path: Path,
        blueprints: dict[str, dict[str, str]],
    ) -> Iterator[Endpoint]:
        """Discover endpoints from MethodView classes and their route registrations."""
        view_classes = self._find_method_view_classes(source)
        if not view_classes:
            return

        registrations = self._find_view_registrations(source)

        for reg in registrations:
            class_name = reg["class_name"]
            if class_name not in view_classes:
                continue

            view_info = view_classes[class_name]
            router_prefix = ""
            bp_var = reg.get("blueprint_var", "")
            if bp_var and bp_var in blueprints:
                router_prefix = blueprints[bp_var].get("url_prefix", "")

            for route in reg["routes"]:
                for method_name, method_node in view_info["methods"].items():
                    http_method = _METHODVIEW_HTTP_METHODS.get(method_name)
                    if not http_method:
                        continue

                    # Auth from class-level decorators_class_view attribute
                    auth_info = view_info["auth"]
                    # Also check method-level decorators
                    method_auth = self.auth_extractor.extract_from_function(method_node)
                    if method_auth.requires_auth or method_auth.allows_anonymous:
                        auth_info = auth_info.merge(method_auth)

                    yield Endpoint(
                        route=route,
                        methods=[http_method],
                        file_path=file_path,
                        line_number=method_node.lineno,
                        framework=Framework.FLASK,
                        endpoint_type=EndpointType.CONTROLLER_ACTION,
                        function_name=f"{class_name}.{method_name}",
                        authorization=auth_info,
                        router_prefix=router_prefix,
                    )

    def _find_method_view_classes(
        self, source: ParsedSource
    ) -> dict[str, dict[str, Any]]:
        """Find classes inheriting from MethodView and extract their HTTP method handlers."""
        classes: dict[str, dict[str, Any]] = {}

        for node in ast.walk(source.tree):
            if not isinstance(node, ast.ClassDef):
                continue

            # Check if class inherits from MethodView
            is_method_view = False
            for base in node.bases:
                base_name = None
                if isinstance(base, ast.Name):
                    base_name = base.id
                elif isinstance(base, ast.Attribute):
                    base_name = base.attr
                if base_name and base_name in _METHODVIEW_BASES:
                    is_method_view = True
                    break

            if not is_method_view:
                continue

            # Extract HTTP method handlers
            methods: dict[str, ast.FunctionDef] = {}
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name in _METHODVIEW_HTTP_METHODS:
                    methods[item.name] = item

            if not methods:
                continue

            # Extract auth from class-level decorators
            class_auth = AuthorizationInfo(source="class")
            # Check class decorators
            for decorator in node.decorator_list:
                dec_auth = self.auth_extractor.extract_from_decorator(decorator)
                if dec_auth.requires_auth or dec_auth.allows_anonymous:
                    class_auth = class_auth.merge(dec_auth)

            # Check `decorators_class_view = [login_required]` class attribute
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id in ("decorators", "decorators_class_view")
                            and isinstance(item.value, ast.List)
                        ):
                            for elem in item.value.elts:
                                dec_auth = self.auth_extractor.extract_from_decorator(elem)
                                if dec_auth.requires_auth or dec_auth.allows_anonymous:
                                    class_auth = class_auth.merge(dec_auth)

            classes[node.name] = {
                "methods": methods,
                "auth": class_auth,
                "node": node,
            }

        return classes

    def _find_view_registrations(
        self, source: ParsedSource
    ) -> list[dict[str, Any]]:
        """
        Find route registrations for class-based views.

        Handles:
        - register_view(bp, routes=["/login"], view_func=Class.as_view("name"))
        - app.add_url_rule("/path", view_func=Class.as_view("name"))
        - bp.add_url_rule("/path", view_func=Class.as_view("name"))
        """
        registrations: list[dict[str, Any]] = []

        for node in ast.walk(source.tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = ASTHelpers.get_call_name(node)
            if not call_name:
                continue

            if call_name == "register_view" or call_name.endswith(".register_view"):
                reg = self._parse_register_view(node)
                if reg:
                    registrations.append(reg)
            elif call_name.endswith("add_url_rule"):
                reg = self._parse_add_url_rule(node, call_name)
                if reg:
                    registrations.append(reg)

        return registrations

    def _extract_class_from_as_view(self, node: ast.expr) -> str | None:
        """Extract class name from Class.as_view("name") call."""
        if not isinstance(node, ast.Call):
            return None
        if isinstance(node.func, ast.Attribute) and node.func.attr == "as_view":
            if isinstance(node.func.value, ast.Name):
                return node.func.value.id
        return None

    def _parse_register_view(self, call: ast.Call) -> dict[str, Any] | None:
        """Parse register_view(bp, routes=[...], view_func=Class.as_view(...))."""
        # Extract routes
        routes_arg = ASTHelpers.find_keyword_arg(call, "routes")
        if not routes_arg:
            # Try positional: register_view(bp, routes=[...])
            for arg in call.args:
                if isinstance(arg, ast.List):
                    routes_arg = arg
                    break

        routes: list[str] = []
        if routes_arg:
            routes = ASTHelpers.get_list_of_strings(routes_arg)

        if not routes:
            return None

        # Extract class name from view_func=Class.as_view(...)
        class_name = None
        view_func_arg = ASTHelpers.find_keyword_arg(call, "view_func")
        if view_func_arg:
            class_name = self._extract_class_from_as_view(view_func_arg)

        # Also check positional args for Class.as_view(...)
        if not class_name:
            for arg in call.args:
                class_name = self._extract_class_from_as_view(arg)
                if class_name:
                    break

        if not class_name:
            return None

        # Extract blueprint variable (first arg if it's a Name)
        bp_var = ""
        if call.args and isinstance(call.args[0], ast.Name):
            bp_var = call.args[0].id

        return {
            "routes": routes,
            "class_name": class_name,
            "blueprint_var": bp_var,
        }

    def _parse_add_url_rule(self, call: ast.Call, call_name: str) -> dict[str, Any] | None:
        """Parse app.add_url_rule("/path", view_func=Class.as_view(...))."""
        # Extract route (first positional arg)
        route = None
        if call.args:
            route = ASTHelpers.get_string_value(call.args[0])

        # Also check 'rule' keyword
        if not route:
            rule_arg = ASTHelpers.find_keyword_arg(call, "rule")
            if rule_arg:
                route = ASTHelpers.get_string_value(rule_arg)

        if not route:
            return None

        # Extract class from view_func=Class.as_view(...)
        class_name = None
        view_func_arg = ASTHelpers.find_keyword_arg(call, "view_func")
        if view_func_arg:
            class_name = self._extract_class_from_as_view(view_func_arg)

        if not class_name:
            return None

        # Extract blueprint/app variable
        bp_var = ""
        parts = call_name.split(".")
        if len(parts) > 1:
            bp_var = parts[-2]

        return {
            "routes": [route],
            "class_name": class_name,
            "blueprint_var": bp_var,
        }
