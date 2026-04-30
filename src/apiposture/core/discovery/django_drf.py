"""Django REST Framework endpoint discoverer."""

import ast
from collections.abc import Iterator
from pathlib import Path

from apiposture.core.analysis.source_loader import ASTHelpers, ParsedSource
from apiposture.core.authorization.django_auth import DjangoAuthExtractor
from apiposture.core.discovery.base import EndpointDiscoverer
from apiposture.core.models.authorization import AuthorizationInfo
from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import EndpointType, Framework, HttpMethod

# DRF view base classes
DRF_VIEW_BASES = {
    "APIView",
    "GenericAPIView",
    "CreateAPIView",
    "ListAPIView",
    "RetrieveAPIView",
    "UpdateAPIView",
    "DestroyAPIView",
    "ListCreateAPIView",
    "RetrieveUpdateAPIView",
    "RetrieveDestroyAPIView",
    "RetrieveUpdateDestroyAPIView",
    "ViewSet",
    "GenericViewSet",
    "ModelViewSet",
    "ReadOnlyModelViewSet",
}

# DRF decorators
DRF_DECORATORS = {"api_view", "action"}

# HTTP method to function name mapping for class-based views
HTTP_METHOD_HANDLERS = {
    "get": HttpMethod.GET,
    "post": HttpMethod.POST,
    "put": HttpMethod.PUT,
    "delete": HttpMethod.DELETE,
    "patch": HttpMethod.PATCH,
    "head": HttpMethod.HEAD,
    "options": HttpMethod.OPTIONS,
}

# ViewSet action to HTTP method mapping
VIEWSET_ACTIONS = {
    "list": HttpMethod.GET,
    "create": HttpMethod.POST,
    "retrieve": HttpMethod.GET,
    "update": HttpMethod.PUT,
    "partial_update": HttpMethod.PATCH,
    "destroy": HttpMethod.DELETE,
}


class DjangoRESTFrameworkDiscoverer(EndpointDiscoverer):
    """Discovers endpoints in Django REST Framework applications."""

    def __init__(self) -> None:
        self.auth_extractor = DjangoAuthExtractor()

    @property
    def framework(self) -> Framework:
        return Framework.DJANGO_DRF

    def can_handle(self, source: ParsedSource) -> bool:
        """Check if the source imports DRF."""
        for node in ast.walk(source.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "rest_framework" in alias.name:
                        return True
            elif isinstance(node, ast.ImportFrom):
                if node.module and "rest_framework" in node.module:
                    return True
        return False

    def discover(self, source: ParsedSource, file_path: Path) -> Iterator[Endpoint]:
        """Discover DRF endpoints."""
        for node in ast.walk(source.tree):
            # Check for class-based views
            if isinstance(node, ast.ClassDef):
                if self._is_drf_view_class(node):
                    yield from self._process_class_view(node, source, file_path)

            # Check for function-based views with @api_view
            elif isinstance(node, ast.FunctionDef):
                yield from self._process_function_view(node, source, file_path)

    def _is_drf_view_class(self, node: ast.ClassDef) -> bool:
        """Check if a class inherits from DRF view classes."""
        base_names = ASTHelpers.get_base_class_names(node)
        return any(
            base.split(".")[-1] in DRF_VIEW_BASES
            for base in base_names
        )

    def _process_class_view(
        self,
        node: ast.ClassDef,
        source: ParsedSource,
        file_path: Path,
    ) -> Iterator[Endpoint]:
        """Process a class-based view."""
        # Extract class-level authorization
        class_auth = self.auth_extractor.extract_from_class(node)

        # Determine if this is a ViewSet
        base_names = ASTHelpers.get_base_class_names(node)
        is_viewset = any(
            "ViewSet" in base.split(".")[-1]
            for base in base_names
        )

        # Find HTTP method handlers
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                method_name = item.name.lower()

                # Check for HTTP method handlers
                if method_name in HTTP_METHOD_HANDLERS:
                    http_method = HTTP_METHOD_HANDLERS[method_name]
                    method_auth = self.auth_extractor.extract_from_method(item)
                    combined_auth = class_auth.merge(method_auth, override=True)

                    yield Endpoint(
                        route=f"/{node.name.lower()}/",  # Placeholder, real route from urls.py
                        methods=[http_method],
                        file_path=file_path,
                        line_number=item.lineno,
                        framework=Framework.DJANGO_DRF,
                        endpoint_type=EndpointType.CONTROLLER_ACTION,
                        function_name=item.name,
                        class_name=node.name,
                        authorization=combined_auth,
                    )

                # Check for ViewSet actions
                elif is_viewset and method_name in VIEWSET_ACTIONS:
                    http_method = VIEWSET_ACTIONS[method_name]
                    method_auth = self.auth_extractor.extract_from_method(item)
                    combined_auth = class_auth.merge(method_auth, override=True)

                    # Determine route suffix for standard actions
                    route_suffix = ""
                    if method_name in ("retrieve", "update", "partial_update", "destroy"):
                        route_suffix = "{pk}/"

                    yield Endpoint(
                        route=f"/{node.name.lower()}/{route_suffix}",
                        methods=[http_method],
                        file_path=file_path,
                        line_number=item.lineno,
                        framework=Framework.DJANGO_DRF,
                        endpoint_type=EndpointType.CONTROLLER_ACTION,
                        function_name=item.name,
                        class_name=node.name,
                        authorization=combined_auth,
                    )

                # Check for custom @action decorator
                action_dec = ASTHelpers.find_decorator(item, {"action"})
                if action_dec and isinstance(action_dec, ast.Call):
                    yield from self._process_action_decorator(
                        item, action_dec, node, file_path, class_auth
                    )

    def _process_action_decorator(
        self,
        method: ast.FunctionDef,
        decorator: ast.Call,
        class_node: ast.ClassDef,
        file_path: Path,
        class_auth: AuthorizationInfo,
    ) -> Iterator[Endpoint]:
        """Process a @action decorated method."""
        # Get HTTP methods
        methods_arg = ASTHelpers.find_keyword_arg(decorator, "methods")
        if methods_arg:
            method_strs = ASTHelpers.get_list_of_strings(methods_arg)
            http_methods = [
                HttpMethod(m.upper())
                for m in method_strs
                if m.upper() in HttpMethod.__members__
            ]
        else:
            http_methods = [HttpMethod.GET]

        # Get detail flag
        detail_arg = ASTHelpers.find_keyword_arg(decorator, "detail")
        is_detail = False
        if detail_arg and isinstance(detail_arg, ast.Constant):
            is_detail = bool(detail_arg.value)

        # Extract method-level auth
        method_auth = self.auth_extractor.extract_from_method(method)
        combined_auth = class_auth.merge(method_auth, override=True)

        # Build route
        route_suffix = "{pk}/" if is_detail else ""
        url_path_arg = ASTHelpers.find_keyword_arg(decorator, "url_path")
        action_name = method.name
        if url_path_arg:
            path = ASTHelpers.get_string_value(url_path_arg)
            if path:
                action_name = path

        yield Endpoint(
            route=f"/{class_node.name.lower()}/{route_suffix}{action_name}/",
            methods=http_methods,
            file_path=file_path,
            line_number=method.lineno,
            framework=Framework.DJANGO_DRF,
            endpoint_type=EndpointType.CONTROLLER_ACTION,
            function_name=method.name,
            class_name=class_node.name,
            authorization=combined_auth,
        )

    def _process_function_view(
        self,
        node: ast.FunctionDef,
        source: ParsedSource,
        file_path: Path,
    ) -> Iterator[Endpoint]:
        """Process a function-based view with @api_view."""
        # Find @api_view decorator
        api_view_dec = ASTHelpers.find_decorator(node, {"api_view"})
        if not api_view_dec or not isinstance(api_view_dec, ast.Call):
            return

        # Get HTTP methods
        http_methods: list[HttpMethod] = []
        if api_view_dec.args:
            method_strs = ASTHelpers.get_list_of_strings(api_view_dec.args[0])
            http_methods = [
                HttpMethod(m.upper())
                for m in method_strs
                if m.upper() in HttpMethod.__members__
            ]

        if not http_methods:
            http_methods = [HttpMethod.GET]

        # Extract authorization from decorators
        auth_info = self.auth_extractor.extract_from_function(node)

        yield Endpoint(
            route=f"/{node.name}/",  # Placeholder
            methods=http_methods,
            file_path=file_path,
            line_number=node.lineno,
            framework=Framework.DJANGO_DRF,
            endpoint_type=EndpointType.FUNCTION,
            function_name=node.name,
            authorization=auth_info,
        )
