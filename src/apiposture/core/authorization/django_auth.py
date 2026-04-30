"""Django REST Framework authorization extraction."""

import ast
from typing import TypedDict

from apiposture.core.analysis.source_loader import ASTHelpers
from apiposture.core.models.authorization import AuthorizationInfo


class _PermissionConfig(TypedDict, total=False):
    """Type for DRF permission class configuration."""

    allows_anonymous: bool
    requires_auth: bool
    roles: list[str]


# DRF permission classes
DRF_PERMISSION_CLASSES: dict[str, _PermissionConfig] = {
    # Built-in
    "AllowAny": {"allows_anonymous": True},
    "IsAuthenticated": {"requires_auth": True},
    "IsAdminUser": {"requires_auth": True, "roles": ["admin"]},
    "IsAuthenticatedOrReadOnly": {"requires_auth": False},  # Complex case
    # Common third-party
    "IsOwner": {"requires_auth": True},
    "IsOwnerOrReadOnly": {"requires_auth": False},
    "IsSuperUser": {"requires_auth": True, "roles": ["superuser"]},
    "DjangoModelPermissions": {"requires_auth": True},
    "DjangoObjectPermissions": {"requires_auth": True},
}

# Auth decorator patterns (function-based views)
AUTH_DECORATORS = {
    "permission_classes",
    "authentication_classes",
}


class DjangoAuthExtractor:
    """Extracts authorization info from Django REST Framework views."""

    def extract_from_class(self, node: ast.ClassDef) -> AuthorizationInfo:
        """
        Extract authorization info from a DRF class-based view.

        Looks for:
        - permission_classes = [IsAuthenticated, ...]
        - authentication_classes = [...]
        """
        # Find permission_classes attribute
        perm_value = ASTHelpers.find_class_attribute(node, "permission_classes")
        if perm_value:
            return self._extract_from_permission_classes(perm_value, source="class")

        # If no permission_classes, check authentication_classes
        auth_value = ASTHelpers.find_class_attribute(node, "authentication_classes")
        if auth_value:
            return AuthorizationInfo(
                requires_auth=True,
                source="class",
            )

        return AuthorizationInfo(source="class")

    def extract_from_method(self, node: ast.FunctionDef) -> AuthorizationInfo:
        """Extract authorization info from decorators on a method."""
        for decorator in node.decorator_list:
            dec_name = ASTHelpers.get_decorator_name(decorator)
            if dec_name and dec_name.endswith("permission_classes"):
                if isinstance(decorator, ast.Call) and decorator.args:
                    return self._extract_from_permission_classes(
                        decorator.args[0], source="method"
                    )

        return AuthorizationInfo(source="method")

    def extract_from_function(self, node: ast.FunctionDef) -> AuthorizationInfo:
        """Extract authorization info from a function-based view's decorators."""
        combined = AuthorizationInfo(source="function")

        for decorator in node.decorator_list:
            dec_name = ASTHelpers.get_decorator_name(decorator)
            if not dec_name:
                continue

            # Check for @permission_classes([...])
            if dec_name.endswith("permission_classes"):
                if isinstance(decorator, ast.Call) and decorator.args:
                    perm_auth = self._extract_from_permission_classes(
                        decorator.args[0], source="decorator"
                    )
                    combined = combined.merge(perm_auth)

            # Check for @authentication_classes([...])
            elif dec_name.endswith("authentication_classes"):
                combined = combined.merge(
                    AuthorizationInfo(requires_auth=True, source="decorator")
                )

        return combined

    def _extract_from_permission_classes(
        self, node: ast.expr, source: str
    ) -> AuthorizationInfo:
        """Extract authorization info from a permission_classes value."""
        permissions: list[str] = []
        roles: list[str] = []
        requires_auth = False
        allows_anonymous = False

        # Handle list or tuple of permission classes
        if isinstance(node, (ast.List, ast.Tuple)):
            for elem in node.elts:
                perm_name = self._get_permission_name(elem)
                if perm_name:
                    permissions.append(perm_name)

                    # Check known permission classes
                    simple_name = perm_name.split(".")[-1]
                    if simple_name in DRF_PERMISSION_CLASSES:
                        config = DRF_PERMISSION_CLASSES[simple_name]
                        if config.get("allows_anonymous"):
                            allows_anonymous = True
                        if config.get("requires_auth"):
                            requires_auth = True
                        if "roles" in config:
                            roles.extend(config["roles"])
                    else:
                        # Unknown permission class - assume it requires auth
                        requires_auth = True

        # Handle single permission class
        else:
            perm_name = self._get_permission_name(node)
            if perm_name:
                permissions.append(perm_name)
                simple_name = perm_name.split(".")[-1]
                if simple_name in DRF_PERMISSION_CLASSES:
                    config = DRF_PERMISSION_CLASSES[simple_name]
                    if config.get("allows_anonymous"):
                        allows_anonymous = True
                    if config.get("requires_auth"):
                        requires_auth = True
                    if "roles" in config:
                        roles.extend(config["roles"])
                else:
                    requires_auth = True

        return AuthorizationInfo(
            requires_auth=requires_auth,
            allows_anonymous=allows_anonymous,
            permissions=permissions,
            roles=roles,
            source=source,
        )

    def _get_permission_name(self, node: ast.expr) -> str | None:
        """Get the name of a permission class from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return ASTHelpers.get_attribute_path(node)
        elif isinstance(node, ast.Call):
            # Handle instantiated permissions like IsOwner()
            return ASTHelpers.get_call_name(node)
        return None
