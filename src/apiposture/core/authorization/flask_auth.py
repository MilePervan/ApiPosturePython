"""Flask authorization extraction."""

import ast

from apiposture.core.analysis.source_loader import ASTHelpers
from apiposture.core.models.authorization import AuthorizationInfo

# Known Flask auth decorator patterns
AUTH_DECORATORS = {
    # flask-login
    "login_required",
    "fresh_login_required",
    # flask-jwt-extended
    "jwt_required",
    "jwt_optional",
    "fresh_jwt_required",
    "verify_jwt_in_request",
    # flask-httpauth
    "auth_required",
    # flask-security
    "auth_token_required",
    "http_auth_required",
    # Common custom patterns
    "require_auth",
    "require_authentication",
    "authenticated",
    "protected",
    "admin_required",
    "permission_required",
}

# Role-based decorators
ROLE_DECORATORS = {
    "roles_required",
    "roles_accepted",
    "role_required",
    "has_role",
    "require_role",
    "admin_required",
}

# Permission-based decorators
PERMISSION_DECORATORS = {
    "permission_required",
    "permissions_required",
    "has_permission",
    "require_permission",
}


class FlaskAuthExtractor:
    """Extracts authorization info from Flask endpoints."""

    def extract_from_decorator(self, decorator: ast.expr) -> AuthorizationInfo:
        """
        Extract authorization info from a single decorator.

        Looks for:
        - @login_required, @jwt_required, etc.
        - @roles_required("admin")
        - @permission_required("view_users")
        """
        decorator_name = ASTHelpers.get_decorator_name(decorator)
        if not decorator_name:
            return AuthorizationInfo()

        # Get just the function name (without module path)
        simple_name = decorator_name.split(".")[-1].lower()

        # Check for auth decorators
        if any(auth.lower() == simple_name for auth in AUTH_DECORATORS):
            return AuthorizationInfo(
                requires_auth=True,
                auth_dependencies=[decorator_name],
                source="decorator",
            )

        # Check for role decorators
        if any(role.lower() == simple_name for role in ROLE_DECORATORS):
            roles = self._extract_roles_from_decorator(decorator)
            return AuthorizationInfo(
                requires_auth=True,
                roles=roles,
                auth_dependencies=[decorator_name],
                source="decorator",
            )

        # Check for permission decorators
        if any(perm.lower() == simple_name for perm in PERMISSION_DECORATORS):
            permissions = self._extract_permissions_from_decorator(decorator)
            return AuthorizationInfo(
                requires_auth=True,
                permissions=permissions,
                auth_dependencies=[decorator_name],
                source="decorator",
            )

        # Check for jwt_optional (authenticated but not required)
        if simple_name == "jwt_optional":
            return AuthorizationInfo(
                allows_anonymous=True,
                auth_dependencies=[decorator_name],
                source="decorator",
            )

        return AuthorizationInfo()

    def _extract_roles_from_decorator(self, decorator: ast.expr) -> list[str]:
        """Extract role names from a role decorator."""
        if isinstance(decorator, ast.Call):
            # @roles_required("admin", "moderator")
            roles: list[str] = []
            for arg in decorator.args:
                role = ASTHelpers.get_string_value(arg)
                if role:
                    roles.append(role)

            # Also check for keyword argument
            roles_arg = ASTHelpers.find_keyword_arg(decorator, "roles")
            if roles_arg:
                roles.extend(ASTHelpers.get_list_of_strings(roles_arg))

            return roles
        return []

    def _extract_permissions_from_decorator(self, decorator: ast.expr) -> list[str]:
        """Extract permission names from a permission decorator."""
        if isinstance(decorator, ast.Call):
            permissions: list[str] = []
            for arg in decorator.args:
                perm = ASTHelpers.get_string_value(arg)
                if perm:
                    permissions.append(perm)

            # Also check for keyword argument
            perms_arg = ASTHelpers.find_keyword_arg(decorator, "permissions")
            if perms_arg:
                permissions.extend(ASTHelpers.get_list_of_strings(perms_arg))

            return permissions
        return []

    def extract_from_function(
        self,
        node: ast.FunctionDef,
    ) -> AuthorizationInfo:
        """Extract combined authorization info from all decorators on a function."""
        combined = AuthorizationInfo(source="function")

        for decorator in node.decorator_list:
            dec_auth = self.extract_from_decorator(decorator)
            if dec_auth.requires_auth or dec_auth.allows_anonymous:
                combined = combined.merge(dec_auth)

        return combined
