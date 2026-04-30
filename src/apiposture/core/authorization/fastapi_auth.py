"""FastAPI authorization extraction."""

import ast
from typing import TypedDict

from apiposture.core.analysis.source_loader import ASTHelpers, ParsedSource
from apiposture.core.models.authorization import AuthorizationInfo


class _DepInfo(TypedDict):
    """Type for dependency extraction info."""

    dependencies: list[str]
    scopes: list[str]
    requires_auth: bool

# Known auth dependency patterns
AUTH_DEPENDENCY_PATTERNS = {
    "get_current_user",
    "get_current_active_user",
    "get_current_admin",
    "current_user",
    "require_auth",
    "require_authentication",
    "authenticate",
    "verify_token",
    "oauth2_scheme",
    "api_key_header",
    "HTTPBearer",
    "HTTPBasic",
}

# Known security patterns
SECURITY_PATTERNS = {
    "Security",
    "HTTPAuthorizationCredentials",
    "HTTPBasicCredentials",
}


_AUTH_NAME_KEYWORDS = {
    "user", "auth", "admin", "token",
    "session", "principal", "identity", "credential",
}


class FastAPIAuthExtractor:
    """Extracts authorization info from FastAPI endpoints."""

    def resolve_type_aliases(self, source: ParsedSource) -> dict[str, AuthorizationInfo]:
        """
        Scan a file for type alias assignments like ``CurrentUser = Annotated[User, Depends(...)]``.

        Returns a mapping from alias name to the extracted AuthorizationInfo.
        """
        aliases: dict[str, AuthorizationInfo] = {}
        for node in ast.walk(source.tree):
            # Match: Name = Annotated[Type, Depends(...)]
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Subscript):
                    auth = self._try_extract_annotated_alias(node.value)
                    if auth:
                        aliases[target.id] = auth
        return aliases

    def _try_extract_annotated_alias(self, subscript: ast.Subscript) -> AuthorizationInfo | None:
        """Try to extract auth from an ``Annotated[Type, Depends(...)]`` subscript."""
        if not (isinstance(subscript.value, ast.Name) and subscript.value.id == "Annotated"):
            # Also handle Attribute form: typing.Annotated
            if not (
                isinstance(subscript.value, ast.Attribute)
                and subscript.value.attr == "Annotated"
            ):
                return None

        if not isinstance(subscript.slice, ast.Tuple):
            return None

        auth_deps: list[str] = []
        scopes: list[str] = []
        requires_auth = False

        for elem in subscript.slice.elts[1:]:
            dep_info = self._extract_from_default(elem)
            if dep_info:
                auth_deps.extend(dep_info["dependencies"])
                scopes.extend(dep_info["scopes"])
                if dep_info["requires_auth"]:
                    requires_auth = True

        if not requires_auth and not auth_deps:
            return None

        return AuthorizationInfo(
            requires_auth=requires_auth,
            auth_dependencies=list(set(auth_deps)),
            scopes=list(set(scopes)),
            source="type_alias",
        )

    def extract_from_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        source: ParsedSource,
        type_aliases: dict[str, AuthorizationInfo] | None = None,
    ) -> AuthorizationInfo:
        """
        Extract authorization info from a FastAPI function.

        Looks for:
        - Depends() in function parameters
        - Security() in function parameters
        - OAuth2 scopes
        - Type alias annotations (e.g. ``CurrentUser``)
        - Heuristic name-based detection for imported auth aliases
        """
        auth_dependencies: list[str] = []
        scopes: list[str] = []
        requires_auth = False

        if type_aliases is None:
            type_aliases = {}

        # Check function parameters for Depends/Security
        for param in node.args.args + node.args.kwonlyargs:
            if param.annotation:
                dep_info = self._extract_from_annotation(
                    param.annotation, type_aliases
                )
                if dep_info:
                    auth_dependencies.extend(dep_info["dependencies"])
                    scopes.extend(dep_info["scopes"])
                    if dep_info["requires_auth"]:
                        requires_auth = True

        # Check defaults for Depends/Security
        all_defaults = list(node.args.defaults) + list(node.args.kw_defaults)
        for default in all_defaults:
            if default is not None:
                dep_info = self._extract_from_default(default)
                if dep_info:
                    auth_dependencies.extend(dep_info["dependencies"])
                    scopes.extend(dep_info["scopes"])
                    if dep_info["requires_auth"]:
                        requires_auth = True

        return AuthorizationInfo(
            requires_auth=requires_auth,
            auth_dependencies=list(set(auth_dependencies)),
            scopes=list(set(scopes)),
            source="function",
        )

    def _extract_from_annotation(
        self,
        annotation: ast.expr,
        type_aliases: dict[str, AuthorizationInfo] | None = None,
    ) -> _DepInfo | None:
        """Extract dependency info from a type annotation."""
        # Handle Annotated[Type, Depends(...)]
        if isinstance(annotation, ast.Subscript):
            if isinstance(annotation.value, ast.Name) and annotation.value.id == "Annotated":
                if isinstance(annotation.slice, ast.Tuple):
                    for elem in annotation.slice.elts[1:]:
                        result = self._extract_from_default(elem)
                        if result:
                            return result

        # Handle type alias names (e.g. CurrentUser resolved from file-level aliases)
        if isinstance(annotation, ast.Name):
            if type_aliases and annotation.id in type_aliases:
                alias_auth = type_aliases[annotation.id]
                return {
                    "dependencies": list(alias_auth.auth_dependencies),
                    "scopes": list(alias_auth.scopes),
                    "requires_auth": alias_auth.requires_auth,
                }
            # Heuristic: imported alias whose name contains auth keywords
            name_lower = annotation.id.lower()
            if any(kw in name_lower for kw in _AUTH_NAME_KEYWORDS):
                return {
                    "dependencies": [annotation.id],
                    "scopes": [],
                    "requires_auth": True,
                }

        return None

    def _extract_from_default(self, default: ast.expr) -> _DepInfo | None:
        """Extract dependency info from a default value (Depends/Security call)."""
        if not isinstance(default, ast.Call):
            return None

        call_name = ASTHelpers.get_call_name(default)
        if not call_name:
            return None

        result: _DepInfo = {
            "dependencies": [],
            "scopes": [],
            "requires_auth": False,
        }

        # Check for Depends()
        if call_name.endswith("Depends"):
            if default.args:
                dep_name = self._get_dependency_name(default.args[0])
                if dep_name:
                    result["dependencies"] = [dep_name]
                    result["requires_auth"] = self._is_auth_dependency(dep_name)
            return result

        # Check for Security()
        if call_name.endswith("Security"):
            result["requires_auth"] = True
            if default.args:
                dep_name = self._get_dependency_name(default.args[0])
                if dep_name:
                    result["dependencies"] = [dep_name]

            # Extract scopes
            scopes_arg = ASTHelpers.find_keyword_arg(default, "scopes")
            if scopes_arg:
                result["scopes"] = ASTHelpers.get_list_of_strings(scopes_arg)

            return result

        # Check for direct auth calls
        if self._is_auth_dependency(call_name):
            result["dependencies"] = [call_name]
            result["requires_auth"] = True
            return result

        return None

    def _get_dependency_name(self, node: ast.expr) -> str | None:
        """Get the name of a dependency from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return ASTHelpers.get_attribute_path(node)
        elif isinstance(node, ast.Call):
            return ASTHelpers.get_call_name(node)
        return None

    def _is_auth_dependency(self, name: str) -> bool:
        """Check if a dependency name looks like an auth dependency."""
        name_lower = name.lower()

        # Check known patterns
        for pattern in AUTH_DEPENDENCY_PATTERNS:
            if pattern.lower() in name_lower:
                return True

        # Check security patterns
        for pattern in SECURITY_PATTERNS:
            if pattern.lower() in name_lower:
                return True

        # Heuristic: contains auth-related keywords
        auth_keywords = {
            "auth", "user", "token", "bearer", "jwt", "oauth", "credential", "permission"
        }
        return any(kw in name_lower for kw in auth_keywords)

    def extract_dependencies_list(self, node: ast.List) -> list[str]:
        """Extract dependency names from a list of Depends() calls."""
        dependencies: list[str] = []
        for elem in node.elts:
            if isinstance(elem, ast.Call):
                call_name = ASTHelpers.get_call_name(elem)
                if call_name and call_name.endswith("Depends"):
                    if elem.args:
                        dep_name = self._get_dependency_name(elem.args[0])
                        if dep_name:
                            dependencies.append(dep_name)
        return dependencies
