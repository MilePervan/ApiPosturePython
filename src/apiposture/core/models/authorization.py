"""Authorization information model."""

from dataclasses import dataclass, field


@dataclass
class AuthorizationInfo:
    """Authorization information for an endpoint."""

    # Whether the endpoint requires authentication
    requires_auth: bool = False

    # Whether the endpoint explicitly allows anonymous access
    allows_anonymous: bool = False

    # Required roles (e.g., ["admin", "moderator"])
    roles: list[str] = field(default_factory=list)

    # Required scopes (e.g., ["read:users", "write:users"])
    scopes: list[str] = field(default_factory=list)

    # Required permissions (e.g., ["IsAuthenticated", "IsAdminUser"])
    permissions: list[str] = field(default_factory=list)

    # Required policies (e.g., ["AdminPolicy"])
    policies: list[str] = field(default_factory=list)

    # Auth dependencies (FastAPI Depends, Flask decorators)
    auth_dependencies: list[str] = field(default_factory=list)

    # Whether auth is inherited from parent (router, class, etc.)
    inherited: bool = False

    # Source of the authorization (e.g., "class", "method", "router")
    source: str = ""

    @property
    def has_specific_requirements(self) -> bool:
        """Check if there are specific role/scope/permission requirements."""
        return bool(self.roles or self.scopes or self.permissions or self.policies)

    @property
    def is_public(self) -> bool:
        """Check if the endpoint is effectively public."""
        return self.allows_anonymous or (
            not self.requires_auth and not self.has_specific_requirements
        )

    def merge(self, other: "AuthorizationInfo", override: bool = False) -> "AuthorizationInfo":
        """
        Merge authorization info from parent (e.g., class-level to method-level).

        If override is True, child values take precedence when both are set.
        If override is False, parent values are combined with child values.
        """
        if override and other.allows_anonymous:
            # AllowAnonymous at method level overrides class-level auth
            return AuthorizationInfo(
                allows_anonymous=True,
                inherited=False,
                source=other.source,
            )

        # Check if other (child) has any meaningful auth configuration
        other_has_config = (
            other.requires_auth
            or other.allows_anonymous
            or other.roles
            or other.scopes
            or other.permissions
            or other.policies
            or other.auth_dependencies
        )

        # For allows_anonymous: if override is True and child has no config, inherit from parent
        if override:
            allows_anon = other.allows_anonymous if other_has_config else self.allows_anonymous
        else:
            allows_anon = self.allows_anonymous and other.allows_anonymous

        return AuthorizationInfo(
            requires_auth=self.requires_auth or other.requires_auth,
            allows_anonymous=allows_anon,
            roles=list(set(self.roles) | set(other.roles)),
            scopes=list(set(self.scopes) | set(other.scopes)),
            permissions=list(set(self.permissions) | set(other.permissions)),
            policies=list(set(self.policies) | set(other.policies)),
            auth_dependencies=list(set(self.auth_dependencies) | set(other.auth_dependencies)),
            inherited=self.inherited if not other.requires_auth else False,
            source=other.source if other.source else self.source,
        )
