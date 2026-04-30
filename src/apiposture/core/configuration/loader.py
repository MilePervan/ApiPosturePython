"""Configuration loader for ApiPosture."""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


@dataclass
class SuppressionConfig:
    """Configuration for suppressing specific findings."""

    rule_id: str
    route_pattern: str | None = None
    reason: str = ""

    def matches(self, rule_id: str, route: str) -> bool:
        """Check if this suppression matches a finding."""
        if self.rule_id != rule_id and self.rule_id != "*":
            return False

        if self.route_pattern:
            try:
                if not re.match(self.route_pattern, route):
                    return False
            except re.error:
                # Invalid regex, treat as literal match
                if self.route_pattern not in route:
                    return False

        return True


@dataclass
class ApiPostureConfig:
    """Configuration for ApiPosture."""

    # Rules to enable (empty = all)
    enabled_rules: list[str] = field(default_factory=list)

    # Rules to disable
    disabled_rules: list[str] = field(default_factory=list)

    # File patterns to include
    include_patterns: list[str] = field(default_factory=lambda: ["**/*.py"])

    # File patterns to exclude
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "**/__pycache__/**",
        "**/venv/**",
        "**/.venv/**",
        "**/site-packages/**",
        "**/node_modules/**",
        "**/.git/**",
        "**/test_*.py",
        "**/*_test.py",
        "**/tests/**",
        "**/conftest.py",
    ])

    # Suppressions
    suppressions: list[SuppressionConfig] = field(default_factory=list)

    # Custom auth dependency patterns
    auth_patterns: list[str] = field(default_factory=list)

    # Minimum severity to report
    min_severity: str = "info"

    def get_active_rules(self) -> list[str] | None:
        """Get list of active rules (None = all)."""
        if self.enabled_rules:
            return [r for r in self.enabled_rules if r not in self.disabled_rules]
        elif self.disabled_rules:
            # Return None to indicate "all except disabled"
            # The rule engine will need to filter
            return None
        return None

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled."""
        if self.enabled_rules:
            return rule_id in self.enabled_rules and rule_id not in self.disabled_rules
        return rule_id not in self.disabled_rules

    def is_suppressed(self, rule_id: str, route: str) -> tuple[bool, str]:
        """
        Check if a finding should be suppressed.

        Returns (is_suppressed, reason).
        """
        for suppression in self.suppressions:
            if suppression.matches(rule_id, route):
                return True, suppression.reason
        return False, ""


class ConfigLoader:
    """Loads configuration from YAML or JSON files."""

    @staticmethod
    def load(path: Path) -> ApiPostureConfig:
        """
        Load configuration from a file.

        Supports YAML (.yaml, .yml) and JSON (.json) files.
        """
        if not path.exists():
            return ApiPostureConfig()

        content = path.read_text(encoding="utf-8")

        if path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(content) or {}
        elif path.suffix == ".json":
            data = json.loads(content)
        else:
            # Try YAML first, then JSON
            try:
                data = yaml.safe_load(content) or {}
            except yaml.YAMLError:
                data = json.loads(content)

        return ConfigLoader._parse_config(data)

    @staticmethod
    def _parse_config(data: dict[str, Any]) -> ApiPostureConfig:
        """Parse configuration dictionary into ApiPostureConfig."""
        config = ApiPostureConfig()

        if "rules" in data:
            rules = data["rules"]
            if "enabled" in rules:
                config.enabled_rules = rules["enabled"]
            if "disabled" in rules:
                config.disabled_rules = rules["disabled"]

        if "include" in data:
            config.include_patterns = data["include"]

        if "exclude" in data:
            config.exclude_patterns = data["exclude"]

        if "suppressions" in data:
            for sup in data["suppressions"]:
                config.suppressions.append(
                    SuppressionConfig(
                        rule_id=sup.get("rule", "*"),
                        route_pattern=sup.get("route"),
                        reason=sup.get("reason", ""),
                    )
                )

        if "auth_patterns" in data:
            config.auth_patterns = data["auth_patterns"]

        if "min_severity" in data:
            config.min_severity = data["min_severity"]

        return config

    @staticmethod
    def find_config(start_path: Path) -> Path | None:
        """
        Find configuration file by walking up from start_path.

        Looks for .apiposture.yaml, .apiposture.yml, or apiposture.yaml.
        """
        config_names = [".apiposture.yaml", ".apiposture.yml", "apiposture.yaml", "apiposture.yml"]

        current = start_path.resolve()
        if current.is_file():
            current = current.parent

        while current != current.parent:
            for name in config_names:
                config_path = current / name
                if config_path.exists():
                    return config_path
            current = current.parent

        return None
