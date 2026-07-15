import yaml
from datetime import datetime
from pathlib import Path

from apiposture.core.analysis.source_loader import SourceLoader
from apiposture.core.classification.classifier import SecurityClassifier
from apiposture.core.configuration.loader import ApiPostureConfig
from apiposture.core.discovery.base import EndpointDiscoverer
from apiposture.core.discovery.django_drf import DjangoRESTFrameworkDiscoverer
from apiposture.core.discovery.fastapi import FastAPIEndpointDiscoverer
from apiposture.core.discovery.flask import FlaskEndpointDiscoverer
from apiposture.core.models.scan_result import ScanResult
from apiposture.rules.engine import RuleEngine

from apiposture.ai.filter import process_findings
from apiposture.ai.config import AIFilterConfig


def deduplicate_endpoints(endpoints: list) -> list:
    seen = {}
    result = []
    for ep in endpoints:
        key = (ep.full_route, frozenset(m.value for m in ep.methods))
        if key not in seen:
            seen[key] = ep
            result.append(ep)
    return result


def _load_ai_filter_section(scan_path: Path) -> dict | None:

    base = scan_path if scan_path.is_dir() else scan_path.parent
    candidates = [
        base / ".apiposture.yaml",
        base / "apiposture.yaml",
        Path.cwd() / ".apiposture.yaml",
    ]
    for cfg_path in candidates:
        if cfg_path.exists():
            try:
                data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
                return (data or {}).get("ai_filter")
            except Exception:
                return None
    return None


class ProjectAnalyzer:

    def __init__(self, config: ApiPostureConfig | None = None) -> None:
        self.config = config or ApiPostureConfig()

        self.discoverers: list[EndpointDiscoverer] = [
            FastAPIEndpointDiscoverer(),
            FlaskEndpointDiscoverer(),
            DjangoRESTFrameworkDiscoverer(),
        ]

        self.classifier = SecurityClassifier()

        active_rules = self.config.get_active_rules()
        self.rule_engine = RuleEngine(enabled_rules=active_rules)

    def analyze(self, path: Path) -> ScanResult:
        """Analyze a project for API security issues."""
        result = ScanResult(scan_path=path)

        files = self._get_files(path)
        result.files_scanned = files

        for file_path in files:
            self._scan_file(file_path, result)

        result.endpoints = deduplicate_endpoints(result.endpoints)

        self.classifier.classify_all(result.endpoints)

        findings = self.rule_engine.evaluate_all(result.endpoints)

        for finding in findings:
            is_suppressed, reason = self.config.is_suppressed(
                finding.rule_id, finding.endpoint.full_route
            )
            if is_suppressed:
                finding.suppressed = True
                finding.suppression_reason = reason

        findings = [
            f for f in findings
            if self.config.is_rule_enabled(f.rule_id)
        ]

        ai_section = _load_ai_filter_section(path)
        ai_config = AIFilterConfig.from_dict(ai_section)

        if ai_config.mode == "disabled":
            result.findings = findings
            result.ai_suppressed = []
        else:
            ai_result = process_findings(findings, config=ai_config)
            result.findings = [f["_original"] for f in ai_result["kept"]]
            result.ai_suppressed = ai_result["suppressed"]

        result.end_time = datetime.now()

        return result

    def _get_files(self, path: Path) -> list[Path]:
        if path.is_file():
            if path.suffix == ".py":
                return [path]
            return []

        files: list[Path] = []

        for pattern in self.config.include_patterns:
            files.extend(path.glob(pattern))

        filtered_files: list[Path] = []
        for file_path in files:
            relative = file_path.relative_to(path)
            excluded = False

            for exclude_pattern in self.config.exclude_patterns:
                if file_path.match(exclude_pattern):
                    excluded = True
                    break
                if any(
                    part.startswith(".")
                    for part in relative.parts
                    if part not in (".", "..")
                ):
                    if "__pycache__" in str(relative) or ".git" in str(relative):
                        excluded = True
                        break

            if not excluded:
                filtered_files.append(file_path)

        return sorted(filtered_files)

    def _scan_file(self, file_path: Path, result: ScanResult) -> None:
        parsed, error = SourceLoader.try_parse_file(file_path)

        if error:
            result.parse_errors[file_path] = error
            return

        if parsed is None:
            return

        for discoverer in self.discoverers:
            if discoverer.can_handle(parsed):
                result.frameworks_detected.add(discoverer.framework)
                for endpoint in discoverer.discover(parsed, file_path):
                    result.endpoints.append(endpoint)
                break