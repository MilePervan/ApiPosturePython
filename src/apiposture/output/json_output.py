"""JSON output formatter."""

import json

from apiposture.core.models.scan_result import ScanResult
from apiposture.output.base import FormatterOptions, OutputFormatter


class JsonFormatter(OutputFormatter):
    """JSON output formatter."""

    def __init__(self, options: FormatterOptions | None = None) -> None:
        super().__init__(options)

    def format(self, result: ScanResult) -> str:
        """Format the scan result as JSON."""
        return json.dumps(result.to_dict(), indent=2)
