"""Base class for output formatters."""

import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass

from rich.console import Console

from apiposture.core.models.scan_result import ScanResult


def _auto_no_color(no_color_flag: bool) -> bool:
    """Determine whether colors should be disabled."""
    if no_color_flag:
        return True
    # NO_COLOR environment variable (https://no-color.org/)
    if os.environ.get("NO_COLOR", "") != "":
        return True
    # Disable colors when stdout is not a TTY (redirected output)
    if not sys.stdout.isatty():
        return True
    return False


def _auto_no_icons(no_icons_flag: bool) -> bool:
    """Determine whether icons should be disabled."""
    if no_icons_flag:
        return True
    # Auto-detect: disable icons on Windows legacy consoles (cmd.exe, PowerShell)
    # which cannot render emoji. Windows Terminal sets WT_SESSION and handles emoji fine.
    if sys.platform == "win32" and not os.environ.get("WT_SESSION"):
        return True
    return False


@dataclass
class FormatterOptions:
    """Options for output formatters."""

    no_color: bool = False
    no_icons: bool = False
    group_by: str | None = None

    def __post_init__(self) -> None:
        self.no_color = _auto_no_color(self.no_color)
        self.no_icons = _auto_no_icons(self.no_icons)


class OutputFormatter(ABC):
    """Base class for output formatters."""

    def __init__(self, options: FormatterOptions | None = None) -> None:
        self.options = options or FormatterOptions()

    @abstractmethod
    def format(self, result: ScanResult) -> str:
        """
        Format the scan result as a string.

        Args:
            result: The scan result to format

        Returns:
            Formatted string output
        """
        ...

    def print(self, result: ScanResult, console: Console) -> None:
        """
        Print the scan result to a console.

        Override this for formatters that use rich directly.

        Args:
            result: The scan result to print
            console: Rich console to print to
        """
        console.print(self.format(result))
