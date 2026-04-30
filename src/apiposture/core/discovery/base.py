"""Base protocol for endpoint discoverers."""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from apiposture.core.analysis.source_loader import ParsedSource
from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import Framework


class EndpointDiscoverer(ABC):
    """Base class for endpoint discoverers."""

    @property
    @abstractmethod
    def framework(self) -> Framework:
        """The framework this discoverer handles."""
        ...

    @abstractmethod
    def can_handle(self, source: ParsedSource) -> bool:
        """Check if this discoverer can handle the given source file."""
        ...

    @abstractmethod
    def discover(self, source: ParsedSource, file_path: Path) -> Iterator[Endpoint]:
        """
        Discover endpoints in the given source file.

        Args:
            source: Parsed source code
            file_path: Path to the source file

        Yields:
            Discovered endpoints
        """
        ...
