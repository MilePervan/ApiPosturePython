"""Base authorization extractor interface."""

import ast
from abc import ABC, abstractmethod

from apiposture.core.models.authorization import AuthorizationInfo


class AuthorizationExtractor(ABC):
    """Base class for framework-specific authorization extractors."""

    @abstractmethod
    def extract_from_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> AuthorizationInfo:
        """Extract authorization info from a function definition."""
        ...

    @abstractmethod
    def extract_from_class(self, node: ast.ClassDef) -> AuthorizationInfo:
        """Extract authorization info from a class definition."""
        ...
