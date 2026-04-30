"""Source code loader and parser using Python's ast module."""

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ParsedSource:
    """Represents a parsed Python source file."""

    # The AST tree
    tree: ast.Module

    # Original source code
    source: str

    # File path (None for inline code)
    file_path: Path | None

    def get_source_segment(self, node: ast.AST) -> str | None:
        """Get the source code segment for an AST node."""
        return ast.get_source_segment(self.source, node)

    def get_line(self, lineno: int) -> str:
        """Get a specific line from the source."""
        lines = self.source.splitlines()
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1]
        return ""


class SourceLoader:
    """Loads and parses Python source files."""

    @staticmethod
    def parse_file(file_path: Path) -> ParsedSource:
        """
        Parse a Python file and return the AST.

        Args:
            file_path: Path to the Python file

        Returns:
            ParsedSource containing the AST and metadata

        Raises:
            SyntaxError: If the file has syntax errors
            FileNotFoundError: If the file doesn't exist
        """
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
        return ParsedSource(tree=tree, source=source, file_path=file_path)

    @staticmethod
    def parse_text(source: str, filename: str = "<string>") -> ParsedSource:
        """
        Parse Python source code from a string.

        Args:
            source: Python source code as a string
            filename: Optional filename for error messages

        Returns:
            ParsedSource containing the AST and metadata

        Raises:
            SyntaxError: If the source has syntax errors
        """
        tree = ast.parse(source, filename=filename)
        return ParsedSource(tree=tree, source=source, file_path=None)

    @staticmethod
    def try_parse_file(file_path: Path) -> tuple[ParsedSource | None, str | None]:
        """
        Try to parse a Python file, returning None and error message on failure.

        Args:
            file_path: Path to the Python file

        Returns:
            Tuple of (ParsedSource or None, error message or None)
        """
        try:
            return SourceLoader.parse_file(file_path), None
        except SyntaxError as e:
            return None, f"Syntax error at line {e.lineno}: {e.msg}"
        except FileNotFoundError:
            return None, f"File not found: {file_path}"
        except UnicodeDecodeError as e:
            return None, f"Unicode decode error: {e}"
        except Exception as e:
            return None, f"Unexpected error: {e}"


class ASTHelpers:
    """Helper functions for working with Python AST nodes."""

    @staticmethod
    def get_decorator_names(
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    ) -> list[str]:
        """
        Get the names of all decorators on a function or class.

        Returns simple names for Name decorators and the full expression for others.
        """
        names: list[str] = []
        for decorator in node.decorator_list:
            name = ASTHelpers.get_decorator_name(decorator)
            if name:
                names.append(name)
        return names

    @staticmethod
    def get_decorator_name(decorator: ast.expr) -> str | None:
        """Get the name/path of a single decorator."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            return ASTHelpers.get_attribute_path(decorator)
        elif isinstance(decorator, ast.Call):
            return ASTHelpers.get_decorator_name(decorator.func)
        return None

    @staticmethod
    def get_attribute_path(node: ast.Attribute) -> str:
        """Get the full dotted path of an attribute (e.g., 'app.route')."""
        parts: list[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    @staticmethod
    def get_call_name(node: ast.Call) -> str | None:
        """Get the name of a function being called."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return ASTHelpers.get_attribute_path(node.func)
        return None

    @staticmethod
    def get_string_value(node: ast.expr) -> str | None:
        """Extract a string value from an AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    @staticmethod
    def get_list_of_strings(node: ast.expr) -> list[str]:
        """Extract a list of strings from an AST node."""
        if isinstance(node, ast.List):
            return [
                s for elem in node.elts
                if (s := ASTHelpers.get_string_value(elem)) is not None
            ]
        return []

    @staticmethod
    def find_keyword_arg(call: ast.Call, name: str) -> ast.expr | None:
        """Find a keyword argument in a function call."""
        for keyword in call.keywords:
            if keyword.arg == name:
                return keyword.value
        return None

    @staticmethod
    def find_decorator(
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        names: set[str],
    ) -> ast.expr | None:
        """Find a decorator matching any of the given names."""
        for decorator in node.decorator_list:
            name = ASTHelpers.get_decorator_name(decorator)
            if name and any(name.endswith(n) for n in names):
                return decorator
        return None

    @staticmethod
    def find_decorators(
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        names: set[str],
    ) -> list[ast.expr]:
        """Find all decorators matching any of the given names."""
        result: list[ast.expr] = []
        for decorator in node.decorator_list:
            name = ASTHelpers.get_decorator_name(decorator)
            if name and any(name.endswith(n) for n in names):
                result.append(decorator)
        return result

    @staticmethod
    def get_base_class_names(node: ast.ClassDef) -> list[str]:
        """Get the names of base classes for a class definition."""
        names: list[str] = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                names.append(base.id)
            elif isinstance(base, ast.Attribute):
                names.append(ASTHelpers.get_attribute_path(base))
        return names

    @staticmethod
    def find_class_attribute(
        node: ast.ClassDef,
        name: str,
    ) -> ast.expr | None:
        """Find a class-level attribute assignment."""
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == name:
                        return stmt.value
            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name) and stmt.target.id == name:
                    return stmt.value
        return None
