"""Python parser built on the stdlib `ast` module.

Extracts, per file:
  - Symbols: functions, methods, classes (with qualname + signature + span)
  - Imports: module dependency edges
  - Calls:   call sites attributed to their enclosing function (the call graph)

Zero native dependencies -> works everywhere, deterministic, fast. tree-sitter
parsers for JS/TS can implement the same `parse_*(path, source) -> ParsedFile`
contract later.
"""

from __future__ import annotations

import ast

from .models import CallEdge, ImportEdge, ParsedFile, Symbol


def _callee_names(func: ast.AST) -> tuple[str | None, str | None]:
    """Return (short_name, dotted_name) for a call target, or (None, None)."""
    if isinstance(func, ast.Name):
        return func.id, func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return func.attr, ".".join(reversed(parts))
    return None, None


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.symbols: list[Symbol] = []
        self.imports: list[ImportEdge] = []
        self.calls: list[CallEdge] = []
        self._scope: list[tuple[str, str]] = []  # (name, kind) enclosing defs
        self._func_stack: list[str] = []  # qualnames of enclosing functions

    def _qual(self, name: str) -> str:
        return ".".join([n for n, _ in self._scope] + [name])

    # --- definitions -----------------------------------------------------
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qual = self._qual(node.name)
        self.symbols.append(
            Symbol("class", node.name, qual, self.path,
                   node.lineno, getattr(node, "end_lineno", node.lineno))
        )
        self._scope.append((node.name, "class"))
        self.generic_visit(node)
        self._scope.pop()

    def _handle_func(self, node) -> None:
        parent_kind = self._scope[-1][1] if self._scope else None
        kind = "method" if parent_kind == "class" else "function"
        qual = self._qual(node.name)
        try:
            signature = f"({ast.unparse(node.args)})"
        except Exception:
            signature = ""
        self.symbols.append(
            Symbol(kind, node.name, qual, self.path,
                   node.lineno, getattr(node, "end_lineno", node.lineno), signature)
        )
        self._scope.append((node.name, "function"))
        self._func_stack.append(qual)
        self.generic_visit(node)
        self._func_stack.pop()
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_func(node)

    # --- imports ---------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(
                ImportEdge(self.path, alias.name, alias.asname or alias.name, node.lineno)
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.imports.append(ImportEdge(self.path, module, alias.name, node.lineno))

    # --- calls -----------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        short, full = _callee_names(node.func)
        if short is not None:
            caller = self._func_stack[-1] if self._func_stack else "<module>"
            self.calls.append(CallEdge(caller, short, full or short, self.path, node.lineno))
        self.generic_visit(node)


def parse_python(path: str, source: str) -> ParsedFile:
    """Parse Python source into a ParsedFile. Raises SyntaxError on bad code."""
    tree = ast.parse(source)
    visitor = _Visitor(path)
    visitor.visit(tree)
    return ParsedFile(visitor.symbols, visitor.imports, visitor.calls)
