import ast
import logging
import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ImportBinding:
    local_name: str
    module_name: str
    symbol_name: Optional[str]
    supported: bool


class PythonProjectContext:
    """Python-specific module and import facts for one scanner lifecycle."""

    def __init__(self, project_root: str):
        self.project_root = os.path.normpath(os.path.abspath(project_root))
        self.file_modules: Dict[str, str] = {}
        self.module_files: Dict[str, str] = {}
        self.file_bindings: Dict[str, Dict[str, ImportBinding]] = {}

    def module_for_file(self, file_path: str) -> Optional[str]:
        path = os.path.normpath(os.path.abspath(file_path))
        relative = os.path.relpath(path, self.project_root)
        if relative == os.pardir or relative.startswith(os.pardir + os.sep):
            return None
        parts = relative.split(os.sep)
        if not parts or not parts[-1].endswith(".py"):
            return None
        stem = parts[-1][:-3]
        if stem == "__init__":
            parts = parts[:-1]
        else:
            parts[-1] = stem
        if any(not part or part == "__init__" for part in parts):
            return None
        directory = self.project_root
        for part in parts[:-1]:
            directory = os.path.join(directory, part)
            if not os.path.isfile(os.path.join(directory, "__init__.py")):
                return None
        return ".".join(parts) if parts else None

    def register_file(self, file_path: str, tree: ast.AST) -> None:
        path = os.path.normpath(os.path.abspath(file_path))
        module = self.module_for_file(path)
        if module is None:
            logger.warning("Could not derive Python module for %s", file_path)
        else:
            existing = self.module_files.get(module)
            if existing is not None and existing != path:
                logger.warning("Ambiguous Python module %r: %s and %s", module, existing, path)
            self.file_modules[path] = module
            self.module_files.setdefault(module, path)

        bindings: Dict[str, ImportBinding] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name.split(".")[0]
                    bindings[local_name] = ImportBinding(
                        local_name, alias.name, None, alias.asname is None and "." not in alias.name
                    )
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    bindings[alias.asname or alias.name] = ImportBinding(
                        alias.asname or alias.name,
                        node.module,
                        alias.name,
                        alias.asname is None,
                    )
        self.file_bindings[path] = bindings

    def binding(self, file_path: str, local_name: str) -> Optional[ImportBinding]:
        return self.file_bindings.get(os.path.normpath(os.path.abspath(file_path)), {}).get(local_name)

    def target_file(self, module_name: str) -> Optional[str]:
        return self.module_files.get(module_name)

    def resolve_binding(self, file_path: str, call_name: str) -> Tuple[Optional[str], Optional[str], bool]:
        parts = call_name.split(".")
        binding = self.binding(file_path, parts[0])
        if binding is None:
            return None, None, False
        if binding.supported and self.target_file(binding.module_name) is None:
            # A third-party import is recorded syntactically but is not part of
            # this project. Leave ordinary source/sink analysis untouched.
            return None, None, False
        if len(parts) == 1 and binding.symbol_name is not None:
            if not binding.supported:
                return None, None, True
            target_file = self.target_file(binding.module_name)
            # External imports are outside this project context and should not
            # interfere with ordinary source/sink matching.
            return target_file, binding.symbol_name, target_file is not None
        if len(parts) == 2 and binding.symbol_name is None:
            if not binding.supported:
                return None, None, True
            target_file = self.target_file(binding.module_name)
            return target_file, parts[1], target_file is not None
        return None, None, True
