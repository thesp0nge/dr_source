import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

@dataclass
class FunctionDefinition:
    name: str
    file_path: str
    node: Any # The AST node (tree-sitter or native AST)
    language: str

class ProjectIndex:
    """
    A global index of all functions and classes discovered across the project.
    Used for inter-file taint analysis.
    """
    def __init__(self):
        self.functions: Dict[str, FunctionDefinition] = {}

    def register_function(self, name: str, file_path: str, node: Any, language: str):
        logger.info(f"REGISTERING GLOBAL FUNCTION: {name} ({language}) in {file_path}")
        if name in self.functions:
            logger.debug(f"Function {name} is already registered. Overwriting with definition from {file_path}")
        self.functions[name] = FunctionDefinition(name, file_path, node, language)

    def find_function(self, name: str) -> Optional[FunctionDefinition]:
        return self.functions.get(name)
