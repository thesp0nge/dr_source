# dr_source/core/detectors/hardcoded_credentials.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class HardcodedCredentialsDetector(BaseDetector):
    BUILTIN_REGEX_PATTERNS = [
        re.compile(r'(?i)(password|pass|pwd)\s*=\s*["\'].*["\']'),
        re.compile(r'(?i)(api_key|apikey|secret|token)\s*=\s*["\'].*["\']'),
    ]

    def __init__(self):
        self.regex_patterns = self.BUILTIN_REGEX_PATTERNS
        self.ast_mode = False

    def detect(self, file_object):
        if self.ast_mode:
            return []
        results = []
        content = file_object.content
        for regex in self.regex_patterns:
            for match in regex.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Hardcoded Credentials (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        results = []
        # Filtra solo i nodi di tipo VariableDeclarator
        for path, node in ast_tree.filter(javalang.tree.VariableDeclarator):
            if node.initializer is not None and isinstance(
                node.initializer, javalang.tree.Literal
            ):
                val = node.initializer.value.strip('"').strip("'")
                lower_name = node.name.lower()
                if any(
                    keyword in lower_name
                    for keyword in [
                        "password",
                        "pass",
                        "pwd",
                        "api_key",
                        "apikey",
                        "secret",
                        "token",
                    ]
                ):
                    line = node.position.line if node.position else 0
                    results.append(
                        {
                            "file": file_object.path,
                            "vuln_type": "Hardcoded Credentials (AST)",
                            "match": f"{node.name} = {val}",
                            "line": line,
                        }
                    )
                    logger.info(
                        "Hardcoded credential (AST) found: %s = %s at line %s",
                        node.name,
                        val,
                        line,
                    )
        return results
