# dr_source/core/detectors/deprecated_api.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class DeprecatedAPIDetector(BaseDetector):
    BUILTIN_REGEX_PATTERNS = [
        re.compile(r"(?i)Thread\.stop\s*\("),
        re.compile(r"(?i)Thread\.suspend\s*\("),
        re.compile(r"(?i)Thread\.resume\s*\("),
        re.compile(r"(?i)System\.runFinalizersOnExit\s*\("),
        re.compile(r"(?i)Runtime\.runFinalizersOnExit\s*\("),
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
                        "vuln_type": "Deprecated API (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        results = []
        deprecated_methods = {"stop", "suspend", "resume", "runFinalizersOnExit"}
        for path, node in ast_tree:
            if (
                isinstance(node, javalang.tree.MethodInvocation)
                and node.member in deprecated_methods
            ):
                line = node.position.line if node.position else 0
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Deprecated API (AST)",
                        "match": f"{node.member} invoked",
                        "line": line,
                    }
                )
                logger.info(
                    "Deprecated API usage (AST) found: %s at line %s", node.member, line
                )
        return results
