import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class DeprecatedAPIDetector(BaseDetector):
    """
    Detects usage of deprecated APIs.
    Esempi:
      - Thread.stop(), Thread.suspend(), Thread.resume()
      - System.runFinalizersOnExit(), Runtime.runFinalizersOnExit()
    """

    REGEX_PATTERNS = [
        re.compile(r"(?i)Thread\.stop\s*\("),
        re.compile(r"(?i)Thread\.suspend\s*\("),
        re.compile(r"(?i)Thread\.resume\s*\("),
        re.compile(r"(?i)System\.runFinalizersOnExit\s*\("),
        re.compile(r"(?i)Runtime\.runFinalizersOnExit\s*\("),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for deprecated API usage.", file_object.path
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "Deprecated API usage (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
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
                logger.debug(
                    "Deprecated API usage (AST) found: %s at line %s", node.member, line
                )
        return results
