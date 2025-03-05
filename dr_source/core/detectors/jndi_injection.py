# dr_source/core/detectors/jndi_injection.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class JNDIInjectionDetector(BaseDetector):
    BUILTIN_REGEX_PATTERNS = [
        re.compile(r"(?i)lookup\s*\(.*request\.getParameter\s*\(", re.DOTALL),
    ]
    BUILTIN_AST_SINK = ["lookup"]

    def __init__(self):
        self.regex_patterns = self.BUILTIN_REGEX_PATTERNS
        self.ast_sink = self.BUILTIN_AST_SINK
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
                        "vuln_type": "JNDI Injection (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        td = TaintDetector()
        return td.detect_ast_taint(
            file_object, ast_tree, self.ast_sink, "JNDI Injection"
        )
