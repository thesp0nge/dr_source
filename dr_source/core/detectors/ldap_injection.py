# dr_source/core/detectors/ldap_injection.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class LDAPInjectionDetector(BaseDetector):
    BUILTIN_REGEX_PATTERNS = [
        re.compile(r"(?i)ldap://.*\+.*request\.getParameter", re.DOTALL),
        re.compile(r"(?i)ldap://.*request\.getParameter\s*\(.*\)\s*\+", re.DOTALL),
    ]
    BUILTIN_AST_SINK = ["ldapQuery"]

    def __init__(self):
        self.regex_patterns = self.BUILTIN_REGEX_PATTERNS
        self.ast_sink = self.BUILTIN_AST_SINK
        self.ast_mode = False

    def detect(self, file_object):
        if self.ast_mode:
            return []
        results = []
        for regex in self.regex_patterns:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "LDAP Injection (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        td = TaintDetector()
        return td.detect_ast_taint(
            file_object, ast_tree, self.ast_sink, "LDAP Injection"
        )
