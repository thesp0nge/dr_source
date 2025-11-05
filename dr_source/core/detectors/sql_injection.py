# dr_source/core/detectors/sql_injection.py
# dr_source/core/detectors/sql_injection.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class SQLInjectionDetector(BaseDetector):
    BUILTIN_REGEX_PATTERNS = [
        re.compile(
            r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*\s+FROM\s+.*\+.*request\.getParameter",
            re.DOTALL,
        ),
        re.compile(
            r"(?i)(Statement|PreparedStatement)\.execute(Query|Update)?\s*\(.*\+.*\)",
            re.DOTALL,
        ),
        re.compile(r"(?i)['\"]\s*\+\s*request\.getParameter\s*\(\s*['\"]", re.DOTALL),
        re.compile(r"(?i)request\.getParameter\s*\(.*\)\s*\+.*['\"].+['\"]", re.DOTALL),
    ]
    BUILTIN_AST_SINK = ["executeQuery", "executeUpdate"]

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
                        "vuln_type": "SQL Injection (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        td = TaintDetector()
        return td.detect_ast_taint(
            file_object, ast_tree, self.ast_sink, "SQL Injection"
        )
