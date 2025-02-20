# dr_source/core/detectors/sql_injection.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class SQLInjectionDetector(BaseDetector):
    REGEX_PATTERNS = [
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

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for SQL Injection vulnerabilities.",
            file_object.path,
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.info(
                    "SQL Injection vulnerability (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
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
        # For SQL Injection, consider executeQuery and executeUpdate as sinks.
        return td.detect_ast_taint(
            file_object, ast_tree, ["executeQuery", "executeUpdate"], "SQL Injection"
        )
