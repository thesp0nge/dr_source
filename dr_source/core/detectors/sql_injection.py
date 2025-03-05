# dr_source/core/detectors/sql_injection.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector
from dr_source.core.detection_rules import DetectionRules

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
        rules = DetectionRules.instance().get_rules("sql_injection")
        custom_regex = rules.get("regex")
        if custom_regex:
            self.regex_patterns = [re.compile(p, re.DOTALL) for p in custom_regex]
        else:
            self.regex_patterns = self.BUILTIN_REGEX_PATTERNS
        self.ast_sink = rules.get("ast_sink", self.BUILTIN_AST_SINK)

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for SQL Injection vulnerabilities.",
            file_object.path,
        )
        for regex in self.regex_patterns:
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
        return td.detect_ast_taint(
            file_object, ast_tree, self.ast_sink, "SQL Injection"
        )
