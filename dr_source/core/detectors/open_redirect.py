import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class OpenRedirectDetector(BaseDetector):
    REGEX_PATTERNS = [
        re.compile(
            r"(?i)response\.sendRedirect\s*\(\s*request\.getParameter\s*\(", re.DOTALL
        ),
        re.compile(
            r"(?i)response\.sendRedirect\s*\(\s*\"http://\".*request\.getParameter",
            re.DOTALL,
        ),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for Open Redirect vulnerabilities.",
            file_object.path,
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "Open Redirect vulnerability (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Open Redirect (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        td = TaintDetector()
        # In AST mode, consider sendRedirect as sink.
        return td.detect_ast_taint(
            file_object, ast_tree, ["sendRedirect"], "Open Redirect"
        )
