import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class InsecureReflectionDetector(BaseDetector):
    """
    Detects unsafe reflection usage, e.g. Class.forName(request.getParameter("className"))
    """

    REGEX_PATTERNS = [
        re.compile(r"(?i)Class\.forName\s*\(\s*request\.getParameter\s*\(", re.DOTALL),
        re.compile(r'(?i)Class\.forName\s*\(\s*["\'].*["\']\s*\)', re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for Insecure Reflection vulnerabilities.",
            file_object.path,
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                # Flag only if input comes from request.getParameter (naively)
                if "request.getParameter" in match.group():
                    logger.debug(
                        "Insecure Reflection vulnerability (regex) found in '%s' at line %s: %s",
                        file_object.path,
                        line,
                        match.group(),
                    )
                    results.append(
                        {
                            "file": file_object.path,
                            "vuln_type": "Insecure Reflection (regex)",
                            "match": match.group(),
                            "line": line,
                        }
                    )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        td = TaintDetector()
        # For reflection, dangerous sink is forName.
        return td.detect_ast_taint(
            file_object, ast_tree, ["forName"], "Insecure Reflection"
        )
