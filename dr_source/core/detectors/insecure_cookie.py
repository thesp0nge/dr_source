import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class InsecureCookieDetector(BaseDetector):
    REGEX_PATTERNS = [
        re.compile(r"(?i)setSecure\s*\(\s*false\s*\)"),
        re.compile(r"(?i)setHttpOnly\s*\(\s*false\s*\)"),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for Insecure Cookie vulnerabilities.",
            file_object.path,
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                vuln_type = (
                    "Insecure Cookie (setSecure)"
                    if "setSecure" in match.group()
                    else "Insecure Cookie (setHttpOnly)"
                )
                logger.debug(
                    "Insecure Cookie vulnerability (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": vuln_type,
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        # AST-based analysis for cookie settings is non-trivial, fallback to regex.
        logger.debug(
            "AST-based detection for Insecure Cookie not implemented; falling back to regex."
        )
        return []
