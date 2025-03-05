# dr_source/core/detectors/information_disclosure.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class InformationDisclosureDetector(BaseDetector):
    BUILTIN_REGEX_PATTERNS = [
        re.compile(r"(?i)printStackTrace\s*\("),
        re.compile(r"(?i)System\.out\.println\s*\(.*\b(e|ex)\b.*\)", re.DOTALL),
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
                        "vuln_type": "Information Disclosure (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        return []  # AST-based detection not implemented.
