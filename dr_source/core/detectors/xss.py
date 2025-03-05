# dr_source/core/detectors/xss.py
# dr_source/core/detectors/xss.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class XSSDetector(BaseDetector):
    BUILTIN_REGEX_PATTERNS = [
        re.compile(r"(?i)<script\b[^>]*>.*?</script>", re.DOTALL),
        re.compile(
            r"(?i)(out\.print(?:ln)?\s*\(.*request\.getParameter.*\))", re.DOTALL
        ),
        re.compile(r"(?i)\s*on\w+\s*=\s*['\"].*?['\"]", re.DOTALL),
        re.compile(
            r"(?i)<img\b[^>]*\bonerror\s*=\s*['\"].*?request\.getParameter.*?['\"][^>]*>",
            re.DOTALL,
        ),
    ]
    BUILTIN_AST_SINK = ["print", "println", "write"]

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
                        "vuln_type": "XSS (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        td = TaintDetector()
        return td.detect_ast_taint(file_object, ast_tree, self.ast_sink, "XSS")
