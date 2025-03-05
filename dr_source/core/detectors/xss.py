# dr_source/core/detectors/xss.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector
from dr_source.core.detection_rules import DetectionRules

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
        rules = DetectionRules.instance().get_rules("xss")
        custom_regex = rules.get("regex")
        if custom_regex:
            self.regex_patterns = [re.compile(p, re.DOTALL) for p in custom_regex]
        else:
            self.regex_patterns = self.BUILTIN_REGEX_PATTERNS
        self.ast_sink = rules.get("ast_sink", self.BUILTIN_AST_SINK)
        # Default: non in modalità AST
        self.ast_mode = False

    def detect(self, file_object):
        # Se siamo in modalità AST, non eseguire il rilevamento regex.
        if self.ast_mode:
            return []
        results = []
        logger.debug(
            "Regex scanning file '%s' for XSS vulnerabilities.", file_object.path
        )
        for regex in self.regex_patterns:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.info(
                    "XSS vulnerability (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
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
