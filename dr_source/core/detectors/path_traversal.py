# dr_source/core/detectors/path_traversal.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class PathTraversalDetector(BaseDetector):
    REGEX_PATTERNS = [
        re.compile(r"(?i)new\s+File\s*\(\s*.*request\.getParameter.*\)", re.DOTALL),
        re.compile(
            r"(?i)(FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(.*request\.getParameter.*\)",
            re.DOTALL,
        ),
        re.compile(r"(?i)(\.\./)+", re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for Path Traversal vulnerabilities.",
            file_object.path,
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "Path Traversal vulnerability (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Path Traversal (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        td = TaintDetector()
        # Dangerous sinks for path traversal may include File constructors and file stream classes.
        return td.detect_ast_taint(
            file_object,
            ast_tree,
            ["File", "FileInputStream", "FileOutputStream"],
            "Path Traversal",
        )
