# dr_source/core/detectors/command_injection.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class CommandInjectionDetector(BaseDetector):
    REGEX_PATTERNS = [
        re.compile(
            r"(?i)Runtime\.getRuntime\(\)\.exec\s*\(.*request\.getParameter.*\)",
            re.DOTALL,
        ),
        re.compile(r"(?i)ProcessBuilder\s*\(.*request\.getParameter.*\)", re.DOTALL),
        re.compile(r"(?i)exec\s*\(.*(?:;|\||&).*request\.getParameter.*\)", re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for Command Injection vulnerabilities.",
            file_object.path,
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.info(
                    "Command Injection vulnerability (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Command Injection (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        td = TaintDetector()
        # For command injection, dangerous sinks include exec and start.
        return td.detect_ast_taint(
            file_object, ast_tree, ["exec", "start"], "Command Injection"
        )
