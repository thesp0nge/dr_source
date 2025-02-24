import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class JNDIInjectionDetector(BaseDetector):
    """
    Detects potential JNDI injection vulnerabilities.
    Example: InitialContext ctx = new InitialContext();
             Object obj = ctx.lookup(request.getParameter("jndiName"));
    """

    # Aggiorniamo il pattern per catturare "lookup(...request.getParameter(...)" in modo più generico.
    REGEX_PATTERNS = [
        re.compile(r"(?i)lookup\s*\(.*request\.getParameter\s*\(", re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for JNDI Injection vulnerabilities.",
            file_object.path,
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "JNDI Injection vulnerability (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "JNDI Injection (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        td = TaintDetector()
        # For JNDI injection, consider the sink method 'lookup'
        return td.detect_ast_taint(file_object, ast_tree, ["lookup"], "JNDI Injection")
