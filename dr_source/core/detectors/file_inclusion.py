import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class FileInclusionDetector(BaseDetector):
    """
    Detects potential insecure file inclusion in JSP.
    For example, when using <jsp:include page="<%= request.getParameter('page') %>" />.
    """

    REGEX_PATTERNS = [
        re.compile(
            r'(?i)<jsp:include\s+page\s*=\s*["\'].*request\.getParameter\s*\(',
            re.DOTALL,
        ),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for File Inclusion vulnerabilities.",
            file_object.path,
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "File Inclusion vulnerability (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "File Inclusion (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        # Per JSP, l'analisi AST è complessa; in questo esempio non implementiamo la modalità AST.
        logger.debug(
            "AST-based detection for File Inclusion not implemented; falling back to regex."
        )
        return []
