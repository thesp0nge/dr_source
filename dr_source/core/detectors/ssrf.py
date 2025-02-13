import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class SSRFDetector(BaseDetector):
    """
    Detects potential Server-Side Request Forgery (SSRF) vulnerabilities by checking for
    URL creation and connection methods that use unsanitized user input.
    """

    REGEX_PATTERNS = [
        re.compile(r"(?i)new\s+URL\s*\(.*request\.getParameter.*\)", re.DOTALL),
        re.compile(r"(?i)openConnection\s*\(.*request\.getParameter.*\)", re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        logger.debug("Scanning file '%s' for SSRF vulnerabilities.", file_object.path)
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "SSRF vulnerability found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "SSRF",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results
