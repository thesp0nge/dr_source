import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class LDAPInjectionDetector(BaseDetector):
    """
    Detects potential LDAP injection vulnerabilities by checking for LDAP URLs
    concatenated with unsanitized user input (e.g., request.getParameter).
    """

    REGEX_PATTERNS = [
        re.compile(r"(?i)ldap://.*\+.*request\.getParameter", re.DOTALL),
        re.compile(r"(?i)ldap://.*request\.getParameter\s*\(.*\)\s*\+", re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Scanning file '%s' for LDAP Injection vulnerabilities.", file_object.path
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "LDAP Injection vulnerability found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "LDAP Injection",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results
