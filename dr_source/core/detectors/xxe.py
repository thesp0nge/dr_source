import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class XXEDetector(BaseDetector):
    """
    Detects potential XML External Entity (XXE) vulnerabilities by scanning for DOCTYPE
    declarations that reference SYSTEM or PUBLIC identifiers.
    """

    REGEX_PATTERNS = [
        re.compile(
            r'(?i)<!DOCTYPE\s+[^>]+(SYSTEM|PUBLIC)\s+["\'][^"\']+["\']', re.DOTALL
        ),
    ]

    def detect(self, file_object):
        results = []
        logger.debug("Scanning file '%s' for XXE vulnerabilities.", file_object.path)
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "XXE vulnerability found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "XXE",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results
