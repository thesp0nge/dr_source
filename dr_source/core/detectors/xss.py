# dr_source/core/detectors/xss.py
import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class XSSDetector(BaseDetector):
    REGEX_PATTERNS = [
        re.compile(r"(?i)<script\b[^>]*>.*?</script>", re.DOTALL),
        re.compile(
            r"(?i)(out\.print(?:ln)?\s*\(.*request\.getParameter.*\))", re.DOTALL
        ),
        re.compile(r"(?i)\s*on\w+\s*=\s*['\"].*?['\"]", re.DOTALL),
        re.compile(r"(?i)<img\b[^>]*\bon\w+\s*=\s*['\"].*?['\"][^>]*>", re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        logger.debug("Scanning file '%s' for XSS vulnerabilities.", file_object.path)
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.info(
                    "XSS vulnerability found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "XSS",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results
