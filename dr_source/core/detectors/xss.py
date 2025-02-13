# dr_source/core/detectors/xss.py
import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class XSSDetector(BaseDetector):
    REGEX_PATTERNS = [
        # Match <script> tags that include unsanitized user input via request.getParameter
        re.compile(
            r"(?i)<script\b[^>]*>.*?(?:request\.getParameter).*?</script>", re.DOTALL
        ),
        # Match out.print or out.println calls that perform string concatenation with unsanitized user input
        re.compile(
            r"(?i)out\.print(?:ln)?\s*\(.*\+.*request\.getParameter.*\)", re.DOTALL
        ),
        # Match <img> tags where the onerror attribute contains unsanitized user input
        re.compile(
            r"(?i)<img\b[^>]*\bonerror\s*=\s*['\"].*?request\.getParameter.*?['\"][^>]*>",
            re.DOTALL,
        ),
    ]

    def detect(self, file_object):
        results = []
        logger.debug("Scanning file '%s' for XSS vulnerabilities.", file_object.path)
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
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
