import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class HardcodedCredentialsDetector(BaseDetector):
    """
    Detector to identify hardcoded credentials such as passwords, API keys, and cryptographic secrets.
    """

    REGEX_PATTERNS = [
        re.compile(
            r'(?i)(password|pass|pwd|api_key|apikey|secret|token)\s*=\s*["\'].*?["\']'
        ),
        re.compile(
            r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'].*?["\']'
        ),
        re.compile(r'(?i)(private_key|ssh_key|auth_token)\s*=\s*["\'].*?["\']'),
    ]

    def detect(self, file_object):
        results = []
        logger.debug("Scanning file '%s' for hardcoded credentials .", file_object.path)
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "Possible hardcoded credential found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Hardcode credential",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results
