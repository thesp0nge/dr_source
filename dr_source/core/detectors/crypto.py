import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class CryptoDetector(BaseDetector):
    """
    Detects usage of deprecated or unsafe cryptographic/hashing functions in Java code.
    For example:
      - MessageDigest.getInstance("MD5") or ("SHA-1" / "SHA1")
      - Cipher.getInstance("DES") or ("RC4")
    """

    REGEX_PATTERNS = [
        # Detect insecure hash functions MD5 and SHA-1
        re.compile(
            r'(?i)MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA-1|SHA1)["\']\s*\)',
            re.DOTALL,
        ),
        # Detect insecure cipher algorithms DES and RC4
        re.compile(
            r'(?i)Cipher\.getInstance\s*\(\s*["\'](DES|RC4)["\']\s*\)', re.DOTALL
        ),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Scanning file '%s' for unsafe crypto/hashing functions.", file_object.path
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "Unsafe crypto/hashing usage found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Unsafe Crypto/Hashing",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results
