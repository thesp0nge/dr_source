import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class CryptoDetector(BaseDetector):
    REGEX_PATTERNS = [
        re.compile(
            r"(?i)MessageDigest\.getInstance\s*\(\s*['\"](MD5|SHA-1|SHA1)['\"]\s*\)",
            re.DOTALL,
        ),
        re.compile(
            r"(?i)Cipher\.getInstance\s*\(\s*['\"](DES|RC4)['\"]\s*\)", re.DOTALL
        ),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for unsafe crypto/hashing functions.",
            file_object.path,
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "Unsafe crypto/hashing usage (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Unsafe Crypto/Hashing (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        # Typically, crypto checks are literal and AST-based analysis is less applicable.
        logger.debug(
            "AST-based detection for Crypto not implemented; falling back to regex."
        )
        return []
