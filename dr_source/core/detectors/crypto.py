# dr_source/core/detectors/crypto.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class CryptoDetector(BaseDetector):
    BUILTIN_REGEX_PATTERNS = [
        re.compile(
            r"(?i)MessageDigest\.getInstance\s*\(\s*['\"](MD5|SHA-1|SHA1)['\"]\s*\)",
            re.DOTALL,
        ),
        re.compile(
            r"(?i)Cipher\.getInstance\s*\(\s*['\"](DES|RC4)['\"]\s*\)", re.DOTALL
        ),
    ]

    def __init__(self):
        self.regex_patterns = self.BUILTIN_REGEX_PATTERNS
        self.ast_mode = False

    def detect(self, file_object):
        if self.ast_mode:
            return []
        results = []
        for regex in self.regex_patterns:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
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
        return []  # AST-based detection for crypto is not implemented.
