# dr_source/core/detectors/serialization.py
import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class SerializationDetector(BaseDetector):
    # Updated regex: Allows for a constructor call with parentheses between the class name and ".readObject"
    REGEX_PATTERNS = [
        re.compile(
            r"(?i)(ObjectInputStream|XMLDecoder)\s*\([^)]*\)\.readObject\s*\(",
            re.DOTALL,
        ),
        re.compile(r"(?i)deserialize\s*\(.*\)", re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Scanning file '%s' for Serialization vulnerabilities.", file_object.path
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "Serialization vulnerability found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Serialization Issues",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results
