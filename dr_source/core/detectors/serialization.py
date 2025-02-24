# dr_source/core/detectors/serialization.py
import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector
from dr_source.core.taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class SerializationDetector(BaseDetector):
    # Abbiamo aggiornato le regex per includere "new ObjectInputStream(...)"
    REGEX_PATTERNS = [
        # Pattern per matchare "new ObjectInputStream(...).readObject(" con spazi opzionali
        re.compile(
            r"(?i)new\s+ObjectInputStream\s*\([^)]*\)\.readObject\s*\(", re.DOTALL
        ),
        re.compile(r"(?i)deserialize\s*\(.*\)", re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Regex scanning file '%s' for Serialization vulnerabilities.",
            file_object.path,
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "Serialization vulnerability (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Serialization Issues (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        td = TaintDetector()
        # Per la deserializzazione, il sink è readObject.
        return td.detect_ast_taint(
            file_object, ast_tree, ["readObject"], "Serialization Issues"
        )
