import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class InformationDisclosureDetector(BaseDetector):
    """
    Detects potential information disclosure vulnerabilities, e.g., stampa di stack trace
    o dettagli delle eccezioni su output pubblici.
    """

    REGEX_PATTERNS = [
        re.compile(r"(?i)printStackTrace\s*\("),
        re.compile(r"(?i)System\.out\.println\s*\(.*\b(e|ex)\b.*\)", re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        content = file_object.content
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                logger.debug(
                    "Information Disclosure vulnerability (regex) found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "Information Disclosure (regex)",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        # L'analisi AST per questa vulnerabilità è complessa (bisogna analizzare i blocchi catch).
        # Per ora si ritorna un risultato vuoto.
        logger.debug(
            "AST-based detection for Information Disclosure not implemented; falling back to regex."
        )
        return []
