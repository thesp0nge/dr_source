# dr_source/core/detectors/sql_injection.py
import re
import logging
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class SQLInjectionDetector(BaseDetector):
    REGEX_PATTERNS = [
        re.compile(
            r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*\s+FROM\s+.*\+.*request\.getParameter",
            re.DOTALL,
        ),
        re.compile(
            r"(?i)(Statement|PreparedStatement)\.execute(Query|Update)?\s*\(.*\+.*\)",
            re.DOTALL,
        ),
        re.compile(r"(?i)['\"]\s*\+\s*request\.getParameter\s*\(\s*['\"]", re.DOTALL),
        re.compile(r"(?i)request\.getParameter\s*\(.*\)\s*\+.*['\"].+['\"]", re.DOTALL),
    ]

    def detect(self, file_object):
        results = []
        logger.debug(
            "Scanning file '%s' for SQL Injection vulnerabilities.", file_object.path
        )
        for regex in self.REGEX_PATTERNS:
            for match in regex.finditer(file_object.content):
                line = file_object.content.count("\n", 0, match.start()) + 1
                logger.info(
                    "SQL Injection vulnerability found in '%s' at line %s: %s",
                    file_object.path,
                    line,
                    match.group(),
                )
                results.append(
                    {
                        "file": file_object.path,
                        "vuln_type": "SQL Injection",
                        "match": match.group(),
                        "line": line,
                    }
                )
        return results
