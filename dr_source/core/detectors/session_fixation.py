import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class SessionFixationDetector(BaseDetector):
    """
    Detects potential session fixation vulnerabilities.
    Flags usage of request.getSession() when no safe session-handling methods (changeSessionId() or invalidate())
    are present in the code.
    """

    # Regex-based approach: controlla se viene chiamato request.getSession() e se nel file non è presente changeSessionId o invalidate.
    REGEX_GETSESSION = re.compile(r"(?i)request\.getSession\s*\(\s*\)")
    REGEX_SAFE = re.compile(r"(?i)session\.(changeSessionId|invalidate)\s*\(")

    def detect(self, file_object):
        results = []
        content = file_object.content
        if self.REGEX_GETSESSION.search(content) and not self.REGEX_SAFE.search(
            content
        ):
            match = self.REGEX_GETSESSION.search(content)
            line = content.count("\n", 0, match.start()) + 1
            logger.debug(
                "Session Fixation vulnerability (regex) found in '%s' at line %s",
                file_object.path,
                line,
            )
            results.append(
                {
                    "file": file_object.path,
                    "vuln_type": "Session Fixation (regex)",
                    "match": match.group(),
                    "line": line,
                }
            )
        return results

    def detect_ast_from_tree(self, file_object, ast_tree):
        """
        In modalità AST, cerca chiamate a getSession() e verifica se in seguito vengono
        invocati metodi safe come changeSessionId() o invalidate(). L'implementazione è semplificata.
        """
        unsafe = False
        safe_found = False
        # Esaminiamo tutti i nodi: se troviamo una chiamata a getSession, la consideriamo "unsafe".
        # Se troviamo una chiamata a changeSessionId o invalidate, segnaliamo che c'è un controllo.
        for path, node in ast_tree:
            if isinstance(node, javalang.tree.MethodInvocation):
                if node.member == "getSession":
                    unsafe = True
                elif node.member in ["changeSessionId", "invalidate"]:
                    safe_found = True
        results = []
        if unsafe and not safe_found:
            results.append(
                {
                    "file": file_object.path,
                    "vuln_type": "Session Fixation (AST)",
                    "match": "request.getSession() without safe session handling",
                    "line": 0,  # Non disponiamo della linea esatta, quindi impostiamo 0
                }
            )
        return results
