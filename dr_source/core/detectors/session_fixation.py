import re
import logging
import javalang
from dr_source.core.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class SessionFixationDetector(BaseDetector):
    """
    Detects potential session fixation vulnerabilities.
    Flags usage of request.getSession() when, within the same method,
    no safe session-handling methods (changeSessionId() or invalidate())
    are called on the resulting session variable after its assignment.
    """

    # Regex-based approach (fallback)
    REGEX_GETSESSION = re.compile(r"(?i)request\.getSession\s*\(\s*\)")
    REGEX_SAFE = re.compile(r"(?i)session\.(changeSessionId|invalidate)\s*\(")

    def detect(self, file_object):
        results = []
        content = file_object.content
        # Metodo semplice: se viene chiamato request.getSession() ma non si trova un safe call, segnala.
        if self.REGEX_GETSESSION.search(content) and not self.REGEX_SAFE.search(
            content
        ):
            match = self.REGEX_GETSESSION.search(content)
            line = content.count("\n", 0, match.start()) + 1
            logger.info(
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
        vulnerabilities = []
        # Itera sui metodi dichiarati
        for path, method_node in ast_tree.filter(javalang.tree.MethodDeclaration):
            session_vars = {}  # {nome variabile: linea di assegnazione}
            safe_calls = {}  # {nome variabile: lista di linee in cui viene invocato un safe method}
            # Se il metodo ha un corpo
            if method_node.body:
                # Esamina le dichiarazioni nel corpo (assumiamo che method_node.body sia una lista di Statement)
                for stmt in method_node.body:
                    # Gestione delle dichiarazioni di variabili locali
                    if isinstance(stmt, javalang.tree.LocalVariableDeclaration):
                        for decl in stmt.declarators:
                            if decl.initializer and isinstance(
                                decl.initializer, javalang.tree.MethodInvocation
                            ):
                                qualifier = getattr(decl.initializer, "qualifier", None)
                                member = getattr(decl.initializer, "member", None)
                                if qualifier == "request" and member == "getSession":
                                    assign_line = (
                                        decl.position.line
                                        if decl.position
                                        else (
                                            stmt.position.line if stmt.position else 0
                                        )
                                    )
                                    session_vars[decl.name] = assign_line
                    # Gestione degli assignment come StatementExpression
                    elif isinstance(stmt, javalang.tree.StatementExpression):
                        expr = stmt.expression
                        if isinstance(expr, javalang.tree.Assignment):
                            left_ids = self._collect_identifiers(expr.expressionl)
                            if expr.value and isinstance(
                                expr.value, javalang.tree.MethodInvocation
                            ):
                                qualifier = getattr(expr.value, "qualifier", None)
                                member = getattr(expr.value, "member", None)
                                if qualifier == "request" and member == "getSession":
                                    assign_line = (
                                        expr.position.line if expr.position else 0
                                    )
                                    for var in left_ids:
                                        session_vars[var] = assign_line
                        # Controlla anche le safe call come StatementExpression
                        elif isinstance(expr, javalang.tree.MethodInvocation):
                            if expr.member in ["changeSessionId", "invalidate"]:
                                qualifier = getattr(expr, "qualifier", None)
                                if qualifier in session_vars:
                                    call_line = (
                                        expr.position.line if expr.position else 0
                                    )
                                    if qualifier in safe_calls:
                                        safe_calls[qualifier].append(call_line)
                                    else:
                                        safe_calls[qualifier] = [call_line]
                    # Controlla se lo statement è direttamente una MethodInvocation
                    elif isinstance(stmt, javalang.tree.MethodInvocation):
                        if stmt.member in ["changeSessionId", "invalidate"]:
                            qualifier = getattr(stmt, "qualifier", None)
                            if qualifier in session_vars:
                                call_line = stmt.position.line if stmt.position else 0
                                if qualifier in safe_calls:
                                    safe_calls[qualifier].append(call_line)
                                else:
                                    safe_calls[qualifier] = [call_line]
                # Dopo aver analizzato il corpo del metodo, verifica per ogni variabile di sessione se esiste almeno una safe call dopo l'assegnazione
                for var, assign_line in session_vars.items():
                    calls = safe_calls.get(var, [])
                    # Flagga se non c'è alcuna safe call oppure tutte le safe call avvengono prima dell'assegnazione
                    if not calls or all(call_line < assign_line for call_line in calls):
                        vulnerabilities.append(
                            {
                                "file": file_object.path,
                                "vuln_type": "Session Fixation (AST)",
                                "match": f"Session variable '{var}' from request.getSession() not secured",
                                "line": assign_line,
                            }
                        )
                        logger.info(
                            "Session Fixation (AST): variable '%s' not secured (assigned at line %s)",
                            var,
                            assign_line,
                        )
        return vulnerabilities

    def _collect_identifiers(self, expr):
        """
        Raccoglie ricorsivamente gli identificatori (nomi) da un'espressione AST.
        """
        ids = set()
        if isinstance(expr, javalang.tree.MemberReference):
            ids.add(expr.member)
        elif isinstance(expr, javalang.tree.BinaryOperation):
            ids |= self._collect_identifiers(expr.operandl)
            ids |= self._collect_identifiers(expr.operandr)
        elif hasattr(expr, "attrs"):
            for attr in expr.attrs:
                val = getattr(expr, attr, None)
                if isinstance(val, javalang.tree.Node):
                    ids |= self._collect_identifiers(val)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, javalang.tree.Node):
                            ids |= self._collect_identifiers(item)
        return ids
