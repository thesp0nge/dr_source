# dr_source/core/taint.py
import javalang
import logging

logger = logging.getLogger(__name__)


class TaintAnalyzer:
    def __init__(self):
        # We consider request.getParameter as our source of taint.
        self.tainted = {}  # Maps variable names to a taint origin description

    def analyze(self, ast_tree):
        vulnerabilities = []
        # First pass: mark tainted variables from declarations and assignments.
        for path, node in ast_tree:
            # Handle variable declarations (VariableDeclarator nodes)
            if (
                isinstance(node, javalang.tree.VariableDeclarator)
                and node.initializer is not None
            ):
                # If initializer is a method invocation, check if it's request.getParameter
                if isinstance(node.initializer, javalang.tree.MethodInvocation):
                    qualifier = getattr(node.initializer, "qualifier", "")
                    member = getattr(node.initializer, "member", "")
                    if qualifier == "request" and member == "getParameter":
                        self.tainted[node.name] = f"{qualifier}.{member}"
                        logger.debug(
                            "Variable '%s' marked as tainted via direct call", node.name
                        )
                # If initializer is a binary operation, collect identifiers and propagate taint
                elif isinstance(node.initializer, javalang.tree.BinaryOperation):
                    ids = self._collect_identifiers(node.initializer)
                    if any(identifier in self.tainted for identifier in ids):
                        self.tainted[node.name] = "tainted from binary expression"
                        logger.debug(
                            "Variable '%s' marked as tainted via binary expression",
                            node.name,
                        )
                else:
                    # Fallback: check initializer's string
                    init_str = str(node.initializer)
                    if "getParameter" in init_str:
                        self.tainted[node.name] = init_str
                        logger.debug(
                            "Variable '%s' marked as tainted via fallback", node.name
                        )
            # Handle assignments: propagate taint from right-hand side to left-hand side
            if isinstance(node, javalang.tree.Assignment):
                left_ids = self._collect_identifiers(node.expressionl)
                right_ids = self._collect_identifiers(node.value)
                for left in left_ids:
                    for right in right_ids:
                        if right in self.tainted:
                            self.tainted[left] = self.tainted[right]
                            logger.debug(
                                "Variable '%s' marked as tainted via assignment from '%s'",
                                left,
                                right,
                            )

        # Second pass: check for sink method invocations that use tainted variables.
        for path, node in ast_tree:
            if isinstance(node, javalang.tree.MethodInvocation) and node.member in [
                "executeQuery",
                "executeUpdate",
            ]:
                for arg in node.arguments:
                    arg_ids = self._collect_identifiers(arg)
                    for var in arg_ids:
                        if var in self.tainted:
                            line = node.position.line if node.position else 0
                            vulnerabilities.append(
                                {
                                    "sink": node.member,
                                    "source": self.tainted[var],
                                    "variable": var,
                                    "line": line,
                                }
                            )
                            logger.info(
                                "Taint detected: variable '%s' (tainted by %s) flows to sink '%s' at line %s",
                                var,
                                self.tainted[var],
                                node.member,
                                line,
                            )
        return vulnerabilities

    def _collect_identifiers(self, expr):
        """
        Recursively collect all identifier names from an expression.
        Returns a set of variable names.
        """
        ids = set()
        if isinstance(expr, javalang.tree.MemberReference):
            ids.add(expr.member)
        elif isinstance(expr, javalang.tree.Literal):
            pass
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
