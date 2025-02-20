# dr_source/core/taint_visitor.py
import javalang
import logging

logger = logging.getLogger(__name__)


class TaintVisitor:
    def __init__(self):
        # We consider any call to request.getParameter as a taint source.
        self.source_qualifier = "request"
        self.source_member = "getParameter"
        # Map variable names to a description of the taint source.
        self.tainted = {}

    def visit(self, node):
        """
        Recursively visit AST nodes and propagate taint.
        """
        # Process variable declarations.
        if (
            isinstance(node, javalang.tree.VariableDeclarator)
            and node.initializer is not None
        ):
            # Check if the initializer is a method invocation that is our source.
            if isinstance(node.initializer, javalang.tree.MethodInvocation):
                qualifier = getattr(node.initializer, "qualifier", None)
                member = getattr(node.initializer, "member", None)
                if qualifier == self.source_qualifier and member == self.source_member:
                    self.tainted[node.name] = f"{qualifier}.{member}"
                    logger.debug(
                        "Variable '%s' marked as tainted (source: %s)",
                        node.name,
                        f"{qualifier}.{member}",
                    )
            # If initializer is a binary operation, check if any operand is tainted.
            elif isinstance(node.initializer, javalang.tree.BinaryOperation):
                ids = self.collect_identifiers(node.initializer)
                if any(identifier in self.tainted for identifier in ids):
                    self.tainted[node.name] = "tainted via binary operation"
                    logger.debug(
                        "Variable '%s' marked as tainted via binary operation",
                        node.name,
                    )
            else:
                init_str = str(node.initializer)
                if self.source_member in init_str:
                    self.tainted[node.name] = init_str
                    logger.debug(
                        "Variable '%s' marked as tainted via fallback", node.name
                    )
        # Process assignments: propagate taint from right to left.
        if isinstance(node, javalang.tree.Assignment):
            left_ids = self.collect_identifiers(node.expressionl)
            right_ids = self.collect_identifiers(node.value)
            for left in left_ids:
                for right in right_ids:
                    if right in self.tainted:
                        self.tainted[left] = self.tainted[right]
                        logger.debug(
                            "Variable '%s' marked as tainted via assignment from '%s'",
                            left,
                            right,
                        )
        # Recursively visit children.
        for child in node.children:
            if isinstance(child, list):
                for item in child:
                    if isinstance(item, javalang.tree.Node):
                        self.visit(item)
            elif isinstance(child, javalang.tree.Node):
                self.visit(child)

    def collect_identifiers(self, expr):
        """
        Recursively collects variable identifiers from an expression node.
        Returns a set of identifier names.
        """
        ids = set()
        if isinstance(expr, javalang.tree.MemberReference):
            ids.add(expr.member)
        elif isinstance(expr, javalang.tree.BinaryOperation):
            ids |= self.collect_identifiers(expr.operandl)
            ids |= self.collect_identifiers(expr.operandr)
        elif hasattr(expr, "attrs"):
            for attr in expr.attrs:
                val = getattr(expr, attr, None)
                if isinstance(val, javalang.tree.Node):
                    ids |= self.collect_identifiers(val)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, javalang.tree.Node):
                            ids |= self.collect_identifiers(item)
        return ids

    def get_vulnerabilities(self, ast_tree, sink_list):
        """
        After propagating taint, traverse the AST again and return vulnerability records
        for method invocations that belong to sink_list and whose arguments contain a tainted variable.
        """
        vulns = []
        for path, node in ast_tree:
            if (
                isinstance(node, javalang.tree.MethodInvocation)
                and node.member in sink_list
            ):
                for arg in node.arguments:
                    ids = self.collect_identifiers(arg)
                    for var in ids:
                        if var in self.tainted:
                            line = node.position.line if node.position else 0
                            vulns.append(
                                {
                                    "sink": node.member,
                                    "source": self.tainted[var],
                                    "variable": var,
                                    "line": line,
                                }
                            )
        return vulns
