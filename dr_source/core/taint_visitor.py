# dr_source/core/taint_visitor.py
import javalang
import logging

logger = logging.getLogger(__name__)


class TaintVisitor:
    def __init__(self):
        # Define source: any call to request.getParameter is considered tainted.
        self.source_qualifier = "request"
        self.source_member = "getParameter"
        # Map variable names to taint description.
        self.tainted = {}

    def visit(self, node):
        """
        Recursively visits the AST and propagates taint.
        """
        # Process variable declarations.
        if (
            isinstance(node, javalang.tree.VariableDeclarator)
            and node.initializer is not None
        ):
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
            elif isinstance(node.initializer, javalang.tree.BinaryOperation):
                if self.is_tainted(node.initializer):
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
        # Process assignments.
        if isinstance(node, javalang.tree.Assignment):
            left_ids = self.collect_identifiers(node.expressionl)
            if self.is_tainted(node.value):
                for left in left_ids:
                    self.tainted[left] = "tainted via assignment"
                    logger.debug("Variable '%s' marked as tainted via assignment", left)
        # Recurse over children.
        for child in node.children:
            if isinstance(child, list):
                for item in child:
                    if isinstance(item, javalang.tree.Node):
                        self.visit(item)
            elif isinstance(child, javalang.tree.Node):
                self.visit(child)

    def is_tainted(self, expr):
        """
        Determines if the given expression is tainted.
        Checks directly if it is a method invocation of request.getParameter,
        recursively checks binary operations, or collects identifiers.
        """
        # Direct check for a source call.
        if isinstance(expr, javalang.tree.MethodInvocation):
            qualifier = getattr(expr, "qualifier", None)
            member = getattr(expr, "member", None)
            if qualifier == self.source_qualifier and member == self.source_member:
                return True
            # Recursively check arguments.
            for arg in expr.arguments:
                if self.is_tainted(arg):
                    return True
        # If it's a binary operation, check both operands.
        if isinstance(expr, javalang.tree.BinaryOperation):
            return self.is_tainted(expr.operandl) or self.is_tainted(expr.operandr)
        # For a member reference, check if it is marked tainted.
        if isinstance(expr, javalang.tree.MemberReference):
            if expr.member in self.tainted:
                return True
        # Fallback: collect identifiers and see if any is tainted.
        ids = self.collect_identifiers(expr)
        return any(identifier in self.tainted for identifier in ids)

    def collect_identifiers(self, expr):
        """
        Recursively collects identifiers (variable names) from an expression.
        Returns a set of variable names.
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
        After visiting the AST, traverses it to find sink method invocations where an argument is tainted.
        Returns a list of vulnerability records.
        """
        vulns = []
        for path, node in ast_tree:
            if (
                isinstance(node, javalang.tree.MethodInvocation)
                and node.member in sink_list
            ):
                for arg in node.arguments:
                    if self.is_tainted(arg):
                        line = node.position.line if node.position else 0
                        # Try to get an identifier for reporting.
                        ids = self.collect_identifiers(arg)
                        var = next(iter(ids), "unknown")
                        vulns.append(
                            {
                                "sink": node.member,
                                "source": self.tainted.get(var, "unknown"),
                                "variable": var,
                                "line": line,
                            }
                        )
        return vulns
