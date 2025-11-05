# dr_source/core/taint_visitor.py
import javalang
import logging

logger = logging.getLogger(__name__)


class TaintVisitor:
    def __init__(self):
        # We consider any call to request.getParameter as a taint source.
        self.source_qualifier = "request"
        self.source_member = "getParameter"
        # Map variable names to taint information: a dict with keys "source" and "trace" (a list of messages)
        self.tainted = {}  # e.g. { "username": { "source": "request.getParameter", "trace": ["tainted at line 3"] } }

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
                    pos = node.position.line if node.position else "unknown"
                    self.tainted[node.name] = {
                        "source": f"{qualifier}.{member}",
                        "trace": [
                            f"Variable '{node.name}' tainted via {qualifier}.{member}() at line {pos}"
                        ],
                    }
                    logger.debug(
                        "Variable '%s' marked as tainted (source: %s)",
                        node.name,
                        f"{qualifier}.{member}",
                    )
            elif isinstance(node.initializer, javalang.tree.BinaryOperation):
                # Check if any operand is tainted.
                ids = self.collect_identifiers(node.initializer)
                if any(identifier in self.tainted for identifier in ids):
                    pos = node.position.line if node.position else "unknown"
                    self.tainted[node.name] = {
                        "source": "propagated via binary operation",
                        "trace": [
                            f"Variable '{node.name}' tainted via binary operation at line {pos}"
                        ],
                    }
                    logger.debug(
                        "Variable '%s' marked as tainted via binary operation",
                        node.name,
                    )
            else:
                init_str = str(node.initializer)
                if self.source_member in init_str:
                    pos = node.position.line if node.position else "unknown"
                    self.tainted[node.name] = {
                        "source": init_str,
                        "trace": [
                            f"Variable '{node.name}' tainted via fallback at line {pos}"
                        ],
                    }
                    logger.debug(
                        "Variable '%s' marked as tainted via fallback", node.name
                    )
        # Process assignments.
        if isinstance(node, javalang.tree.Assignment):
            left_ids = self.collect_identifiers(node.expressionl)
            right_ids = self.collect_identifiers(node.value)
            for lid in left_ids:
                for rid in right_ids:
                    if rid in self.tainted:
                        pos = node.position.line if node.position else "unknown"
                        # Propagate taint and append to the trace.
                        trace = self.tainted[rid]["trace"] + [
                            f"Variable '{lid}' tainted via assignment from '{rid}' at line {pos}"
                        ]
                        self.tainted[lid] = {
                            "source": self.tainted[rid]["source"],
                            "trace": trace,
                        }
                        logger.debug(
                            "Variable '%s' marked as tainted via assignment from '%s'",
                            lid,
                            rid,
                        )
        # Recurse into children.
        for child in node.children:
            if isinstance(child, list):
                for item in child:
                    if isinstance(item, javalang.tree.Node):
                        self.visit(item)
            elif isinstance(child, javalang.tree.Node):
                self.visit(child)

    def collect_identifiers(self, expr):
        """
        Recursively collects variable identifiers from an expression.
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
        After visiting the AST, traverse it again to find sink method invocations that use a tainted variable.
        Returns a list of vulnerability records, each including a call trace.
        """
        vulns = []
        for path, node in ast_tree:
            if (
                isinstance(node, javalang.tree.MethodInvocation)
                and node.member in sink_list
            ):
                for arg in node.arguments:
                    if self.is_tainted(arg):
                        pos = node.position.line if node.position else 0
                        ids = self.collect_identifiers(arg)
                        # Choose one identifier to represent the tainted variable (if any).
                        var = next(iter(ids), "unknown")
                        trace = self.tainted.get(var, {}).get("trace", [])
                        vulns.append(
                            {
                                "sink": node.member,
                                "source": self.tainted.get(var, {}).get(
                                    "source", "unknown"
                                ),
                                "variable": var,
                                "line": pos,
                                "trace": trace,
                            }
                        )
        return vulns

    def is_tainted(self, expr):
        """
        Determines if the given expression is tainted.
        """
        if isinstance(expr, javalang.tree.MethodInvocation):
            qualifier = getattr(expr, "qualifier", None)
            member = getattr(expr, "member", None)
            if qualifier == self.source_qualifier and member == self.source_member:
                return True
            for arg in expr.arguments:
                if self.is_tainted(arg):
                    return True
        if isinstance(expr, javalang.tree.BinaryOperation):
            return self.is_tainted(expr.operandl) or self.is_tainted(expr.operandr)
        if isinstance(expr, javalang.tree.MemberReference):
            if expr.member in self.tainted:
                return True
        # Fallback: check collected identifiers.
        ids = self.collect_identifiers(expr)
        return any(identifier in self.tainted for identifier in ids)
