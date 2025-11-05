import javalang
import logging
from javalang.tree import (
    Node,
    VariableDeclarator,
    MethodInvocation,
    BinaryOperation,
    Assignment,
    MemberReference,
)
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)


class TaintVisitor:
    """
    Visits the Java AST to find variables tainted by insecure sources
    AND checks if they are used in dangerous sinks *in a single pass*.
    """

    def __init__(self, source_list: List[str], sink_list: List[str]):
        """
        Initializes the visitor with dynamic sources AND sinks from the KB.
        """
        self.tainted: Dict[str, Dict[str, Any]] = {}
        self.vulnerabilities: List[Dict[str, Any]] = []

        # 1. Process Sources (e.g., "request.getParameter")
        self.processed_sources: Set[tuple] = set()
        for source in source_list:
            parts = source.split(".")
            if len(parts) > 1:
                self.processed_sources.add((parts[0], parts[-1]))
            else:
                self.processed_sources.add((None, source))

        # 2. Process Sinks (e.g., "Statement.executeQuery")
        self.processed_sinks: Set[tuple] = set()
        for sink in sink_list:
            parts = sink.split(".")
            if len(parts) > 1:
                # We only care about the member name for sinks,
                # as the qualifier (variable name) can change.
                # We'll check the member name and *then* check the qualifier
                # to see if it's a known sink type (e.g., "Statement").
                # For now, let's just use the member.
                # A more advanced check would store ('Statement', 'executeQuery')
                self.processed_sinks.add(parts[-1])  # Just "executeQuery"
            else:
                self.processed_sinks.add(sink)

        # --- A BETTER SINK LOGIC ---
        # Let's assume sinks in the KB are just the method name for now.
        # This is simpler and more robust.
        # e.g., "executeQuery", "exec"
        self.processed_sinks = set(sink_list)

    def collect_identifiers(self, node: Node) -> Set[str]:
        """
        Recursively collects all variable names (MemberReference)
        from a given AST node and its children.
        """
        ids = set()
        if node is None:
            return ids
        if isinstance(node, MemberReference):
            ids.add(node.member)  # type: ignore
        if hasattr(node, "children"):
            for child in node.children:
                if isinstance(child, list):
                    for item in child:
                        if isinstance(item, Node):
                            ids.update(self.collect_identifiers(item))
                elif isinstance(child, Node):
                    ids.update(self.collect_identifiers(child))
        return ids

    def visit(self, node: Node):
        """
        Recursively visits the AST, propagates taint, and checks for sinks.
        """
        if node is None:
            return

        # === 1. Taint Propagation Logic (from before, is correct) ===
        if (
            isinstance(node, VariableDeclarator) and node.initializer is not None  # type: ignore
        ):
            if isinstance(node.initializer, MethodInvocation):  # type: ignore
                qualifier = getattr(node.initializer, "qualifier", None)
                member = getattr(node.initializer, "member", None)
                if (qualifier, member) in self.processed_sources:
                    pos = node.position.line if node.position else "unknown"
                    self.tainted[node.name] = {  # type: ignore
                        "source": f"{qualifier}.{member}",
                        "trace": [
                            f"Variable '{node.name}' tainted by source {qualifier}.{member}() at line {pos}"
                        ],  # type: ignore
                    }
            elif isinstance(node.initializer, BinaryOperation):  # type: ignore
                ids = self.collect_identifiers(node.initializer)  # type: ignore
                for identifier in ids:
                    if identifier in self.tainted:
                        pos = node.position.line if node.position else "unknown"
                        self.tainted[node.name] = {  # type: ignore
                            "source": self.tainted[identifier]["source"],
                            "trace": self.tainted[identifier]["trace"]
                            + [
                                f"Variable '{node.name}' tainted via binary operation at line {pos}"
                            ],  # type: ignore
                        }
                        break
        if isinstance(node, Assignment):
            if isinstance(node.expression, MemberReference):  # type: ignore
                left_var = node.expression.member  # type: ignore
                right_ids = self.collect_identifiers(node.value)  # type: ignore
                for rid in right_ids:
                    if rid in self.tainted:
                        pos = node.position.line if node.position else "unknown"
                        self.tainted[left_var] = {
                            "source": self.tainted[rid]["source"],
                            "trace": self.tainted[rid]["trace"]
                            + [
                                f"Variable '{left_var}' tainted via assignment from '{rid}' at line {pos}"
                            ],
                        }
                        break

        # === 2. Sink Checking Logic (NEW) ===
        if isinstance(node, MethodInvocation):
            # Check if this method's *name* is a known sink
            sink_member = node.member  # type: ignore
            if sink_member in self.processed_sinks:
                # This is a sink. Check if any arguments are tainted.
                tainted_args_found = set()
                for arg in node.arguments:  # type: ignore
                    arg_ids = self.collect_identifiers(arg)
                    for var_name in arg_ids:
                        if var_name in self.tainted:
                            tainted_args_found.add(var_name)

                # Create vulnerabilities for all tainted args found
                for var in tainted_args_found:
                    self.vulnerabilities.append(
                        {
                            "sink": sink_member,
                            "variable": var,
                            "line": node.position.line if node.position else "unknown",
                            "trace": self.tainted[var]["trace"],
                        }
                    )

        # === 3. Recurse (Unchanged) ===
        if hasattr(node, "children"):
            for child in node.children:
                if isinstance(child, list):
                    for item in child:
                        if isinstance(item, Node):
                            self.visit(item)
                elif isinstance(child, Node):
                    self.visit(child)

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Returns the vulnerabilities found during the visit.
        """
        return self.vulnerabilities
