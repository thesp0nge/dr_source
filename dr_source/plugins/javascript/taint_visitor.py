import logging
from typing import List, Dict, Any, Set
from tree_sitter import Node

logger = logging.getLogger(__name__)


class JavaScriptTaintVisitor:
    """
    Performs taint analysis on the JavaScript Tree-sitter AST.
    """

    def __init__(self, sources: Set[str], sinks: Set[str], source_code: bytes):
        self.sources = sources
        self.sinks = sinks
        self.code = source_code
        self.tainted_vars: Dict[str, List[str]] = {}  # {var_name: [trace]}
        self.vulnerabilities: List[Dict[str, Any]] = []

    def get_text(self, node: Node) -> str:
        """Helper to get the source text for a node."""
        if not node:
            return ""
        return self.code[node.start_byte : node.end_byte].decode("utf-8")

    def get_full_member_name(self, node: Node) -> str:
        """Reconstructs full names like 'req.query.command' or 'child_process.exec'"""
        if node.type == "member_expression":
            obj = self.get_full_member_name(node.child_by_field_name("object"))
            prop = self.get_text(node.child_by_field_name("property"))
            if obj and prop:
                return f"{obj}.{prop}"

        if node.type == "identifier":
            return self.get_text(node)

        return ""

    def collect_identifiers(self, node: Node) -> Set[str]:
        """Recursively finds all identifier names (variables) in an expression."""
        ids = set()
        if not node:
            return ids

        for child in node.children:
            ids.update(self.collect_identifiers(child))

        if node.type == "identifier":
            ids.add(self.get_text(node))

        return ids

    def check_for_source(self, node: Node) -> tuple[bool, str]:
        """Checks if a node is a known source method invocation OR member access."""

        # Case A: Simple Call Expression (e.g., req.param('...'))
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node:
                func_name = self.get_full_member_name(func_node)
                if func_name in self.sources:
                    return True, func_name
            return False, ""

        # Case B: Member Access (e.g., req.query.command)
        elif node.type == "member_expression":
            full_name = self.get_full_member_name(node)

            # Check if the access chain starts with a known source object
            # e.g., if 'req.query' is a source, then 'req.query.command' is tainted.
            for source_obj in self.sources:
                if full_name.startswith(source_obj):
                    return True, source_obj
            return False, ""

        return False, ""

    def visit(self, node: Node):
        """Recursive tree walker."""

        # 1. Assignment or Variable Declaration (Taint Source/Propagation)
        if node.type in [
            "variable_declarator",
            "assignment_expression",
            "lexical_declaration",
        ]:
            # Find the variable being assigned to
            target_node = node.child_by_field_name("name") or node.child_by_field_name(
                "left"
            )
            value_node = node.child_by_field_name("value") or node.child_by_field_name(
                "right"
            )

            if target_node and value_node and target_node.type == "identifier":
                target_var = self.get_text(target_node)

                is_source, source_name = self.check_for_source(value_node)

                # Check for Taint Source
                if is_source:
                    self.tainted_vars[target_var] = [
                        f"Tainted by source {source_name} at line {node.start_point[0] + 1}"
                    ]

                # Check for Taint Propagation (e.g., cmd_str = "echo " + cmd)
                else:
                    ids = self.collect_identifiers(value_node)
                    for identifier in ids:
                        if identifier in self.tainted_vars:
                            # Propagate the trace
                            new_trace = self.tainted_vars[identifier] + [
                                f"Propagated to '{target_var}' at line {node.start_point[0] + 1}"
                            ]
                            self.tainted_vars[target_var] = new_trace
                            break

        # 2. Sink Check (Call Expression)
        elif node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node:
                sink_name = self.get_full_member_name(func_node)

                # Check if the function name is a known sink (either full name or simple name)
                is_sink = (
                    sink_name in self.sinks or sink_name.split(".")[-1] in self.sinks
                )

                if is_sink:
                    args_node = node.child_by_field_name("arguments")
                    if args_node:
                        # Check all arguments for tainted variables
                        for arg in args_node.children:
                            ids = self.collect_identifiers(arg)
                            for var_name in ids:
                                if var_name in self.tainted_vars:
                                    # Vulnerability found!
                                    self.vulnerabilities.append(
                                        {
                                            "vuln_type": "COMMAND_INJECTION",
                                            "sink": sink_name,
                                            "variable": var_name,
                                            "line": node.start_point[0] + 1,
                                            "trace": self.tainted_vars[var_name],
                                        }
                                    )
                                    break  # Stop checking args for this sink

        # 3. Recurse (Manual recursion for Tree-sitter)
        for child in node.children:
            self.visit(child)

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        return self.vulnerabilities
