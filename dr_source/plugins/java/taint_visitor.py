import logging
from typing import List, Dict, Any, Set, Optional
from tree_sitter import Node

logger = logging.getLogger(__name__)


class TaintVisitor:
    def __init__(
        self, source_list: List[str], sink_list: List[str], source_code: bytes
    ):
        self.tainted: Dict[str, Dict[str, Any]] = {}
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.sinks = set(sink_list)
        self.sources = set(source_list)
        self.code = source_code

        self.sources = set()
        for s in source_list:
            if "." in s:
                self.sources.add(s.split(".")[-1])  # Take the last part
            else:
                self.sources.add(s)

    def get_text(self, node: Node) -> str:
        if not node:
            return ""
        return self.code[node.start_byte : node.end_byte].decode("utf-8")

    def collect_identifiers(self, node: Node) -> Set[str]:
        ids = set()
        if node is None:
            return ids
        if node.type == "identifier":
            ids.add(self.get_text(node))
        for child in node.children:
            ids.update(self.collect_identifiers(child))
        return ids

    def get_method_name(self, node: Node) -> str:
        name_node = node.child_by_field_name("name")
        if name_node:
            return self.get_text(name_node)
        return ""

    def get_method_qualifier(self, node: Node) -> str:
        object_node = node.child_by_field_name("object")
        if object_node:
            return self.get_text(object_node)
        return ""

    def visit(self, node: Node):
        if node is None:
            return

        # 1. Variable Declaration
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")

            if name_node and value_node:
                var_name = self.get_text(name_node)

                if value_node.type == "method_invocation":
                    method_name = self.get_method_name(value_node)
                    if method_name in self.sources:
                        line = node.start_point[0] + 1
                        self.tainted[var_name] = {
                            "source": method_name,
                            "trace": [f"Tainted by {method_name} at line {line}"],
                        }
                else:
                    ids = self.collect_identifiers(value_node)
                    for identifier in ids:
                        if identifier in self.tainted:
                            line = node.start_point[0] + 1
                            self.tainted[var_name] = {
                                "source": self.tainted[identifier]["source"],
                                "trace": self.tainted[identifier]["trace"]
                                + [f"Propagated to {var_name}"],
                            }
                            break

        # 2. Assignment
        elif node.type == "assignment_expression":
            left_node = node.child_by_field_name("left")
            right_node = node.child_by_field_name("right")

            if left_node and right_node:
                var_name = self.get_text(left_node)
                ids = self.collect_identifiers(right_node)
                for identifier in ids:
                    if identifier in self.tainted:
                        line = node.start_point[0] + 1
                        self.tainted[var_name] = {
                            "source": self.tainted[identifier]["source"],
                            "trace": self.tainted[identifier]["trace"]
                            + [f"Propagated to {var_name}"],
                        }
                        break

        # 3. Sink Check
        elif node.type == "method_invocation":
            method_name = self.get_method_name(node)

            if method_name in self.sinks:
                args_node = node.child_by_field_name("arguments")
                if args_node:
                    tainted_args_found = set()
                    for i in range(args_node.child_count):
                        arg = args_node.child(i)
                        ids = self.collect_identifiers(arg)

                        for var_name in ids:
                            if var_name in self.tainted:
                                tainted_args_found.add(var_name)

                    for var in tainted_args_found:
                        line = node.start_point[0] + 1
                        self.vulnerabilities.append(
                            {
                                "sink": method_name,
                                "variable": var,
                                "line": line,
                                "trace": self.tainted[var]["trace"],
                            }
                        )

        # Recurse
        for child in node.children:
            self.visit(child)

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        return self.vulnerabilities
