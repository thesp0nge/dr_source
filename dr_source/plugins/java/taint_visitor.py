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
from typing import List, Dict, Any, Set, Optional

logger = logging.getLogger(__name__)


class TaintVisitor:
    """
    Visits the Java AST to find variables tainted by insecure sources
    and checks if they are used in dangerous sinks.
    This class uses a recursive 'visit' method.
    """

    def __init__(self, source_list: List[str], sink_list: List[str]):
        """
        Initializes the visitor with dynamic sources and sinks from the KB.
        """
        self.tainted: Dict[str, Dict[str, Any]] = {}
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.sinks = sink_list  # Store sinks for later use

        self.processed_sources: Set[tuple] = set()
        for source in source_list:
            if "." in source:
                parts = source.split(".")
                self.processed_sources.add((parts[0], parts[-1]))
            else:
                self.processed_sources.add((None, source))

    def collect_identifiers(self, node: Node) -> Set[str]:
        """
        Recursively collects all variable names (MemberReference)
        from a given AST node and its children.
        """
        ids = set()
        if node is None:
            return ids

        # 1. Base Case: The node itself is a variable
        if isinstance(node, MemberReference):
            ids.add(node.member)  # type: ignore

        # 2. Recursive Step: Walk all children
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
        Recursively visits the AST and propagates taint.
        """
        if node is None:
            return

        # 1. Taint Source: A variable is declared and initialized from a source
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
                            f"Variable '{node.name}' tainted by source {qualifier}.{member}() at line {pos}"  # type: ignore
                        ],
                    }
                    logger.debug(
                        "Variable '%s' marked as tainted (source: %s)",
                        node.name,  # type: ignore
                        f"{qualifier}.{member}",
                    )

            # 2. Taint Propagation: A variable is initialized from a binary operation
            elif isinstance(node.initializer, BinaryOperation):  # type: ignore
                # This will now correctly find 'userId'
                ids = self.collect_identifiers(node.initializer)  # type: ignore
                for identifier in ids:
                    if identifier in self.tainted:
                        pos = node.position.line if node.position else "unknown"
                        self.tainted[node.name] = {  # type: ignore
                            "source": self.tainted[identifier]["source"],
                            "trace": self.tainted[identifier]["trace"]
                            + [
                                f"Variable '{node.name}' tainted via binary operation at line {pos}"  # type: ignore
                            ],
                        }
                        logger.debug(
                            "Variable '%s' marked as tainted via binary op",
                            node.name,  # type: ignore
                        )
                        break

        # 3. Taint Propagation: A variable is assigned a tainted value
        if isinstance(node, Assignment):
            # javalang uses 'expressionl' (left side) for Assignment
            left_side = getattr(node, "expressionl", None)

            if isinstance(left_side, MemberReference):
                left_var = left_side.member

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
                        logger.debug(
                            "Variable '%s' marked as tainted via assignment from '%s'",
                            left_var,
                            rid,
                        )
                        break

        # Recurse into children
        if hasattr(node, "children"):
            for child in node.children:
                if isinstance(child, list):
                    for item in child:
                        if isinstance(item, Node):
                            self.visit(item)
                elif isinstance(child, Node):
                    self.visit(child)

    def get_vulnerabilities(
        self, ast_tree: Node, sink_list: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Finds all sinks in the tree and checks if they use tainted variables.
        """
        self.vulnerabilities = []

        # Use sinks passed here, or fallback to self.sinks initialized in __init__
        sinks_to_check = sink_list if sink_list is not None else self.sinks

        for _, node in ast_tree:
            if isinstance(node, MethodInvocation):
                if node.member in sinks_to_check:  # type: ignore
                    tainted_args_found = set()

                    for arg in node.arguments:  # type: ignore
                        arg_ids = self.collect_identifiers(arg)
                        for var_name in arg_ids:
                            if var_name in self.tainted:
                                tainted_args_found.add(var_name)

                    for var in tainted_args_found:
                        self.vulnerabilities.append(
                            {
                                "sink": node.member,  # type: ignore
                                "variable": var,
                                "line": node.position.line
                                if node.position
                                else "unknown",
                                "trace": self.tainted[var]["trace"],
                            }
                        )

        return self.vulnerabilities
