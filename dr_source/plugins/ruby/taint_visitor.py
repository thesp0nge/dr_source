import logging
import os
from typing import List, Dict, Any, Set, Optional
from tree_sitter import Node

logger = logging.getLogger(__name__)

class RubyTaintVisitor:
    def __init__(self, sources: Set[str], sinks: List[Any], sanitizers: Set[str], source_code: bytes, project_index: Optional[Any] = None, depth: int = 0, initial_scope: Optional[Dict[str, Any]] = None):
        self.scopes: List[Dict[str, Dict[str, Any]]] = [initial_scope if initial_scope else {}]
        self.constants: List[Dict[str, Any]] = [initial_scope if initial_scope else {}]
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.functions: Dict[str, Node] = {} 
        self.project_index = project_index
        self.depth = depth
        self.max_depth = 3
        self.skip_first_scope = initial_scope is not None
        
        self.sinks = {}
        for s in sinks:
            if isinstance(s, dict) and "name" in s:
                self.sinks[s["name"]] = s.get("args")
            elif isinstance(s, str):
                self.sinks[s] = None
                
        self.sources = sources
        self.sanitizers = sanitizers
        self.code = source_code
        logger.debug(f"RubyTaintVisitor initialized with sources: {self.sources}")

    def get_text(self, node: Node) -> str:
        if not node: return ""
        return self.code[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")

    def is_tainted(self, var_name: str) -> Optional[Dict[str, Any]]:
        for scope in reversed(self.scopes):
            if var_name in scope: return scope[var_name]
        return None

    def get_constant(self, var_name: str) -> Any:
        for scope in reversed(self.constants):
            if var_name in scope: return scope[var_name]
        return None

    def set_constant(self, var_name: str, value: Any):
        self.constants[-1][var_name] = value

    def set_tainted(self, var_name: str, data: Dict[str, Any]):
        self.scopes[-1][var_name] = data
        if var_name in self.constants[-1]: del self.constants[-1][var_name]

    def clear_taint(self, var_name: str):
        if var_name in self.scopes[-1]: del self.scopes[-1][var_name]

    def _resolve_value(self, node: Node) -> Any:
        if node.type in ["string", "integer", "symbol", "string_content"]:
            # A Ruby string is only a constant if it has no interpolation
            if node.type == "string":
                for child in node.children:
                    if child.type == "interpolation":
                        return None
            return self.get_text(node).strip("'\":")
        if node.type == "identifier":
            return self.get_constant(self.get_text(node))
        return None

    def collect_identifiers(self, node: Node) -> Set[str]:
        # logger.debug(f"collect_identifiers visiting {node.type}")
        ids = set()
        if node.type == "identifier":
            ids.add(self.get_text(node))
        for child in node.children:
            ids.update(self.collect_identifiers(child))
        if ids: logger.debug(f"COLLECTED IDs from {node.type}: {ids}")
        return ids

    def check_source_or_sanitizer(self, node: Node) -> tuple[Optional[str], Optional[str]]:
        name = ""
        if node.type == "call":
            method_node = node.child_by_field_name("method")
            if method_node: name = self.get_text(method_node)
        elif node.type == "identifier":
            name = self.get_text(node)
        elif node.type == "element_reference":
            obj_node = node.children[0]
            if obj_node: name = self.get_text(obj_node)
        
        if not name: return None, None
        logger.debug(f"CHECKING SOURCE/SAN: '{name}' against sources {self.sources}")
        if name in self.sanitizers: return "sanitizer", name
        if name in self.sources: return "source", name
        return None, None

    def get_method_name(self, node: Node) -> str:
        method_node = node.child_by_field_name("method")
        if method_node: return self.get_text(method_node)
        for child in node.children:
            if child.type == "identifier": return self.get_text(child)
        return ""

    def visit(self, node: Node):
        if node is None: return

        if node.type == "method":
            name_node = node.child_by_field_name("name")
            if name_node: self.functions[self.get_text(name_node)] = node

        is_scope_node = node.type in ["method", "do_block", "block"]
        should_push = False
        if is_scope_node:
            if self.skip_first_scope: self.skip_first_scope = False
            else: should_push = True

        if should_push:
            self.scopes.append({})
            self.constants.append({})

        if node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right and left.type == "identifier":
                self._handle_assignment(self.get_text(left), right, node.start_point[0] + 1)

        elif node.type == "call":
            method_name = self.get_method_name(node)
            if method_name:
                match_name = None
                if method_name in self.sinks: match_name = method_name
                else:
                    for s_name in self.sinks:
                        if s_name.endswith("." + method_name) or s_name == method_name:
                            match_name = s_name; break
                if match_name: self._check_sink_violation(node, match_name)

        for child in node.children: self.visit(child)
        if should_push:
            self.constants.pop()
            self.scopes.pop()

    def _handle_assignment(self, var_name: str, value_node: Node, line: int):
        logger.debug(f"HANDLING ASSIGNMENT: {var_name} = {value_node.type} at line {line}")
        const_val = self._resolve_value(value_node)
        if const_val is not None:
            self.set_constant(var_name, const_val)
            self.clear_taint(var_name)
            return

        kind, name = self.check_source_or_sanitizer(value_node)
        if kind == "sanitizer": self.clear_taint(var_name); return
        if kind == "source":
            logger.debug(f"TAINTED: {var_name} by {name}")
            self.set_tainted(var_name, {"source": name, "trace": [f"Tainted by source {name} at line {line}"]})
            return
        
        for identifier in self.collect_identifiers(value_node):
            taint = self.is_tainted(identifier)
            if taint:
                logger.debug(f"TAINT PROPAGATED: {identifier} -> {var_name}")
                self.set_tainted(var_name, {"source": taint["source"], "trace": taint["trace"] + [f"Propagated to {var_name} at line {line}"]})
                return
        self.clear_taint(var_name)

    def _check_sink_violation(self, node: Node, sink_name: str):
        args_node = node.child_by_field_name("arguments")
        actual_args = []
        if args_node:
            actual_args = [child for child in args_node.children if child.is_named]
        else:
            actual_args = [child for child in node.children if child.is_named and child.type not in ["identifier", "constant", "symbol", ".", "method_call", "scope_resolution"]]
        
        logger.debug(f"CHECKING SINK VIOLATION: {sink_name}, args: {[a.type for a in actual_args]}")
        vuln_args = self.sinks.get(sink_name)
        for idx, arg in enumerate(actual_args):
            if vuln_args is not None and idx not in vuln_args: continue
            if self._resolve_value(arg) is not None: continue
            for var_name in self.collect_identifiers(arg):
                taint = self.is_tainted(var_name)
                if taint:
                    logger.debug(f"VULNERABILITY FOUND: {sink_name} via {var_name}")
                    self.vulnerabilities.append({
                        "sink": sink_name,
                        "variable": var_name,
                        "line": node.start_point[0] + 1,
                        "trace": taint["trace"]
                    })
                    break
