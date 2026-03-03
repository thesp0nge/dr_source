import logging
import os
from typing import List, Dict, Any, Set, Optional
from tree_sitter import Node

logger = logging.getLogger(__name__)

class PHPTaintVisitor:
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
        if node.type in ["string", "integer", "encapsed_string"]:
            return self.get_text(node).strip("'\"")
        if node.type == "variable_name":
            return self.get_constant(self.get_text(node))
        return None

    def collect_identifiers(self, node: Node) -> Set[str]:
        ids = set()
        if node.type == "variable_name": ids.add(self.get_text(node))
        for child in node.children: ids.update(self.collect_identifiers(child))
        return ids

    def check_source_or_sanitizer(self, node: Node) -> tuple[Optional[str], Optional[str]]:
        name = ""
        if node.type == "function_call_expression":
            func_node = node.child_by_field_name("function")
            if func_node: name = self.get_text(func_node)
        elif node.type == "variable_name":
            name = self.get_text(node)
        elif node.type == "subscript_expression":
            # Handle $_GET['id']
            obj_node = node.child_by_field_name("callable") or node.children[0]
            if obj_node: name = self.get_text(obj_node)
        
        if not name: return None, None
        if name in self.sanitizers: return "sanitizer", name
        if name in self.sources or any(name.startswith(s) for s in self.sources):
            return "source", name
        return None, None

    def visit(self, node: Node):
        if node is None: return

        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node: self.functions[self.get_text(name_node)] = node

        is_scope_node = node.type in ["function_definition", "method_definition"]
        should_push = False
        if is_scope_node:
            if self.skip_first_scope: self.skip_first_scope = False
            else: should_push = True

        if should_push:
            self.scopes.append({})
            self.constants.append({})

        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right and (left.type == "variable_name" or left.type == "subscript_expression"):
                self._handle_assignment(self.get_text(left), right, node.start_point[0] + 1)

        elif node.type == "function_call_expression":
            func_node = node.child_by_field_name("function")
            if func_node:
                name = self.get_text(func_node)
                if name in self.sinks:
                    self._check_sink_violation(node, name)

        # In PHP, 'echo' is often a statement, not a function call
        elif node.type == "echo_statement":
            if "echo" in self.sinks:
                self._check_sink_violation(node, "echo")

        for child in node.children: self.visit(child)
        if should_push:
            self.constants.pop()
            self.scopes.pop()

    def _handle_assignment(self, var_name: str, value_node: Node, line: int):
        const_val = self._resolve_value(value_node)
        if const_val is not None:
            self.set_constant(var_name, const_val)
            self.clear_taint(var_name)
            return

        kind, name = self.check_source_or_sanitizer(value_node)
        if kind == "sanitizer": self.clear_taint(var_name); return
        if kind == "source":
            self.set_tainted(var_name, {"source": name, "trace": [f"Tainted by source {name} at line {line}"]})
            return
        
        for identifier in self.collect_identifiers(value_node):
            taint = self.is_tainted(identifier)
            if taint:
                self.set_tainted(var_name, {"source": taint["source"], "trace": taint["trace"] + [f"Propagated to {var_name} at line {line}"]})
                return
        self.clear_taint(var_name)

    def _check_sink_violation(self, node: Node, sink_name: str):
        # For echo_statement, arguments are direct children
        if node.type == "echo_statement":
            actual_args = [c for c in node.children if c.is_named and c.type != "echo"]
        else:
            args_node = node.child_by_field_name("arguments")
            actual_args = [child for child in args_node.children if child.is_named] if args_node else []
        
        vuln_args = self.sinks.get(sink_name)
        for idx, arg in enumerate(actual_args):
            if vuln_args is not None and idx not in vuln_args: continue
            if self._resolve_value(arg) is not None: continue
            for var_name in self.collect_identifiers(arg):
                taint = self.is_tainted(var_name)
                if taint:
                    self.vulnerabilities.append({
                        "sink": sink_name,
                        "variable": var_name,
                        "line": node.start_point[0] + 1,
                        "trace": taint["trace"]
                    })
                    break
