import logging
import os
from typing import List, Dict, Any, Set, Optional
from tree_sitter import Node

logger = logging.getLogger(__name__)

class TaintVisitor:
    def __init__(
        self, source_list: List[str], sink_list: List[Any], sanitizer_list: List[str], source_code: bytes, project_index: Optional[Any] = None, depth: int = 0, initial_scope: Optional[Dict[str, Any]] = None
    ):
        self.scopes: List[Dict[str, Dict[str, Any]]] = [initial_scope if initial_scope else {}]
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.functions: Dict[str, Node] = {} 
        self.project_index = project_index
        self.depth = depth
        self.max_depth = 3
        self.is_simulation = initial_scope is not None
        self.skip_first_scope = self.is_simulation
        
        self.sinks = {}
        for s in sink_list:
            if isinstance(s, dict) and "name" in s:
                self.sinks[s["name"]] = s.get("args")
            elif isinstance(s, str):
                self.sinks[s] = None

        self.sources = set()
        self.sanitizers = set()
        self.code = source_code

        for s in source_list:
            self.sources.add(s.split(".")[-1] if "." in s else s)
        for s in sanitizer_list:
            self.sanitizers.add(s.split(".")[-1] if "." in s else s)

    def get_text(self, node: Node, alt_code: Optional[bytes] = None) -> str:
        if not node: return ""
        c = alt_code if alt_code is not None else self.code
        return c[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")

    def is_tainted(self, var_name: str) -> Optional[Dict[str, Any]]:
        for scope in reversed(self.scopes):
            if var_name in scope: return scope[var_name]
        return None

    def set_tainted(self, var_name: str, data: Dict[str, Any]):
        self.scopes[-1][var_name] = data

    def clear_taint(self, var_name: str):
        if var_name in self.scopes[-1]: del self.scopes[-1][var_name]

    def collect_identifiers(self, node: Node, alt_code: Optional[bytes] = None) -> Set[str]:
        ids = set()
        if node.type == "identifier": ids.add(self.get_text(node, alt_code))
        for child in node.children: ids.update(self.collect_identifiers(child, alt_code))
        return ids

    def get_method_name(self, node: Node) -> str:
        name_node = node.child_by_field_name("name")
        return self.get_text(name_node) if name_node else ""

    def visit(self, node: Node):
        if node is None: return

        if node.type == "method_declaration":
            name = self.get_method_name(node)
            if name: self.functions[name] = node

        # SCOPE MANAGEMENT
        is_scope_node = node.type in ["method_declaration", "constructor_declaration", "block"]
        
        should_push = False
        if is_scope_node:
            if self.skip_first_scope:
                self.skip_first_scope = False
            else:
                should_push = True

        if should_push: self.scopes.append({})

        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node and value_node:
                self._handle_assignment(self.get_text(name_node), value_node, node.start_point[0] + 1)

        elif node.type == "assignment_expression":
            left_node = node.child_by_field_name("left")
            right_node = node.child_by_field_name("right")
            if left_node and right_node:
                self._handle_assignment(self.get_text(left_node), right_node, node.start_point[0] + 1)

        elif node.type == "method_invocation":
            method_name = self.get_method_name(node)
            # SINK RESOLUTION WITH SUFFIX SUPPORT
            match_name = None
            if method_name in self.sinks: match_name = method_name
            else:
                for s_name in self.sinks:
                    if s_name.endswith("." + method_name):
                        match_name = s_name; break
            
            if match_name:
                self._check_sink_violation(node, match_name)
            else:
                func_def = self.functions.get(method_name)
                target_file, target_code = None, None
                if not func_def and self.project_index and self.depth < self.max_depth:
                    global_def = self.project_index.find_function(method_name)
                    if global_def and global_def.language == "java":
                        func_def = global_def.node["node"]
                        target_code = global_def.node["code"]
                        target_file = global_def.file_path
                if func_def:
                    self._simulate_call(node, func_def, method_name, target_file, target_code)

        for child in node.children: self.visit(child)
        if should_push: self.scopes.pop()

    def _handle_assignment(self, var_name: str, value_node: Node, line: int):
        if value_node.type == "method_invocation":
            name = self.get_method_name(value_node)
            if name in self.sanitizers:
                self.clear_taint(var_name); return
            if name in self.sources:
                self.set_tainted(var_name, {"source": name, "trace": [f"Tainted by {name} at line {line}"]}); return
        for identifier in self.collect_identifiers(value_node):
            taint = self.is_tainted(identifier)
            if taint:
                self.set_tainted(var_name, {"source": taint["source"], "trace": taint["trace"] + [f"Propagated to {var_name} at line {line}"]}); return
        self.clear_taint(var_name)

    def _check_sink_violation(self, node: Node, method_name: str):
        args_node = node.child_by_field_name("arguments")
        if not args_node: return
        vuln_args = self.sinks.get(method_name)
        actual_args = [child for child in args_node.children if child.is_named]
        for idx, arg in enumerate(actual_args):
            if vuln_args is not None and idx not in vuln_args: continue
            for var_name in self.collect_identifiers(arg):
                taint = self.is_tainted(var_name)
                if taint:
                    self.vulnerabilities.append({"sink": method_name, "variable": var_name, "line": node.start_point[0] + 1, "trace": taint["trace"]})
                    break

    def _simulate_call(self, call_node: Node, func_node: Node, method_name: str, target_file: Optional[str], target_code: Optional[bytes]):
        args_node = call_node.child_by_field_name("arguments")
        params_node = func_node.child_by_field_name("parameters")
        if not args_node or not params_node: return
        actual_args = [child for child in args_node.children if child.is_named]
        actual_params = [child for child in params_node.children if child.type == "formal_parameter"]
        t_code = target_code if target_code is not None else self.code
        tainted_params = {}
        for idx, arg in enumerate(actual_args):
            if idx < len(actual_params):
                p_name_node = actual_params[idx].child_by_field_name("name")
                if not p_name_node: continue
                param_name = self.get_text(p_name_node, t_code)
                for var_name in self.collect_identifiers(arg):
                    taint = self.is_tainted(var_name)
                    if taint:
                        loc = f"in {os.path.basename(target_file)}" if target_file else "locally"
                        tainted_params[param_name] = {"source": taint["source"], "trace": taint["trace"] + [f"Passed to {method_name}() {loc} at line {call_node.start_point[0] + 1}"]}
                        break
        if tainted_params:
            body_node = func_node.child_by_field_name("body")
            if body_node:
                sinks_list = [{"name": n, "args": a} for n, a in self.sinks.items()]
                visitor = TaintVisitor(list(self.sources), sinks_list, list(self.sanitizers), t_code, self.project_index, self.depth + 1, initial_scope=tainted_params)
                visitor.visit(body_node)
                self.vulnerabilities.extend(visitor.vulnerabilities)

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        return self.vulnerabilities
