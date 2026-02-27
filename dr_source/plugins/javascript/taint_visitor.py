import logging
import os
from typing import List, Dict, Any, Set, Optional
from tree_sitter import Node

logger = logging.getLogger(__name__)

class JavaScriptTaintVisitor:
    def __init__(self, sources: Set[str], sinks: List[Any], sanitizers: Set[str], source_code: bytes, project_index: Optional[Any] = None, depth: int = 0, initial_scope: Optional[Dict[str, Any]] = None):
        # Initialize scopes with initial_scope if provided, else an empty scope
        self.scopes: List[Dict[str, Dict[str, Any]]] = [initial_scope if initial_scope else {}]
        self.constants: List[Dict[str, Any]] = [initial_scope if initial_scope else {}] # Track literal values
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.functions: Dict[str, Node] = {} 
        self.project_index = project_index
        self.depth = depth
        self.max_depth = 3
        self.is_simulation = initial_scope is not None
        self.skip_first_scope = self.is_simulation
        
        self.sinks = {}
        for s in sinks:
            if isinstance(s, dict) and "name" in s:
                self.sinks[s["name"]] = s.get("args")
            elif isinstance(s, str):
                self.sinks[s] = None
                
        self.sources = sources
        self.sanitizers = sanitizers
        self.code = source_code

    def get_text(self, node: Node, alt_code: Optional[bytes] = None) -> str:
        if not node: return ""
        c = alt_code if alt_code is not None else self.code
        return c[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")

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
        """Attempts to resolve a JS node to a constant value."""
        if node.type in ["string", "number", "string_fragment"]:
            val = self.get_text(node)
            return val.strip("'\"")
        if node.type == "identifier":
            return self.get_constant(self.get_text(node))
        if node.type == "binary_expression":
            left_node = node.child_by_field_name("left")
            right_node = node.child_by_field_name("right")
            op_node = [c for c in node.children if c.type in ["+", "-", "*", "/"]]
            if left_node and right_node and op_node and self.get_text(op_node[0]) == "+":
                l_val = self._resolve_value(left_node)
                r_val = self._resolve_value(right_node)
                if isinstance(l_val, str) and isinstance(r_val, str):
                    return l_val + r_val
        return None

    def get_full_member_name(self, node: Node) -> str:
        if node.type == "member_expression":
            obj = self.get_full_member_name(node.child_by_field_name("object"))
            prop = self.get_text(node.child_by_field_name("property"))
            return f"{obj}.{prop}" if obj and prop else ""
        if node.type == "identifier": return self.get_text(node)
        return ""

    def collect_identifiers(self, node: Node, alt_code: Optional[bytes] = None) -> Set[str]:
        ids = set()
        if node.type == "identifier": ids.add(self.get_text(node, alt_code))
        for child in node.children: ids.update(self.collect_identifiers(child, alt_code))
        return ids

    def check_source_or_sanitizer(self, node: Node) -> tuple[Optional[str], Optional[str]]:
        name = ""
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node: name = self.get_full_member_name(func_node)
        elif node.type == "member_expression": name = self.get_full_member_name(node)
        if not name: return None, None
        base = name.split(".")[-1]
        if name in self.sanitizers or base in self.sanitizers: return "sanitizer", name
        if name in self.sources or any(name.startswith(s) for s in self.sources): return "source", name
        return None, None

    def visit(self, node: Node):
        if node is None: return

        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node: self.functions[self.get_text(name_node)] = node

        # SCOPE MANAGEMENT
        is_scope_node = node.type in ["function_declaration", "arrow_function", "method_definition", "statement_block"]
        
        should_push = False
        if is_scope_node:
            if self.skip_first_scope:
                self.skip_first_scope = False # Only skip the very first one
            else:
                should_push = True

        if should_push:
            self.scopes.append({})
            self.constants.append({})

        if node.type in ["variable_declarator", "assignment_expression"]:
            target = node.child_by_field_name("name") or node.child_by_field_name("left")
            value = node.child_by_field_name("value") or node.child_by_field_name("right")
            if target and value:
                if target.type == "identifier":
                    self._handle_assignment(self.get_text(target), value, node.start_point[0] + 1)
                elif target.type == "member_expression":
                    # Check for property sinks (e.g., innerHTML)
                    prop_name = self.get_text(target.child_by_field_name("property"))
                    if prop_name in self.sinks:
                        self._check_sink_violation_for_node(value, prop_name, node.start_point[0] + 1)

        elif node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node:
                name = self.get_full_member_name(func_node)
                base = name.split(".")[-1]
                match_name = None
                if name in self.sinks: match_name = name
                elif base in self.sinks: match_name = base
                else:
                    for s_name in self.sinks:
                        if s_name.endswith("." + base):
                            match_name = s_name; break
                
                if match_name:
                    self._check_sink_violation(node, match_name)
                else:
                    func_def = self.functions.get(name)
                    target_file, target_code = None, None
                    if not func_def and self.project_index and self.depth < self.max_depth:
                        global_def = self.project_index.find_function(name)
                        if global_def and global_def.language == "javascript":
                            func_def = global_def.node["node"]
                            target_code = global_def.node["code"]
                            target_file = global_def.file_path
                    if func_def: self._simulate_call(node, func_def, name, target_file, target_code)

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
        args_node = node.child_by_field_name("arguments")
        if not args_node: return
        actual_args = [child for child in args_node.children if child.is_named]
        vuln_args = self.sinks.get(sink_name)
        for idx, arg in enumerate(actual_args):
            if vuln_args is not None and idx not in vuln_args: continue
            self._check_sink_violation_for_node(arg, sink_name, node.start_point[0] + 1)

    def _check_sink_violation_for_node(self, node: Node, sink_name: str, line: int):
        if self._resolve_value(node) is not None:
            return
        for var_name in self.collect_identifiers(node):
            taint = self.is_tainted(var_name)
            if taint:
                self.vulnerabilities.append({
                    "sink": sink_name,
                    "variable": var_name,
                    "line": line,
                    "trace": taint["trace"]
                })
                break

    def _simulate_call(self, call_node: Node, func_node: Node, func_name: str, target_file: Optional[str], target_code: Optional[bytes]):
        args_node = call_node.child_by_field_name("arguments")
        params_node = func_node.child_by_field_name("parameters")
        if not args_node or not params_node: return
        actual_args = [child for child in args_node.children if child.is_named]
        actual_params = [child for child in params_node.children if child.type in ["identifier", "formal_parameter"]]
        
        t_code = target_code if target_code is not None else self.code
        tainted_params = {}
        for idx, arg in enumerate(actual_args):
            if idx < len(actual_params):
                param_node = actual_params[idx]
                param_name = self.get_text(param_node, t_code)
                for var_name in self.collect_identifiers(arg):
                    taint = self.is_tainted(var_name)
                    if taint:
                        loc = f"in {os.path.basename(target_file)}" if target_file else "locally"
                        tainted_params[param_name] = {"source": taint["source"], "trace": taint["trace"] + [f"Passed to {func_name}() {loc} at line {call_node.start_point[0] + 1}"]}
                        break
        if tainted_params:
            body_node = func_node.child_by_field_name("body")
            if body_node:
                sinks_list = [{"name": n, "args": a} for n, a in self.sinks.items()]
                visitor = JavaScriptTaintVisitor(self.sources, sinks_list, self.sanitizers, t_code, self.project_index, self.depth + 1, initial_scope=tainted_params)
                visitor.visit(body_node)
                self.vulnerabilities.extend(visitor.vulnerabilities)

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        return self.vulnerabilities
