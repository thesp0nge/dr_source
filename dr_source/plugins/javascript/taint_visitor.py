import logging
import os
from typing import List, Dict, Any, Set, Optional
from tree_sitter import Node

logger = logging.getLogger(__name__)

class JavaScriptTaintVisitor:
    def __init__(self, sources: Set[str], sinks: List[Any], sanitizers: Set[str], source_code: bytes, project_index: Optional[Any] = None, depth: int = 0, initial_scope: Optional[Dict[str, Any]] = None):
        self.scopes: List[Dict[str, Dict[str, Any]]] = [initial_scope if initial_scope else {}]
        self.constants: List[Dict[str, Any]] = [{}]
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.functions: Dict[str, Node] = {} 
        self.project_index = project_index
        self.depth = depth
        self.max_depth = 3
        self.is_simulation = initial_scope is not None
        self.skip_first_scope = self.is_simulation
        
        self.sinks = {}
        for s in sinks:
            if isinstance(s, dict) and "name" in s: self.sinks[s["name"]] = s.get("args")
            elif isinstance(s, str): self.sinks[s] = None
                
        self.sources = sources
        self.sanitizers = sanitizers
        self.code = source_code
        # PII Patterns
        self.pii_names = {"password", "email", "secret", "token", "credit_card", "cc", "ssn"}

    def get_text(self, node: Node) -> str:
        if not node: return ""
        return self.code[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")

    def _get_full_path(self, node: Node) -> Optional[str]:
        if node.type == "identifier": return self.get_text(node)
        if node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            if obj and prop:
                base = self._get_full_path(obj)
                return f"{base}.{self.get_text(prop)}" if base else None
        return None

    def is_tainted(self, path: str) -> Optional[Dict[str, Any]]:
        for scope in reversed(self.scopes):
            if path in scope: return scope[path]
            if "." in path:
                base = path.split(".")[0]
                if base in scope: return scope[base]
        return None

    def get_constant(self, var_name: str) -> Any:
        for scope in reversed(self.constants):
            if var_name in scope: return scope[var_name]
        return None

    def set_constant(self, path: str, value: Any):
        self.constants[-1][path] = value

    def set_tainted(self, path: str, data: Dict[str, Any]):
        self.scopes[-1][path] = data
        if path in self.constants[-1]: del self.constants[-1][path]

    def clear_taint(self, path: str):
        if path in self.scopes[-1]: del self.scopes[-1][path]

    def _resolve_value(self, node: Node) -> Any:
        if node.type in ["string", "number", "string_fragment"]:
            return self.get_text(node).strip("'\"")
        path = self._get_full_path(node)
        if path: return self.get_constant(path)
        if node.type == "binary_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            op = node.child_by_field_name("operator")
            if left and right and op and self.get_text(op) == "+":
                l_val, r_val = self._resolve_value(left), self._resolve_value(right)
                if isinstance(l_val, str) and isinstance(r_val, str): return l_val + r_val
        return None

    def collect_identifiers(self, node: Node) -> Set[str]:
        paths = set()
        path = self._get_full_path(node)
        if path: paths.add(path)
        for child in node.children: paths.update(self.collect_identifiers(child))
        return paths

    def check_source_or_sanitizer(self, node: Node, var_name: Optional[str] = None) -> tuple[Optional[str], Optional[str]]:
        # Heuristic: Check if variable name is sensitive
        if var_name:
            clean_name = var_name.lower().split(".")[-1]
            if any(p in clean_name for p in self.pii_names):
                return "source", f"Sensitive variable name: {var_name}"

        name = ""
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func: name = self._get_full_path(func) or ""
        else:
            path = self._get_full_path(node)
            if path: name = path
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

        is_scope = node.type in ["function_declaration", "arrow_function", "method_definition", "statement_block"]
        should_push = is_scope and not self.skip_first_scope
        if is_scope and self.skip_first_scope: self.skip_first_scope = False
        if should_push:
            self.scopes.append({}); self.constants.append({})

        if node.type in ["variable_declarator", "assignment_expression"]:
            target = node.child_by_field_name("name") or node.child_by_field_name("left")
            value = node.child_by_field_name("value") or node.child_by_field_name("right")
            if target and value:
                path = self._get_full_path(target)
                if path: self._handle_assignment(path, value, node.start_point[0] + 1)
                elif target.type == "member_expression":
                    prop = self.get_text(target.child_by_field_name("property"))
                    if prop in self.sinks: self._check_sink_violation_for_node(value, prop, node.start_point[0] + 1)

        elif node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func:
                name = self._get_full_path(func) or ""
                base = name.split(".")[-1]
                match_name = None
                if name in self.sinks: match_name = name
                elif base in self.sinks: match_name = base
                else:
                    for s in self.sinks:
                        if s.endswith("." + base) or s == base: match_name = s; break
                if match_name: self._check_sink_violation(node, match_name)
                else:
                    f_def = self.functions.get(name)
                    if not f_def and self.project_index and self.depth < self.max_depth:
                        g = self.project_index.find_function(name)
                        if g and g.language == "javascript":
                            self._simulate_call(node, g.node["node"], name, g.file_path, g.node["code"])
                    elif f_def: self._simulate_call(node, f_def, name, None, None)

        for child in node.children: self.visit(child)
        if should_push:
            self.constants.pop(); self.scopes.pop()

    def _handle_assignment(self, path: str, value_node: Node, line: int):
        kind, name = self.check_source_or_sanitizer(value_node, var_name=path)
        if kind == "sanitizer": self.clear_taint(path); return
        if kind == "source":
            self.set_tainted(path, {"source": name, "trace": [f"Tainted by {name} at line {line}"]}); return

        const_val = self._resolve_value(value_node)
        if const_val is not None:
            self.set_constant(path, const_val); self.clear_taint(path); return

        for p in self.collect_identifiers(value_node):
            t = self.is_tainted(p)
            if t:
                self.set_tainted(path, {"source": t["source"], "trace": t["trace"] + [f"Propagated to {path} at line {line}"]}); return
        self.clear_taint(path)

    def _check_sink_violation(self, node: Node, sink_name: str):
        args_node = node.child_by_field_name("arguments")
        if not args_node: return
        vuln_args = self.sinks.get(sink_name)
        actual_args = [child for child in args_node.children if child.is_named]
        for idx, arg in enumerate(actual_args):
            if vuln_args is not None and idx not in vuln_args: continue
            self._check_sink_violation_for_node(arg, sink_name, node.start_point[0] + 1)

    def _check_sink_violation_for_node(self, node: Node, sink_name: str, line: int):
        for path in self.collect_identifiers(node):
            t = self.is_tainted(path)
            if t: self.vulnerabilities.append({"sink": sink_name, "variable": path, "line": line, "trace": t["trace"]}); break

    def _simulate_call(self, call_node: Node, func_node: Node, func_name: str, target_file: Optional[str], target_code: Optional[bytes]):
        args_node, params_node = call_node.child_by_field_name("arguments"), func_node.child_by_field_name("parameters")
        if not args_node or not params_node: return
        actual_args = [c for c in args_node.children if c.is_named]
        actual_params = [c for c in params_node.children if c.type in ["identifier", "formal_parameter"]]
        t_code = target_code if target_code is not None else self.code
        tainted = {}
        for idx, arg in enumerate(actual_args):
            if idx < len(actual_params):
                p_name_node = actual_params[idx]
                if p_name_node.type == "formal_parameter":
                    p_name_node = p_name_node.child_by_field_name("name") or p_name_node
                p_name = t_code[p_name_node.start_byte : p_name_node.end_byte].decode("utf-8")
                for path in self.collect_identifiers(arg):
                    t = self.is_tainted(path)
                    if t:
                        loc = f"in {os.path.basename(target_file)}" if target_file else "locally"
                        tainted[p_name] = {"source": t["source"], "trace": t["trace"] + [f"Passed to {func_name}() {loc} at line {call_node.start_point[0] + 1}"]}
                        break
        if tainted:
            body = func_node.child_by_field_name("body")
            if body:
                v = JavaScriptTaintVisitor(self.sources, [{"name": n, "args": a} for n, a in self.sinks.items()], self.sanitizers, t_code, self.project_index, self.depth + 1, initial_scope=tainted)
                v.visit(body); self.vulnerabilities.extend(v.vulnerabilities)

    def get_vulnerabilities(self) -> List[Dict[str, Any]]: return self.vulnerabilities
