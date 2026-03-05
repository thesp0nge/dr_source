import logging
import os
from typing import List, Dict, Any, Set, Optional
from tree_sitter import Node

from .frameworks import SpringBootMapper, JakartaEEMapper, JaxRsMapper, HibernateMapper

logger = logging.getLogger(__name__)

class TaintVisitor:
    def __init__(
        self, source_list: List[str], sink_list: List[Any], sanitizer_list: List[str], source_code: bytes, project_index: Optional[Any] = None, depth: int = 0, initial_scope: Optional[Dict[str, Any]] = None
    ):
        self.scopes: List[Dict[str, Dict[str, Any]]] = [initial_scope if initial_scope else {}]
        self.constants: List[Dict[str, Any]] = [{}]
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.functions: Dict[str, Node] = {} 
        self.project_index = project_index
        self.depth = depth
        self.max_depth = 3
        self.is_simulation = initial_scope is not None
        self.skip_first_scope = self.is_simulation
        self.code = source_code
        
        self.framework_mappers = [SpringBootMapper(), JakartaEEMapper(), JaxRsMapper(), HibernateMapper()]
        self.sinks = {}
        for s in sink_list:
            if isinstance(s, dict) and "name" in s: self.sinks[s["name"]] = s.get("args")
            elif isinstance(s, str): self.sinks[s] = None

        self.sources = set(s.split(".")[-1] for s in source_list)
        self.sanitizers = set(s.split(".")[-1] for s in sanitizer_list)
        # PII Patterns
        self.pii_names = {"password", "email", "secret", "token", "credit_card", "cc", "ssn"}

    def get_text(self, node: Node) -> str:
        if not node: return ""
        return self.code[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")

    def _get_full_path(self, node: Node) -> Optional[str]:
        if node.type == "identifier": return self.get_text(node)
        if node.type == "field_access":
            obj = node.child_by_field_name("object")
            field = node.child_by_field_name("field")
            if obj and field:
                base = self._get_full_path(obj)
                return f"{base}.{self.get_text(field)}" if base else None
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
        if node.type in ["string_literal", "decimal_integer_literal"]:
            return self.get_text(node).strip("'\"")
        path = self._get_full_path(node)
        if path: return self.get_constant(path)
        if node.type == "binary_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left and right:
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
        if node.type == "method_invocation": name = self.get_method_name(node)
        else:
            path = self._get_full_path(node)
            if path: name = path
        if not name: return None, None
        if name in self.sanitizers: return "sanitizer", name
        if name in self.sources: return "source", name
        for mapper in self.framework_mappers:
            if isinstance(mapper, JakartaEEMapper) and name in mapper.SERVLET_SOURCES: return "source", name
        return None, None

    def get_method_name(self, node: Node) -> str:
        name_node = node.child_by_field_name("name")
        if name_node: return self.get_text(name_node)
        for child in node.children:
            if child.type == "identifier": return self.get_text(child)
        return ""

    def visit(self, node: Node):
        if node is None: return
        if node.type in ["class_declaration", "program"]:
            for child in node.children:
                if child.type == "class_body":
                    for gc in child.children:
                        if gc.type == "method_declaration":
                            m_name = self.get_method_name(gc)
                            if m_name: self.functions[m_name] = gc

        if node.type == "method_declaration":
            name = self.get_method_name(node)
            if name: self.functions[name] = node
        
        if node.type == "formal_parameter":
            p_name_node = node.child_by_field_name("name") or next((c for c in node.children if c.type == "identifier"), None)
            if p_name_node:
                p_name = self.get_text(p_name_node)
                if any(p in p_name.lower() for p in self.pii_names):
                    self.set_tainted(p_name, {"source": f"Sensitive parameter: {p_name}", "trace": [f"Sensitive data in parameter {p_name} at line {node.start_point[0] + 1}"]})

            for mapper in self.framework_mappers:
                src_name = mapper.get_source_name(node, self.code)
                if src_name: self.set_tainted(src_name, {"source": "Framework", "trace": [f"Tainted by {mapper.__class__.__name__} at line {node.start_point[0] + 1}"]})

        is_scope_node = node.type in ["method_declaration", "constructor_declaration", "block"]
        should_push = is_scope_node and not self.skip_first_scope
        if is_scope_node and self.skip_first_scope: self.skip_first_scope = False
        if should_push:
            self.scopes.append({}); self.constants.append({})

        if node.type in ["variable_declarator", "assignment_expression"]:
            target_node = node.child_by_field_name("name") or node.child_by_field_name("left")
            value = node.child_by_field_name("value") or node.child_by_field_name("right")
            if target_node and value:
                path = self._get_full_path(target_node)
                if path: self._handle_assignment(path, value, node.start_point[0] + 1)

        elif node.type == "method_invocation":
            method_name = self.get_method_name(node)
            match_name = None
            if method_name in self.sinks: match_name = method_name
            else:
                for s_name in self.sinks:
                    if s_name.endswith("." + method_name) or s_name == method_name: match_name = s_name; break
            
            if match_name: self._check_sink_violation(node, match_name)
            else:
                found_fw = False
                for mapper in self.framework_mappers:
                    sink_info = mapper.is_sink(node, self.code)
                    if sink_info:
                        v_type, vuln_args = sink_info["type"], sink_info.get("args")
                        args_node = node.child_by_field_name("arguments")
                        if args_node:
                            actual_args = [c for c in args_node.children if c.is_named]
                            for idx, arg in enumerate(actual_args):
                                if vuln_args is not None and idx not in vuln_args: continue
                                self._check_sink_violation_for_node(arg, f"{v_type} ({mapper.__class__.__name__})", node.start_point[0] + 1)
                        found_fw = True; break
                
                if not found_fw:
                    func_def = self.functions.get(method_name)
                    if not func_def and self.project_index and self.depth < self.max_depth:
                        global_def = self.project_index.find_function(method_name)
                        if global_def and global_def.language == "java":
                            func_def, target_file, target_code = global_def.node["node"], global_def.file_path, global_def.node["code"]
                            self._simulate_call(node, func_def, method_name, target_file, target_code)
                    elif func_def: self._simulate_call(node, func_def, method_name, None, None)

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

        for identifier in self.collect_identifiers(value_node):
            taint = self.is_tainted(identifier)
            if taint:
                self.set_tainted(path, {"source": taint["source"], "trace": taint["trace"] + [f"Propagated to {path} at line {line}"]}); return
        self.clear_taint(path)

    def _check_sink_violation(self, node: Node, method_name: str):
        args_node = node.child_by_field_name("arguments")
        if not args_node: return
        vuln_args = self.sinks.get(method_name)
        actual_args = [c for c in args_node.children if c.is_named]
        for idx, arg in enumerate(actual_args):
            if vuln_args is not None and idx not in vuln_args: continue
            self._check_sink_violation_for_node(arg, method_name, node.start_point[0] + 1)

    def _check_sink_violation_for_node(self, node: Node, sink_name: str, line: int):
        # NOTE: For PII LEAKAGE, we don't skip literals. But this generic visitor 
        # is used for everything. We rely on the fact that if a literal was assigned 
        # to a 'password' variable, _handle_assignment marked it as tainted.
        for path in self.collect_identifiers(node):
            taint = self.is_tainted(path)
            if taint: self.vulnerabilities.append({"sink": sink_name, "variable": path, "line": line, "trace": taint["trace"]}); break

    def _simulate_call(self, call_node: Node, func_node: Node, method_name: str, target_file: Optional[str], target_code: Optional[bytes]):
        args_node, params_node = call_node.child_by_field_name("arguments"), func_node.child_by_field_name("parameters")
        if not args_node or not params_node: return
        actual_args = [c for c in args_node.children if c.is_named]
        actual_params = [c for c in params_node.children if c.type == "formal_parameter"]
        t_code = target_code if target_code is not None else self.code
        tainted_params = {}
        for idx, arg in enumerate(actual_args):
            if idx < len(actual_params):
                p_node = actual_params[idx]
                p_name_node = p_node.child_by_field_name("name") or next((c for c in p_node.children if c.type == "identifier"), None)
                if not p_name_node: continue
                p_name = t_code[p_name_node.start_byte : p_name_node.end_byte].decode("utf-8")
                for path in self.collect_identifiers(arg):
                    taint = self.is_tainted(path)
                    if taint:
                        loc = f"in {os.path.basename(target_file)}" if target_file else "locally"
                        tainted_params[p_name] = {"source": taint["source"], "trace": taint["trace"] + [f"Passed to {method_name}() {loc} at line {call_node.start_point[0] + 1}"]}
                        break
        if tainted_params:
            body = func_node.child_by_field_name("body")
            if body:
                v = TaintVisitor(list(self.sources), [{"name": n, "args": a} for n, a in self.sinks.items()], list(self.sanitizers), t_code, self.project_index, self.depth + 1, initial_scope=tainted_params)
                v.visit(body); self.vulnerabilities.extend(v.vulnerabilities)

    def get_vulnerabilities(self) -> List[Dict[str, Any]]: return self.vulnerabilities
