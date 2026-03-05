import logging
import os
from typing import List, Dict, Any, Set, Optional
from tree_sitter import Node

logger = logging.getLogger(__name__)

class PHPTaintVisitor:
    def __init__(self, sources: Set[str], sinks: List[Any], sanitizers: Set[str], source_code: bytes, project_index: Optional[Any] = None, depth: int = 0, initial_scope: Optional[Dict[str, Any]] = None):
        self.scopes: List[Dict[str, Dict[str, Any]]] = [initial_scope if initial_scope else {}]
        self.constants: List[Dict[str, Any]] = [{}]
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.functions: Dict[str, Node] = {} 
        self.project_index = project_index
        self.depth = depth
        self.max_depth = 3
        self.skip_first_scope = initial_scope is not None
        
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
        if node.type == "variable_name": return self.get_text(node)
        if node.type == "member_access_expression":
            obj = node.child_by_field_name("object")
            name = node.child_by_field_name("name")
            if obj and name:
                base = self._get_full_path(obj)
                return f"{base}->{self.get_text(name)}" if base else None
        if node.type == "subscript_expression":
            obj = node.child_by_field_name("callable") or (node.children[0] if node.children else None)
            if obj:
                base = self._get_full_path(obj)
                return f"{base}[]" if base else None
        return None

    def is_tainted(self, path: str) -> Optional[Dict[str, Any]]:
        for scope in reversed(self.scopes):
            if path in scope: return scope[path]
            if "->" in path:
                base = path.split("->")[0]
                if base in scope: return scope[base]
            if "[]" in path:
                base = path.split("[]")[0]
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
        if node.type in ["string", "integer", "encapsed_string"]:
            return self.get_text(node).strip("'\"")
        path = self._get_full_path(node)
        if path: return self.get_constant(path)
        return None

    def collect_identifiers(self, node: Node) -> Set[str]:
        paths = set()
        path = self._get_full_path(node)
        if path: paths.add(path)
        for child in node.children: paths.update(self.collect_identifiers(child))
        return paths

    def check_source_or_sanitizer(self, node: Node, var_name: Optional[str] = None) -> tuple[Optional[str], Optional[str]]:
        # Heuristic: Check if variable name is sensitive (for PII_LEAKAGE)
        if var_name:
            clean_name = var_name.lower().replace("$", "")
            if any(p in clean_name for p in self.pii_names):
                return "source", f"Sensitive variable name: {var_name}"

        name = ""
        if node.type == "function_call_expression":
            func = node.child_by_field_name("function")
            if func: name = self.get_text(func)
        else:
            path = self._get_full_path(node)
            if path: name = path
        
        if not name: return None, None
        if name in self.sanitizers: return "sanitizer", name
        if name in self.sources or any(name.startswith(s) for s in self.sources): return "source", name
        return None, None

    def visit(self, node: Node):
        if node is None: return
        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node: self.functions[self.get_text(name_node)] = node

        is_scope = node.type in ["function_definition", "method_definition"]
        should_push = is_scope and not self.skip_first_scope
        if is_scope and self.skip_first_scope: self.skip_first_scope = False
        if should_push:
            self.scopes.append({}); self.constants.append({})

        if node.type == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left and right:
                path = self._get_full_path(left)
                if path: self._handle_assignment(path, right, node.start_point[0] + 1)

        elif node.type == "function_call_expression":
            func = node.child_by_field_name("function")
            if func:
                name = self.get_text(func)
                if name in self.sinks: self._check_sink_violation(node, name)

        elif node.type == "echo_statement":
            if "echo" in self.sinks: self._check_sink_violation(node, "echo")
            
        # HANDLE PHP INCLUDES/REQUIRES (Special nodes in Tree-sitter)
        elif node.type in ["include_expression", "include_once_expression", "require_expression", "require_once_expression"]:
            # Standardize name to 'include' or 'require' for KB matching
            name = node.type.split("_")[0]
            if name in self.sinks:
                # The path is the only child that is not the keyword
                for child in node.children:
                    if child.is_named:
                        self._check_sink_violation_for_node(child, name, node.start_point[0] + 1)
                        break

        for child in node.children: self.visit(child)
        if should_push:
            self.constants.pop(); self.scopes.pop()

    def _handle_assignment(self, path: str, value_node: Node, line: int):
        # We pass 'path' to check for sensitive variable names
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
        actual_args = []
        if node.type == "echo_statement":
            actual_args = [c for c in node.children if c.is_named and c.type != "echo"]
        else:
            args_node = node.child_by_field_name("arguments")
            if args_node: actual_args = [c for c in args_node.children if c.is_named]
        
        vuln_args = self.sinks.get(sink_name)
        for idx, arg in enumerate(actual_args):
            if vuln_args is not None and idx not in vuln_args: continue
            self._check_sink_violation_for_node(arg, sink_name, node.start_point[0] + 1)

    def _check_sink_violation_for_node(self, node: Node, sink_name: str, line: int):
        if self._resolve_value(node) is not None: return
        for path in self.collect_identifiers(node):
            t = self.is_tainted(path)
            if t: self.vulnerabilities.append({"sink": sink_name, "variable": path, "line": line, "trace": t["trace"]}); break

    def get_vulnerabilities(self) -> List[Dict[str, Any]]: return self.vulnerabilities
