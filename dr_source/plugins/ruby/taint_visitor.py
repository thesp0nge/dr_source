import logging
import os
from typing import List, Dict, Any, Set, Optional
from tree_sitter import Node

logger = logging.getLogger(__name__)

class RubyTaintVisitor:
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
        self.pii_names = {"password", "email", "secret", "token", "credit_card", "cc", "ssn"}

    def get_text(self, node: Node) -> str:
        if not node: return ""
        return self.code[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")

    def _get_full_path(self, node: Node) -> Optional[str]:
        """Resolves a Ruby node to a path (e.g., 'user.name' or 'params[:id]')."""
        if node.type == "identifier": return self.get_text(node)
        if node.type == "call":
            receiver = node.child_by_field_name("receiver")
            method = node.child_by_field_name("method")
            if receiver and method:
                base = self._get_full_path(receiver)
                return f"{base}.{self.get_text(method)}" if base else None
        if node.type == "element_reference":
            # For params[:user], children are [params, [, :user, ]]
            if node.children:
                base = self._get_full_path(node.children[0])
                return f"{base}[]" if base else None
        return None

    def is_tainted(self, path: str) -> Optional[Dict[str, Any]]:
        for scope in reversed(self.scopes):
            if path in scope: return scope[path]
            if "." in path:
                base = path.split(".")[0]
                if base in scope: return scope[base]
            if "[]" in path:
                base = path.split("[]")[0]
                if base in scope: return scope[base]
        
        # New: Check if the path itself is a known source (Direct usage)
        clean_path = path.split("[]")[0].split(".")[0]
        if clean_path in self.sources:
            return {"source": clean_path, "trace": [f"Direct usage of source {path}"]}
            
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
        if node.type in ["string", "integer", "symbol", "string_content"]:
            if node.type == "string":
                for child in node.children:
                    if child.type == "interpolation": return None
            return self.get_text(node).strip("'\":")
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
        if var_name:
            clean_name = var_name.lower().replace("@", "")
            if any(p in clean_name for p in self.pii_names):
                return "source", f"Sensitive variable name: {var_name}"

        name = ""
        if node.type == "call":
            method = node.child_by_field_name("method")
            if method: name = self.get_text(method)
        elif node.type == "identifier": name = self.get_text(node)
        elif node.type == "element_reference":
            if node.children: name = self.get_text(node.children[0])
        
        if not name: return None, None
        if name in self.sanitizers: return "sanitizer", name
        if name in self.sources or any(name.startswith(s) for s in self.sources): return "source", name
        return None, None

    def get_method_name(self, node: Node) -> str:
        method = node.child_by_field_name("method")
        if method: return self.get_text(method)
        for child in node.children:
            if child.type == "identifier": return self.get_text(child)
        return ""

    def visit(self, node: Node):
        if node is None: return
        if node.type == "method":
            name_node = node.child_by_field_name("name")
            if name_node: self.functions[self.get_text(name_node)] = node

        is_scope = node.type in ["method", "do_block", "block"]
        should_push = is_scope and not self.skip_first_scope
        if is_scope and self.skip_first_scope: self.skip_first_scope = False
        if should_push:
            self.scopes.append({}); self.constants.append({})

        if node.type == "assignment":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left and right:
                path = self._get_full_path(left)
                if path: self._handle_assignment(path, right, node.start_point[0] + 1)

        elif node.type == "call":
            method_name = self.get_method_name(node)
            logger.debug(f"RUBY CALL: {method_name} at line {node.start_point[0]+1}, sinks: {list(self.sinks.keys())}")
            if method_name:
                match_name = None
                if method_name in self.sinks: match_name = method_name
                else:
                    for s_name in self.sinks:
                        if method_name == s_name or method_name.endswith("." + s_name) or s_name.endswith("." + method_name):
                            match_name = s_name; break
                if match_name:
                    logger.debug(f"RUBY MATCHED SINK: {match_name}")
                    self._check_sink_violation(node, match_name)

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
        # Ruby arguments can be in 'argument_list' or just children of the 'call'
        actual_args = []
        args_node = node.child_by_field_name("arguments")
        if args_node:
            actual_args = [c for c in args_node.children if c.is_named]
        else:
            # Handle calls without parentheses: method arg1, arg2
            method_node = node.child_by_field_name("method")
            if method_node:
                found_method = False
                for child in node.children:
                    if child == method_node: found_method = True; continue
                    if found_method and child.is_named: actual_args.append(child)
        
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
