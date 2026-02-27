import ast
import logging
import os
from typing import List, Set, Dict, Any, Optional

logger = logging.getLogger(__name__)

class PythonTaintVisitor(ast.NodeVisitor):
    def __init__(self, source_list: List[str], sink_list: List[Any], sanitizer_list: List[str], project_index: Optional[Any] = None, depth: int = 0):
        self.sources = set(source_list)
        self.sanitizers = set(sanitizer_list)
        self.project_index = project_index
        self.depth = depth
        self.max_depth = 3 # Prevent deep recursion
        
        # Parse sinks
        self.sinks = {}
        for s in sink_list:
            if isinstance(s, dict) and "name" in s:
                self.sinks[s["name"]] = s.get("args")
            elif isinstance(s, str):
                self.sinks[s] = None
                
        self.scopes: List[Dict[str, Dict[str, Any]]] = [{}]
        self.constants: List[Dict[str, Any]] = [{}] # Track literal values for constant propagation
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.functions: Dict[str, ast.FunctionDef] = {} 

    def is_tainted(self, var_name: str) -> Optional[Dict[str, Any]]:
        for scope in reversed(self.scopes):
            if var_name in scope:
                return scope[var_name]
        return None

    def get_constant(self, var_name: str) -> Any:
        for scope in reversed(self.constants):
            if var_name in scope:
                return scope[var_name]
        return None

    def set_constant(self, var_name: str, value: Any):
        self.constants[-1][var_name] = value

    def set_tainted(self, var_name: str, data: Dict[str, Any]):
        self.scopes[-1][var_name] = data
        # If it's tainted, it's not a safe constant
        if var_name in self.constants[-1]:
            del self.constants[-1][var_name]

    def clear_taint(self, var_name: str):
        if var_name in self.scopes[-1]:
            del self.scopes[-1][var_name]

    def _resolve_value(self, node: ast.AST) -> Any:
        """Attempts to resolve a node to a constant value."""
        if isinstance(node, (ast.Constant, ast.Str, ast.Num)):
            return getattr(node, 'value', getattr(node, 's', getattr(node, 'n', None)))
        if isinstance(node, ast.Name):
            return self.get_constant(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve_value(node.left)
            right = self._resolve_value(node.right)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
        return None

    def _get_full_call_name(self, node: ast.Call) -> str:
        def resolve_attribute(attr_node: ast.Attribute) -> str:
            value = attr_node.value
            if isinstance(value, ast.Name): return f"{value.id}.{attr_node.attr}"
            if isinstance(value, ast.Attribute): return f"{resolve_attribute(value)}.{attr_node.attr}"
            if isinstance(value, ast.Call):
                base = self._get_full_call_name(value)
                if base.endswith("cursor"): return f"cursor.{attr_node.attr}"
            return f"UNKNOWN.{attr_node.attr}"
        if isinstance(node.func, ast.Name): return node.func.id
        if isinstance(node.func, ast.Attribute): return resolve_attribute(node.func)
        return "UNKNOWN_CALL"

    def _get_ids_from_node(self, node: ast.AST) -> Set[str]:
        ids = set()
        if node is None: return ids
        for n in ast.walk(node):
            if isinstance(n, ast.Name): ids.add(n.id)
        return ids

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.functions[node.name] = node
        self.scopes.append({})
        self.constants.append({})
        self.generic_visit(node)
        self.constants.pop()
        self.scopes.pop()

    def visit_Assign(self, node: ast.Assign):
        if node.targets and isinstance(node.targets[0], ast.Name):
            self._handle_assignment(node.targets[0].id, node.value, node.lineno)
        self.generic_visit(node)

    def _handle_assignment(self, var_name: str, value_node: ast.AST, line: int):
        # 1. Try Constant Propagation
        const_val = self._resolve_value(value_node)
        if const_val is not None:
            self.set_constant(var_name, const_val)
            self.clear_taint(var_name)
            return

        # 2. Taint Analysis
        if isinstance(value_node, ast.Call):
            func_name = self._get_full_call_name(value_node)
            if func_name in self.sanitizers:
                self.clear_taint(var_name)
                return
            if func_name in self.sources:
                self.set_tainted(var_name, {"source": func_name, "trace": [f"Tainted by {func_name} at line {line}"]})
                return
        
        value_ids = self._get_ids_from_node(value_node)
        for var_id in value_ids:
            taint_info = self.is_tainted(var_id)
            if taint_info:
                self.set_tainted(var_name, {"source": taint_info["source"], "trace": taint_info["trace"] + [f"Propagated to {var_name} at line {line}"]})
                return
        self.clear_taint(var_name)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_full_call_name(node)
        
        # 1. Sink Checking
        if func_name in self.sinks:
            vulnerable_args = self.sinks[func_name]
            for idx, arg in enumerate(node.args):
                if vulnerable_args is not None and idx not in vulnerable_args: continue
                
                # Check if it's a safe constant
                if self._resolve_value(arg) is not None:
                    continue # Safe literal, skip this arg

                for var in self._get_ids_from_node(arg):
                    taint_info = self.is_tainted(var)
                    if taint_info:
                        self.vulnerabilities.append({"sink": func_name, "variable": var, "line": node.lineno, "trace": taint_info["trace"]})
                        break
        
        # 2. Inter-Procedural Analysis (Local or Global)
        else:
            func_def = self.functions.get(func_name)
            target_file = None
            
            # If not local, look in project index
            if not func_def and self.project_index and self.depth < self.max_depth:
                global_def = self.project_index.find_function(func_name)
                if global_def and global_def.language == "python":
                    func_def = global_def.node
                    target_file = global_def.file_path

            if func_def:
                self._simulate_call(node, func_def, func_name, target_file)

        self.generic_visit(node)

    def _simulate_call(self, call_node: ast.Call, func_def: ast.FunctionDef, func_name: str, target_file: Optional[str] = None):
        tainted_params = {}
        for idx, arg in enumerate(call_node.args):
            if idx < len(func_def.args.args):
                param_name = func_def.args.args[idx].arg
                for var in self._get_ids_from_node(arg):
                    taint_info = self.is_tainted(var)
                    if taint_info:
                        loc_info = f"in {os.path.basename(target_file)}" if target_file else "locally"
                        tainted_params[param_name] = {
                            "source": taint_info["source"],
                            "trace": taint_info["trace"] + [f"Passed to {func_name}() {loc_info} at line {call_node.lineno}"]
                        }
                        break
        
        if tainted_params:
            # If it's a cross-file call, we need a fresh visitor to avoid scope pollution
            if target_file:
                visitor = PythonTaintVisitor(list(self.sources), list(self.sinks.keys()), list(self.sanitizers), self.project_index, self.depth + 1)
                visitor.scopes = [tainted_params] # Start with tainted params in scope
                visitor.visit(func_def)
                self.vulnerabilities.extend(visitor.vulnerabilities)
            else:
                self.scopes.append(tainted_params)
                for stmt in func_def.body: self.visit(stmt)
                self.scopes.pop()
