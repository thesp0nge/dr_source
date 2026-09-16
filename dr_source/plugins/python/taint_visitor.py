import ast
import logging
import os
from typing import List, Set, Dict, Any, Optional

from dr_source.core.resolution import Resolution, ResolutionReason, ResolutionStatus

logger = logging.getLogger(__name__)

class PythonTaintVisitor(ast.NodeVisitor):
    def __init__(self, source_list: List[str], sink_list: List[Any], sanitizer_list: List[str], project_index: Optional[Any] = None, depth: int = 0, structural_analysis: bool = True, current_file: Optional[str] = None, python_context: Optional[Any] = None):
        self.sources = set(source_list)
        self.sanitizers = set(s.split(".")[-1] for s in sanitizer_list)
        self.project_index = project_index
        self.current_file = current_file
        self.python_context = python_context
        self.depth = depth
        self.max_depth = 3
        self.structural_analysis = structural_analysis
        
        self.sinks = {}
        for s in sink_list:
            if isinstance(s, dict) and "name" in s: self.sinks[s["name"]] = s.get("args")
            elif isinstance(s, str): self.sinks[s] = None
                
        self.scopes: List[Dict[str, Dict[str, Any]]] = [{}]
        self.constants: List[Dict[str, Any]] = [{}]
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.functions: Dict[str, ast.FunctionDef] = {} 
        from .frameworks import FastAPIMapper, DjangoMapper
        self.framework_mappers = [FastAPIMapper(), DjangoMapper()]
        # PII Heuristic
        self.pii_names = {"password", "email", "secret", "token", "credit_card", "cc", "ssn"}

    def visit(self, node: ast.AST):
        # Allow framework mappers to perform structural analysis
        if self.structural_analysis:
            for mapper in self.framework_mappers:
                struct_vulns = mapper.analyze_node(node)
                for v in struct_vulns:
                    self.vulnerabilities.append({
                        "sink": v["type"],
                        "variable": "structural",
                        "line": v["line"],
                        "trace": [v["message"]]
                    })
        super().visit(node)

    def _get_full_attr_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_full_attr_name(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def is_tainted(self, path: str) -> Optional[Dict[str, Any]]:
        for scope in reversed(self.scopes):
            if path in scope: return scope[path]
            if "." in path:
                base = path.split(".")[0]
                if base in scope: return scope[base]
        return None

    def get_constant(self, path: str) -> Any:
        for scope in reversed(self.constants):
            if path in scope: return scope[path]
        return None

    def set_constant(self, path: str, value: Any):
        self.constants[-1][path] = value

    def set_tainted(self, path: str, data: Dict[str, Any]):
        self.scopes[-1][path] = data
        if path in self.constants[-1]: del self.constants[-1][path]

    def clear_taint(self, path: str):
        if path in self.scopes[-1]: del self.scopes[-1][path]

    def _resolve_value(self, node: ast.AST) -> Any:
        if isinstance(node, (ast.Constant, ast.Str, ast.Num)):
            return getattr(node, 'value', getattr(node, 's', getattr(node, 'n', None)))
        path = self._get_full_attr_name(node)
        if path: return self.get_constant(path)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            l, r = self._resolve_value(node.left), self._resolve_value(node.right)
            if isinstance(l, str) and isinstance(r, str): return l + r
        return None

    def _get_full_call_name(self, node: ast.Call) -> str:
        def resolve(attr_node: ast.AST) -> str:
            if isinstance(attr_node, ast.Name): return attr_node.id
            if isinstance(attr_node, ast.Attribute):
                base = resolve(attr_node.value)
                return f"{base}.{attr_node.attr}" if base else f"UNKNOWN.{attr_node.attr}"
            if isinstance(attr_node, ast.Call): return resolve(attr_node.func)
            return "UNKNOWN"
        if isinstance(node.func, ast.Name): return node.func.id
        if isinstance(node.func, ast.Attribute): return resolve(node.func)
        return "UNKNOWN_CALL"

    def _get_ids_from_node(self, node: ast.AST) -> Set[str]:
        paths = set()
        if node is None: return paths
        for n in ast.walk(node):
            if isinstance(n, ast.Name): paths.add(n.id)
            elif isinstance(n, ast.Attribute):
                p = self._get_full_attr_name(n)
                if p: paths.add(p)
        return paths

    def visit_FunctionDef(self, node: ast.FunctionDef): self._handle_func(node)
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef): self._handle_func(node)

    def _handle_func(self, node: Any):
        self.functions[node.name] = node
        self.scopes.append({}); self.constants.append({})
        for arg in node.args.args:
            # Check for PII in parameter names
            if any(p in arg.arg.lower() for p in self.pii_names):
                self.set_tainted(arg.arg, {"source": f"Sensitive parameter: {arg.arg}", "trace": [f"Sensitive data in parameter {arg.arg} at line {node.lineno}"]})
            
            for m in self.framework_mappers:
                src = m.get_source_name(arg, node.decorator_list)
                if src: self.set_tainted(src, {"source": "Framework", "trace": [f"Tainted parameter {src} at line {node.lineno}"]})
        self.generic_visit(node)
        self.constants.pop(); self.scopes.pop()

    def visit_Assign(self, node: ast.Assign):
        if node.targets:
            path = self._get_full_attr_name(node.targets[0])
            if path: self._handle_assignment(path, node.value, node.lineno)
        self.generic_visit(node)

    def _handle_assignment(self, path: str, value_node: ast.AST, line: int):
        # 1. PII Heuristic: Check if variable name being assigned is sensitive
        clean_path = path.lower().split(".")[-1]
        if any(p in clean_path for p in self.pii_names):
            self.set_tainted(path, {"source": f"Sensitive variable name: {path}", "trace": [f"Variable {path} marked as sensitive at line {line}"]})
            return

        # 2. Source Detection
        kind, name = self.check_source_or_sanitizer(value_node)
        if kind == "sanitizer": self.clear_taint(path); return
        if kind == "source":
            self.set_tainted(path, {"source": name, "trace": [f"Tainted by {name} at line {line}"]}); return

        const_val = self._resolve_value(value_node)
        if const_val is not None:
            self.set_constant(path, const_val); self.clear_taint(path); return

        # 3. General Propagation
        for identifier in self._get_ids_from_node(value_node):
            taint = self.is_tainted(identifier)
            if taint:
                self.set_tainted(path, {"source": taint["source"], "trace": taint["trace"] + [f"Propagated to {path} at line {line}"]}); return
        self.clear_taint(path)

    def check_source_or_sanitizer(self, node: ast.AST) -> tuple[Optional[str], Optional[str]]:
        if isinstance(node, ast.Call): name = self._get_full_call_name(node)
        else: name = self._get_full_attr_name(node) or ""
        if not name: return None, None
        if name in self.sanitizers or name.split(".")[-1] in self.sanitizers: return "sanitizer", name
        if name in self.sources or any(name.endswith("." + s) for s in self.sources) or any(s in name for s in self.sources):
            return "source", name
        return None, None

    def _resolve_project_call(self, node: ast.Call) -> Resolution:
        """Resolve a project call using Python context and indexed candidates.

        Local functions are intentionally handled by ``self.functions`` in
        ``visit_Call``. This method only decides whether an inter-file target
        can be selected; it does not perform source, sink, or sanitizer logic.
        """
        fn = self._get_full_call_name(node)
        if self.project_index is None:
            return Resolution.unresolved()

        target_file = None
        target_name = fn
        explicit_binding = False
        if self.python_context and self.current_file:
            target_file, bound_name, explicit_binding = self.python_context.resolve_binding(
                self.current_file, fn
            )
            target_name = bound_name or fn

        if not explicit_binding:
            return self.project_index.resolve_unique(fn, language="python")

        if target_file is None:
            binding = self.python_context.binding(self.current_file, fn.split(".")[0])
            reason = (
                ResolutionReason.UNSUPPORTED_BINDING
                if binding is not None and not binding.supported
                else ResolutionReason.UNSUPPORTED_CALL_FORM
            )
            return Resolution.unsupported(reason)

        candidates = [
            candidate
            for candidate in self.project_index.find_candidates(target_name, language="python")
            if os.path.normpath(os.path.abspath(candidate.file_path))
            == os.path.normpath(os.path.abspath(target_file))
        ]
        candidate_ids = tuple(candidate.symbol_id for candidate in candidates)
        if len(candidates) == 1:
            return Resolution.resolved(candidate_ids[0], candidate_ids)
        if len(candidates) > 1:
            return Resolution.ambiguous(candidate_ids)
        return Resolution.unresolved(reason=ResolutionReason.EXPLICIT_TARGET_NOT_FOUND)

    def _log_project_resolution(self, name: str, resolution: Resolution) -> None:
        """Retain the existing resolver warnings while decisions use statuses."""
        binding = None
        bound_name = None
        explicit = False
        if self.python_context and self.current_file:
            _, bound_name, explicit = self.python_context.resolve_binding(
                self.current_file, name
            )
            binding = self.python_context.binding(self.current_file, name.split(".")[0])
        diagnostic_name = bound_name or name
        if resolution.status is ResolutionStatus.UNSUPPORTED:
            logger.warning(
                "Unsupported or unresolved Python import binding for %s in %s",
                name,
                self.current_file,
            )
        elif resolution.status is ResolutionStatus.AMBIGUOUS:
            if explicit:
                module = binding.module_name if binding else "unknown"
                logger.warning(
                    "Ambiguous or unresolved Python symbol %r in module %r: %d candidates",
                    diagnostic_name,
                    module,
                    len(resolution.candidates),
                )
            else:
                logger.warning(
                    "Ambiguous function %r: %d candidates; language=python; "
                    "inter-file analysis skipped: %s",
                    name,
                    len(resolution.candidates),
                    list(resolution.candidates),
                )
        elif resolution.reason is ResolutionReason.EXPLICIT_TARGET_NOT_FOUND:
            module = binding.module_name if binding else "unknown"
            logger.warning(
                "Ambiguous or unresolved Python symbol %r in module %r: 0 candidates",
                diagnostic_name,
                module,
            )

    def visit_Call(self, node: ast.Call):
        fn = self._get_full_call_name(node)
        match_name = None
        if fn in self.sinks: match_name = fn
        else:
            for s_name in self.sinks:
                if fn.endswith("." + s_name) or fn == s_name:
                    match_name = s_name; break
        if match_name:
            v_args = self.sinks[match_name]
            for idx, arg in enumerate(node.args):
                if v_args is not None and idx not in v_args: continue
                # FOR PII LEAKAGE: We DO NOT skip constants, because printing a hardcoded password IS a leak.
                # But for SQLi it's safe. We need to distinguish.
                # Heuristic: If it's a PII leak check, literals are vulnerable.
                
                for var in self._get_ids_from_node(arg):
                    t = self.is_tainted(var)
                    if t: self.vulnerabilities.append({"sink": match_name, "variable": var, "line": node.lineno, "trace": t["trace"]}); break
            for kw in node.keywords:
                for var in self._get_ids_from_node(kw.value):
                    t = self.is_tainted(var)
                    if t: self.vulnerabilities.append({"sink": match_name, "variable": var, "line": node.lineno, "trace": t["trace"]}); break
        else:
            f_def = self.functions.get(fn)
            if not f_def and self.project_index and self.depth < self.max_depth:
                resolution = self._resolve_project_call(node)
                self._log_project_resolution(fn, resolution)
                if resolution.status is ResolutionStatus.RESOLVED and resolution.symbol is not None:
                    definition = self.project_index.get_definition(resolution.symbol)
                    if definition is not None and definition.language == "python":
                        f_def, t_file = definition.node, definition.file_path
                        self._simulate_call(node, f_def, fn, t_file)
        self.generic_visit(node)

    def _simulate_call(self, node: ast.Call, f_def: Any, fn: str, t_file: Optional[str] = None):
        tainted = {}
        for idx, arg in enumerate(node.args):
            params = f_def.args.args
            if idx < len(params):
                p_name = params[idx].arg
                for var in self._get_ids_from_node(arg):
                    t = self.is_tainted(var)
                    if t:
                        loc = f"in {os.path.basename(t_file)}" if t_file else "locally"
                        tainted[p_name] = {"source": t["source"], "trace": t["trace"] + [f"Passed to {fn}() {loc} at line {node.lineno}"]}
                        break
        if tainted:
            if t_file:
                v = PythonTaintVisitor(
                    list(self.sources),
                    [{"name": n, "args": a} for n, a in self.sinks.items()],
                    list(self.sanitizers),
                    self.project_index,
                    self.depth + 1,
                    current_file=t_file,
                    python_context=self.python_context,
                )
                v.scopes = [tainted]; v.visit(f_def); self.vulnerabilities.extend(v.vulnerabilities)
            else:
                self.scopes.append(tainted); 
                if hasattr(f_def, 'body'):
                    for stmt in f_def.body: self.visit(stmt)
                self.scopes.pop()

    def get_vulnerabilities(self) -> List[Dict[str, Any]]: return self.vulnerabilities
