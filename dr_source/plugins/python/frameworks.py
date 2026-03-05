import ast
import logging
from typing import Optional, Set, List

logger = logging.getLogger(__name__)

class PythonFrameworkMapper:
    """Base class for Python framework specific logic."""
    def get_source_name(self, node: ast.arg, decorator_list: list) -> Optional[str]:
        return None
    
    def analyze_node(self, node: ast.AST) -> List[dict]:
        """Performs additional analysis on specific nodes."""
        return []

class FastAPIMapper(PythonFrameworkMapper):
    """Specific mapping for FastAPI framework."""
    FASTAPI_ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch", "options", "head", "api_route"}

    def get_source_name(self, node: ast.arg, decorator_list: list) -> Optional[str]:
        is_route = False
        for dec in decorator_list:
            if isinstance(dec, ast.Call):
                func = dec.func
                if isinstance(func, ast.Attribute) and func.attr in self.FASTAPI_ROUTE_DECORATORS:
                    is_route = True
                    break
            elif isinstance(dec, ast.Attribute) and dec.attr in self.FASTAPI_ROUTE_DECORATORS:
                is_route = True
                break
        if is_route: return node.arg
        return None

class DjangoMapper(PythonFrameworkMapper):
    """Specific mapping for Django framework."""
    DJANGO_VIEW_DECORATORS = {"login_required", "csrf_exempt", "require_http_methods", "require_GET", "require_POST"}

    def get_source_name(self, node: ast.arg, decorator_list: list) -> Optional[str]:
        is_view = False
        for dec in decorator_list:
            name = ""
            if isinstance(dec, ast.Name): name = dec.id
            elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name): name = dec.func.id
            elif isinstance(dec, ast.Attribute): name = dec.attr
            if name in self.DJANGO_VIEW_DECORATORS: is_view = True; break
        if node.arg == "request" or is_view: return node.arg
        return None

    def analyze_node(self, node: ast.AST) -> List[dict]:
        """Detects Mass Assignment in Django forms (fields = '__all__')."""
        vulnerabilities = []
        if isinstance(node, ast.ClassDef):
            # Look for inner class Meta in a ModelForm
            is_model_form = any(isinstance(base, ast.Attribute) and base.attr == "ModelForm" for base in node.bases)
            if is_model_form:
                for item in node.body:
                    if isinstance(item, ast.ClassDef) and item.name == "Meta":
                        for meta_item in item.body:
                            if isinstance(meta_item, ast.Assign):
                                for target in meta_item.targets:
                                    if isinstance(target, ast.Name) and target.id == "fields":
                                        if isinstance(meta_item.value, ast.Constant) and meta_item.value.value == "__all__":
                                            vulnerabilities.append({
                                                "type": "MASS_ASSIGNMENT",
                                                "message": "Django ModelForm with fields = '__all__' is vulnerable to mass assignment.",
                                                "line": meta_item.lineno
                                            })
        return vulnerabilities
