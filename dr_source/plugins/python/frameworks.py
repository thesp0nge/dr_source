import ast
import logging
from typing import Optional, Set, List

logger = logging.getLogger(__name__)

class PythonFrameworkMapper:
    """Base class for Python framework specific logic."""
    def get_source_name(self, node: ast.arg, decorator_list: list) -> Optional[str]:
        """Returns a source name if the function argument represents a framework-specific entry point."""
        return None

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
        
        if is_route:
            return node.arg
        return None

class DjangoMapper(PythonFrameworkMapper):
    """Specific mapping for Django framework."""
    
    DJANGO_VIEW_DECORATORS = {"login_required", "csrf_exempt", "require_http_methods", "require_GET", "require_POST"}

    def get_source_name(self, node: ast.arg, decorator_list: list) -> Optional[str]:
        """
        Identifies Django sources. In Django views, the 'request' object 
        is the primary source of user-controlled data.
        """
        # Heuristic 1: Parameter named 'request' in a function with Django-like decorators
        is_view = False
        for dec in decorator_list:
            name = ""
            if isinstance(dec, ast.Name): name = dec.id
            elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name): name = dec.func.id
            elif isinstance(dec, ast.Attribute): name = dec.attr
            
            if name in self.DJANGO_VIEW_DECORATORS:
                is_view = True
                break
        
        # Heuristic 2: If the parameter name is exactly 'request', we treat it as a source 
        # (common convention in Django FBVs)
        if node.arg == "request":
            return "request"
            
        if is_view:
            return node.arg
            
        return None
