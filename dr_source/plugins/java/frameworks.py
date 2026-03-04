import logging
from typing import Set, Optional, List, Any, Dict
from tree_sitter import Node

logger = logging.getLogger(__name__)

class JavaFrameworkMapper:
    """Base class for Java framework specific logic."""
    def get_source_name(self, node: Node, source_code: bytes) -> Optional[str]:
        return None

    def is_sink(self, node: Node, source_code: bytes) -> Optional[Dict[str, Any]]:
        return None

class SpringBootMapper(JavaFrameworkMapper):
    """Mapping for Spring Boot framework annotations and sinks."""
    SPRING_SOURCE_ANNOTATIONS = {
        "RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue", "ModelAttribute"
    }
    SPRING_SINKS = {
        "jdbcTemplate.query": {"type": "SQL_INJECTION", "args": [0]},
        "jdbcTemplate.update": {"type": "SQL_INJECTION", "args": [0]},
        "jdbcTemplate.execute": {"type": "SQL_INJECTION", "args": [0]},
    }

    def _get_text(self, node: Node, source_code: bytes) -> str:
        return source_code[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def get_source_name(self, node: Node, source_code: bytes) -> Optional[str]:
        if node.type == "formal_parameter":
            for child in node.children:
                if child.type == "modifiers":
                    for mod in child.children:
                        if mod.type == "annotation":
                            name_node = mod.child_by_field_name("name")
                            if name_node:
                                ann_name = self._get_text(name_node, source_code).split(".")[-1]
                                if ann_name in self.SPRING_SOURCE_ANNOTATIONS:
                                    param_name_node = node.child_by_field_name("name")
                                    if param_name_node:
                                        return self._get_text(param_name_node, source_code)
        return None

    def is_sink(self, node: Node, source_code: bytes) -> Optional[Dict[str, Any]]:
        if node.type == "method_invocation":
            # Robust method name extraction
            name_node = node.child_by_field_name("name")
            if not name_node:
                # Fallback to last identifier
                ids = [c for c in node.children if c.type == "identifier"]
                if ids: name_node = ids[-1]
            
            if not name_node: return None
            method_name = self._get_text(name_node, source_code)
            
            # Extract object/receiver
            object_node = node.child_by_field_name("object")
            if not object_node:
                ids = [c for c in node.children if c.type == "identifier"]
                if len(ids) > 1: object_node = ids[0]
            
            if object_node:
                obj_name = self._get_text(object_node, source_code)
                full_call = f"{obj_name}.{method_name}"
                if full_call in self.SPRING_SINKS: return self.SPRING_SINKS[full_call]
            
            return self.SPRING_SINKS.get(method_name)
        return None

class JakartaEEMapper(JavaFrameworkMapper):
    """Mapping for standard Jakarta EE / J2EE Servlets."""
    SERVLET_SOURCES = {"getParameter", "getHeader", "getCookies", "getQueryString"}

    def _get_text(self, node: Node, source_code: bytes) -> str:
        return source_code[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def is_sink(self, node: Node, source_code: bytes) -> Optional[Dict[str, Any]]:
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if not name_node:
                ids = [c for c in node.children if c.type == "identifier"]
                if ids: name_node = ids[-1]
            
            if name_node:
                method_name = self._get_text(name_node, source_code)
                if method_name in ["getWriter", "getOutputStream"]: 
                    return {"type": "XSS", "args": None}
        return None

class JaxRsMapper(JavaFrameworkMapper):
    """Mapping for JAX-RS (Jersey, RestEasy) annotations."""
    JAXRS_SOURCE_ANNOTATIONS = {
        "QueryParam", "PathParam", "HeaderParam", "CookieParam", "FormParam", "MatrixParam", "Context"
    }

    def _get_text(self, node: Node, source_code: bytes) -> str:
        return source_code[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def get_source_name(self, node: Node, source_code: bytes) -> Optional[str]:
        if node.type == "formal_parameter":
            for child in node.children:
                if child.type == "modifiers":
                    for mod in child.children:
                        if mod.type == "annotation":
                            name_node = mod.child_by_field_name("name")
                            if name_node:
                                ann_name = self._get_text(name_node, source_code).split(".")[-1]
                                if ann_name in self.JAXRS_SOURCE_ANNOTATIONS:
                                    param_name_node = node.child_by_field_name("name")
                                    if param_name_node:
                                        return self._get_text(param_name_node, source_code)
        return None

class HibernateMapper(JavaFrameworkMapper):
    """Mapping for Hibernate / JPA sinks."""
    HIBERNATE_SINKS = {
        "createQuery": {"type": "SQL_INJECTION", "args": [0]},
        "createNativeQuery": {"type": "SQL_INJECTION", "args": [0]},
        "createSelectionQuery": {"type": "SQL_INJECTION", "args": [0]},
        "createMutationQuery": {"type": "SQL_INJECTION", "args": [0]}
    }

    def _get_text(self, node: Node, source_code: bytes) -> str:
        return source_code[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def is_sink(self, node: Node, source_code: bytes) -> Optional[Dict[str, Any]]:
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if not name_node:
                # Robust extraction: the method name is usually the identifier before the argument_list
                ids = [c for c in node.children if c.type == "identifier"]
                if ids: name_node = ids[-1]
            
            if name_node:
                method_name = self._get_text(name_node, source_code)
                if method_name in self.HIBERNATE_SINKS:
                    return self.HIBERNATE_SINKS[method_name]
        return None
