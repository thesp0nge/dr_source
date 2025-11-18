import logging
from typing import List, Dict, Any
from tree_sitter import Tree
from .taint_visitor import TaintVisitor

logger = logging.getLogger(__name__)


class TaintDetector:
    def detect_ast_taint(
        self,
        file_object,
        ast_tree: Tree,
        source_code: bytes,
        source_list: List[str],
        sink_list: List[str],
        vuln_prefix: str,
    ) -> List[Dict[str, Any]]:
        # 1. Create the visitor
        visitor = TaintVisitor(source_list, sink_list, source_code)

        # 2. Run the visit
        visitor.visit(ast_tree.root_node)

        # 3. Get raw results
        raw_vulns = visitor.get_vulnerabilities()

        # 4. Format results for the plugin
        #    (This is the part that was missing!)
        formatted_results = []
        for v in raw_vulns:
            formatted_results.append(
                {
                    "file": file_object.path,
                    "vuln_type": f"{vuln_prefix} (AST Taint)",
                    "match": f"Sink method '{v['sink']}' called with tainted variable '{v['variable']}'",
                    "line": v["line"],
                    "trace": v["trace"],
                }
            )

        return formatted_results
