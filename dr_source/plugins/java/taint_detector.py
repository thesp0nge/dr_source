import logging
from .taint_visitor import TaintVisitor
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class TaintDetector:
    def detect_ast_taint(
        self,
        file_object,
        ast_tree,
        source_list: List[str],
        sink_list: List[str],
        vuln_prefix: str,
    ) -> List[Dict[str, Any]]:
        # 1. Create the visitor with both lists
        visitor = TaintVisitor(source_list, sink_list)

        # 2. Run the visit to identify tainted variables
        visitor.visit(ast_tree)

        # 3. Get the results by checking sinks against the AST
        vulns = visitor.get_vulnerabilities(ast_tree)
        # -------------------------------

        results = []
        for v in vulns:
            results.append(
                {
                    "file": file_object.path,
                    "vuln_type": f"{vuln_prefix} (AST Taint)",
                    "match": f"{v['sink']} called with tainted variable '{v['variable']}'",
                    "line": v["line"],
                    "trace": v.get("trace", []),
                }
            )
        return results
