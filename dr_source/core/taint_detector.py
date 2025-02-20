# dr_source/core/taint_detector.py
import logging
from dr_source.core.taint_visitor import TaintVisitor

logger = logging.getLogger(__name__)


class TaintDetector:
    def detect_ast_taint(self, file_object, ast_tree, sink_list, vuln_prefix):
        visitor = TaintVisitor()
        visitor.visit(ast_tree)
        vulns = visitor.get_vulnerabilities(ast_tree, sink_list)
        results = []
        for v in vulns:
            results.append(
                {
                    "file": file_object.path,
                    "vuln_type": f"{vuln_prefix} (AST Taint)",
                    "match": f"{v['sink']} called with tainted variable '{v['variable']}'",
                    "line": v["line"],
                }
            )
        return results
