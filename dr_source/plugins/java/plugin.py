import javalang
from typing import List
from types import SimpleNamespace

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from .taint_detector import TaintDetector
# We don't need to import TaintVisitor here anymore


class JavaAstAnalyzer(AnalyzerPlugin):
    def __init__(self):
        self.kb = KnowledgeBaseLoader()
        self.detector = TaintDetector()  # We can reuse the detector instance

    @property
    def name(self) -> str:
        return "Java AST Analyzer"

    def get_supported_extensions(self) -> List[str]:
        return [".java"]

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            tree = javalang.parse.parse(code)

            file_object = SimpleNamespace(path=file_path)
            all_vuln_types = self.kb.rules.keys()

            for vuln_type in all_vuln_types:
                # --- THIS IS THE FULL FIX ---
                # 1. Get BOTH sources and sinks from the KB
                sources = self.kb.get_lang_ast_sources(vuln_type, "java")
                sinks = self.kb.get_lang_ast_sinks(vuln_type, "java")

                # If this rule has no sources OR no sinks, skip it
                if not sources or not sinks:
                    continue

                rules = self.kb.get_detector_rules(vuln_type)
                severity = rules.get("severity", "MEDIUM").upper()

                # 2. Call your updated detector with BOTH lists
                raw_issues = self.detector.detect_ast_taint(
                    file_object=file_object,
                    ast_tree=tree,
                    source_list=sources,  # <-- Pass the sources
                    sink_list=sinks,  # <-- Pass the sinks
                    vuln_prefix=vuln_type,
                )

                # 3. Translate results (this code is unchanged)
                for issue in raw_issues:
                    vuln = Vulnerability(
                        vulnerability_type=issue["vuln_type"],
                        message=issue["match"],
                        severity=severity,
                        file_path=issue["file"],
                        line_number=issue["line"],
                        plugin_name=self.name,
                    )
                    findings.append(vuln)

        except javalang.parser.JavaSyntaxError as e:
            print(f"Warning: Could not parse Java file {file_path}. Error: {e}")
        except Exception as e:
            print(f"Error analyzing {file_path} with {self.name}: {e}")

        return findings
