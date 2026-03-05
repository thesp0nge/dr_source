import re
import logging
from typing import List, Dict, Any
from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader

logger = logging.getLogger(__name__)

class RegexAnalyzer(AnalyzerPlugin):
    def __init__(self):
        self.kb = KnowledgeBaseLoader()

    @property
    def name(self) -> str:
        return "General Regex Analyzer"

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        ext = "." + file_path.split(".")[-1]
        
        # We need to map extensions to language names used in KB
        lang_map = {
            ".py": "python",
            ".java": "java",
            ".js": "javascript",
            ".ts": "javascript",
            ".php": "php",
            ".rb": "ruby"
        }
        lang = lang_map.get(ext)
        
        all_vuln_types = self.kb.get_all_vuln_types()
        
        # Collect and compile all relevant rules
        compiled_rules = []
        for vuln_type in all_vuln_types:
            # Get general regex patterns for this vuln type
            general = self.kb.get_general_regex(vuln_type)
            for r in general:
                try:
                    compiled_rules.append({
                        "id": r["id"],
                        "message": r["message"],
                        "pattern": re.compile(r["pattern"]),
                        "severity": r.get("severity", "MEDIUM"),
                        "type": vuln_type
                    })
                except: pass
            
            # Get language specific regex patterns
            if lang:
                specific = self.kb.get_lang_regex(vuln_type, lang)
                for r in specific:
                    try:
                        compiled_rules.append({
                            "id": r["id"],
                            "message": r["message"],
                            "pattern": re.compile(r["pattern"]),
                            "severity": r.get("severity", "MEDIUM"),
                            "type": vuln_type
                        })
                    except: pass

        reported = set()
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    for rule in compiled_rules:
                        if (rule["id"], line_num) in reported:
                            continue
                            
                        if rule["pattern"].search(line):
                            severity = rule["severity"].upper()
                            if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                                severity = "INFO"
                                
                            findings.append(Vulnerability(
                                file_path=file_path,
                                line_number=line_num,
                                vulnerability_type=rule["type"],
                                message=f"({rule['id']}) {rule['message']}",
                                severity=severity,
                                plugin_name=self.name
                            ))
                            reported.add((rule["id"], line_num))
        except Exception as e:
            logger.error(f"Error analyzing {file_path} with Regex Analyzer: {e}")

        return findings

    def get_supported_extensions(self) -> List[str]:
        return [".*"]
