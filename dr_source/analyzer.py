import os
import re
import logging
import javalang
from bs4 import BeautifulSoup
from typing import List, Dict, Tuple

from dr_source.java_ast_vuln_detector import JavaAstDetector
from .vulnerability import Vulnerability
from .re_vulnerability_detector import ReVulnerabilityDetector
from collections import Counter


class DRSourceAnalyzer:
    KNOWN_EXTENSIONS = {
        "jsp",
        "java",
    }

    def __init__(self, project_path: str):
        # Generate database name from project path
        project_name = os.path.basename(os.path.normpath(project_path))

        self.vulnerabilities: List[Vulnerability] = []

        self.project_path = project_path
        self.logger = self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - DRSource - %(levelname)s: %(message)s",
        )
        return logging.getLogger("DRSourceAnalyzer")

    def find_project_files(
        self, lang: str, exclude_test: bool
    ) -> List[Tuple[str, str]]:
        """Find Java and JSP files recursively"""
        files = []
        for root, _, filenames in os.walk(self.project_path):
            for filename in filenames:
                file_extension = filename.split(".")[-1]
                file_path = os.path.join(root, filename)

                if exclude_test and (
                    "test" in filename.lower() or "test" in root.lower()
                ):
                    continue

                if file_extension in DRSourceAnalyzer.KNOWN_EXTENSIONS:
                    files.append((file_path, file_extension))

        return files

    def analyze_file(self, file_path: str, file_type: str) -> List[Vulnerability]:
        issues = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if file_type == "java":
                vulnerabilities = ReVulnerabilityDetector.detect_vulnerabilities(
                    content, file_path
                )
                # java_ast_detector = JavaAstDetector(content)
                # issues.append(java_ast_detector.analyze_ast(file_path))

            elif file_type == "jsp":
                vulnerabilities = self._analyze_jsp(content, file_path)

            if issues:
                print(f"\n🚨 Vulnerabilities found in {file_path}:")
                for vuln in issues:
                    print(
                        f"  🔥 {vuln['type']} detected: Data flows from '{vuln['source']}' → '{vuln['sink']}'"
                    )
            return vulnerabilities
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")
            return []

    def _analyze_jsp(self, content: str, file_path: str) -> List[Vulnerability]:
        """Enhanced JSP vulnerability analysis"""
        vulnerabilities = []

        # Detect XSS in JSP
        xss_patterns = [
            r"\$\{.*?\}",  # EL expressions
            r"<%= .*? %>",  # Scriptlet expressions
        ]

        for pattern in xss_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                vulnerabilities.append(
                    Vulnerability(
                        type="XSS",
                        line=content[: match.start()].count("\n") + 1,
                        match=match.group(0),
                        file_path=file_path,
                        description="Potential XSS in JSP expression",
                        severity="HIGH",
                        engine="re",
                    )
                )

        # Parse HTML for potential security issues
        soup = BeautifulSoup(content, "html.parser")

        # Check for unsafe attributes
        unsafe_attributes = ["onclick", "onload", "onerror"]
        for attr in unsafe_attributes:
            elements = soup.find_all(attrs={attr: True})
            for el in elements:
                vulnerabilities.append(
                    Vulnerability(
                        type="XSS",
                        line=content[: match.start()].count("\n") + 1,
                        match=match.group(0),
                        file_path=file_path,
                        description=f"Potential XSS via {attr} attribute",
                        severity="HIGH",
                        engine="re",
                    )
                )

        return vulnerabilities

    def generate_report(self, vulnerabilities: List[Vulnerability]) -> Dict:
        total_vulnerabilities = len(vulnerabilities)
        vulnerability_types = Counter(v.type for v in vulnerabilities)
        severity_distribution = Counter(v.severity for v in vulnerabilities)

        report_data = {
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerability_types": dict(vulnerability_types),
            "severity_distribution": dict(severity_distribution),
        }
        return report_data
