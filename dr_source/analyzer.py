import os
import re
import sqlite3
import json
import logging
import click
import javalang
from bs4 import BeautifulSoup
from typing import List, Dict, Optional, Tuple


class VulnerabilityDetector:
    VULNERABILITY_PATTERNS = {
        "XSS": [
            # Java Patterns
            r"(response\.getWriter\(\)\.print|out\.println)\(.*\)",
            # JSP Patterns
            r"\$\{.*?\}",  # Direct EL expressions
            r'<c:out value=".*?"',  # JSTL out tag
        ],
        "SQL_INJECTION": [
            r"(executeQuery|prepareStatement)\(.*\+.*\)",  # Dynamic SQL
            r'(\.createQuery\(|\.createNativeQuery\()\s*["\'].*\$.*["\']',  # HQL/JPQL Injection
        ],
        "COMMAND_INJECTION": [
            r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\(.*\)",
            r"java\.lang\.Runtime\.getRuntime\(\)\.exec",
        ],
        "PATH_TRAVERSAL": [
            r"(new File|FileInputStream)\(.*user.*input.*\)",
            r"\.getResourceAsStream\(.*\+.*\)",
            r"\.\./|\.\\",  # Path traversal characters
        ],
        "DESERIALIZATION": [
            r"ObjectInputStream\.readObject\(\)",
            r"new ObjectInputStream\(",
        ],
        "SENSITIVE_DATA_EXPOSURE": [
            r"System\.out\.println\(.*password.*\)",
            r"logger\.info\(.*credentials.*\)",
            r"print.*sensitive",
        ],
    }

    @classmethod
    def detect_vulnerabilities(cls, content: str, file_path: str) -> List[Dict]:
        vulnerabilities = []

        for vuln_type, patterns in cls.VULNERABILITY_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    vulnerabilities.append(
                        {
                            "type": vuln_type,
                            "line_number": content[: match.start()].count("\n") + 1,
                            "description": f"Potential {vuln_type} vulnerability",
                            "severity": cls._determine_severity(vuln_type),
                            "match": match.group(0),
                        }
                    )

        return vulnerabilities

    @staticmethod
    def _determine_severity(vuln_type: str) -> str:
        severity_map = {
            "XSS": "HIGH",
            "SQL_INJECTION": "CRITICAL",
            "COMMAND_INJECTION": "CRITICAL",
            "PATH_TRAVERSAL": "HIGH",
            "DESERIALIZATION": "CRITICAL",
            "SENSITIVE_DATA_EXPOSURE": "MEDIUM",
        }
        return severity_map.get(vuln_type, "LOW")


class DRSourceAnalyzer:
    def __init__(self, project_path: str):
        # Generate database name from project path
        project_name = os.path.basename(os.path.normpath(project_path))
        self.db_path = f"{project_name}_vulnerabilities.sqlite3"

        self.project_path = project_path
        self.logger = self._setup_logging()
        self._init_database()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - DRSource - %(levelname)s: %(message)s",
        )
        return logging.getLogger("DRSourceAnalyzer")

    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                file_path TEXT,
                line_number INTEGER,
                vulnerability_type TEXT,
                description TEXT,
                severity TEXT,
                code_snippet TEXT
            )
        """)
        conn.commit()
        conn.close()

    def find_project_files(self) -> List[Tuple[str, str]]:
        """Find Java and JSP files recursively"""
        files = []
        for root, _, filenames in os.walk(self.project_path):
            for filename in filenames:
                if filename.endswith((".java", ".jsp")):
                    files.append(
                        (os.path.join(root, filename), filename.split(".")[-1])
                    )
        return files

    def analyze_file(self, file_path: str, file_type: str) -> List[Dict]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if file_type == "java":
                vulnerabilities = VulnerabilityDetector.detect_vulnerabilities(
                    content, file_path
                )
            elif file_type == "jsp":
                vulnerabilities = self._analyze_jsp(content, file_path)

            return vulnerabilities
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")
            return []

    def _analyze_jsp(self, content: str, file_path: str) -> List[Dict]:
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
                    {
                        "type": "XSS",
                        "line_number": content[: match.start()].count("\n") + 1,
                        "description": "Potential XSS in JSP expression",
                        "severity": "HIGH",
                        "match": match.group(0),
                    }
                )

        # Parse HTML for potential security issues
        soup = BeautifulSoup(content, "html.parser")

        # Check for unsafe attributes
        unsafe_attributes = ["onclick", "onload", "onerror"]
        for attr in unsafe_attributes:
            elements = soup.find_all(attrs={attr: True})
            for el in elements:
                vulnerabilities.append(
                    {
                        "type": "XSS",
                        "line_number": content[: content.find(str(el))].count("\n") + 1,
                        "description": f"Potential XSS via {attr} attribute",
                        "severity": "HIGH",
                        "match": str(el),
                    }
                )

        return vulnerabilities

    def analyze_project(self) -> List[Dict]:
        all_vulnerabilities = []
        project_files = self.find_project_files()

        for file_path, file_type in project_files:
            file_vulnerabilities = self.analyze_file(file_path, file_type)

            if file_vulnerabilities:
                # Print vulnerabilities to stdout
                for vuln in file_vulnerabilities:
                    print(f"Vulnerability in {file_path}:")
                    print(f"  Type: {vuln['type']}")
                    print(f"  Line: {vuln['line_number']}")
                    print(f"  Description: {vuln['description']}")
                    print(f"  Severity: {vuln['severity']}")
                    print(f"  Snippet: {vuln.get('match', 'N/A')}")
                    print("-" * 50)
                self._store_vulnerabilities(file_path, file_vulnerabilities)
                all_vulnerabilities.extend(file_vulnerabilities)

        return all_vulnerabilities

    def _store_vulnerabilities(self, file_path: str, vulnerabilities: List[Dict]):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for vuln in vulnerabilities:
            cursor.execute(
                """
                INSERT INTO vulnerabilities 
                (file_path, line_number, vulnerability_type, description, severity, code_snippet)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    file_path,
                    vuln["line_number"],
                    vuln["type"],
                    vuln["description"],
                    vuln["severity"],
                    vuln.get("match", ""),
                ),
            )

        conn.commit()
        conn.close()

    def generate_report(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT vulnerability_type, COUNT(*) FROM vulnerabilities GROUP BY vulnerability_type"
        )
        type_distribution = dict(cursor.fetchall())

        cursor.execute(
            "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
        )
        severity_distribution = dict(cursor.fetchall())

        conn.close()

        return {
            "total_vulnerabilities": sum(type_distribution.values()),
            "vulnerability_types": type_distribution,
            "severity_distribution": severity_distribution,
        }
