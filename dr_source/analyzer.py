import os
import re
import sqlite3
import logging
import javalang
from bs4 import BeautifulSoup
from typing import List, Dict, Tuple
from .vulnerability import Vulnerability
from collections import Counter


class VulnerabilityDetector:
    SS_VULNERABILITY_PATTERNS = (
        {
            "SQL_INJECTION": {
                "sources": {
                    "getParameter",
                    "getHeader",
                    "getQueryString",
                    "getCookies",
                    "getInputStream",
                    "getReader",
                    "getParameterMap",
                },
                "sinks": {
                    "executeQuery",
                    "executeUpdate",
                    "execute",
                    "addBatch",
                    "prepareStatement",
                    "nativeQuery",
                },
                "severity": "HIGH",
            },
            "XSS": {
                "sources": {
                    "getParameter",
                    "getHeader",
                    "getCookies",
                    "getQueryString",
                },
                "sinks": {
                    "println",
                    "print",
                    "write",
                    "getWriter",
                    "out.print",
                    "out.println",
                    "response.getWriter",
                },
                "severity": "MEDIUM",
            },
            "PATH_TRAVERSAL": {
                "sources": {"getParameter", "getHeader", "getQueryString"},
                "sinks": {
                    "File",
                    "FileInputStream",
                    "FileReader",
                    "FileWriter",
                    "RandomAccessFile",
                },
                "severity": "HIGH",
            },
        },
    )
    RE_VULNERABILITY_PATTERNS = {
        "XSS": [
            # Java Patterns
            r"(response\\.getWriter\\(\\)\\.print|out\\.println)\\(\\s*(?!\"[^\"]*\"\\s*\\)$).*",
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
            r"(?:https?://[^/\s]+|(?:GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+)[^\s]*?(?:\.\./|\.\\)[^\s]*",
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
    def re_detect_vulnerabilities(
        cls, content: str, file_path: str
    ) -> List[Vulnerability]:
        vulnerabilities = []

        for vuln_type, patterns in cls.RE_VULNERABILITY_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    vulnerabilities.append(
                        Vulnerability(
                            type=vuln_type,
                            line=content[: match.start()].count("\n") + 1,
                            match=match.group(0),
                            file_path=file_path,
                            description=f"Potential {vuln_type} vulnerability",
                            severity=cls._determine_severity(vuln_type),
                            engine="re",
                        )
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
    KNOWN_EXTENSIONS = {
        "jsp",
        "java",
    }

    def __init__(self, project_path: str):
        # Generate database name from project path
        project_name = os.path.basename(os.path.normpath(project_path))
        self.db_path = f"{project_name}_vulnerabilities.sqlite3"

        self.vulnerabilities: List[Vulnerability] = []
        self.tainted_variables: Dict[str, Set[str]] = {}

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
                engine TEXT,
                vulnerability_type TEXT,
                description TEXT,
                severity TEXT,
                code_snippet TEXT, 
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
        """)
        conn.commit()
        conn.close()

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
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if file_type == "java":
                vulnerabilities = VulnerabilityDetector.re_detect_vulnerabilities(
                    content, file_path
                )
            elif file_type == "jsp":
                vulnerabilities = self._analyze_jsp(content, file_path)

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

    def analyze_project(self) -> List[Vulnerability]:
        all_vulnerabilities = []
        project_files = self.find_project_files()

        for file_path, file_type in project_files:
            file_vulnerabilities = self.analyze_file(file_path, file_type)

            if file_vulnerabilities:
                # Print vulnerabilities to stdout
                for vuln in file_vulnerabilities:
                    print(f"Vulnerability in {file_path}:")
                    print(f"  Type: {vuln.type}")
                    print(f"  Line: {vuln.line}")
                    print(f"  Description: {vuln.description}")
                    print(f"  Severity: {vuln.severity}")
                    print(f"  Snippet: {vuln.match}")
                    print("-" * 50)
                self._store_vulnerabilities(file_path, file_vulnerabilities)
                all_vulnerabilities.extend(file_vulnerabilities)

        return all_vulnerabilities

    def _store_vulnerabilities(
        self, file_path: str, vulnerabilities: List[Vulnerability]
    ):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for vuln in vulnerabilities:
            cursor.execute(
                """
                INSERT INTO vulnerabilities 
                (file_path, line_number, engine, vulnerability_type, description, severity, code_snippet)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    file_path,
                    vuln.line,
                    vuln.engine,
                    vuln.type,
                    vuln.description,
                    vuln.severity,
                    vuln.match,
                ),
            )

        conn.commit()
        conn.close()

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
