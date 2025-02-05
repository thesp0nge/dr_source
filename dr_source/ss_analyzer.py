import javalang
import re
from typing import List, Dict, Set, Union, Optional
from pathlib import Path
from bs4 import BeautifulSoup
import security_vulnerability


class SsAnalizer:
    def __init__(self, project_path: str):
        self.vulnerabilities: List[SecurityVulnerability] = []
        self.tainted_variables: Dict[str, Set[str]] = {}

        # Definizione delle vulnerability patterns
        self.VULNERABILITY_PATTERNS = {
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
        }

    def analyze_file(self, file_path: str) -> List[SecurityVulnerability]:
        """Analizza un singolo file Java o JSP."""
        self.current_file = file_path

        if file_path.endswith(".java"):
            return self._analyze_java_file(file_path)
        elif file_path.endswith(".jsp"):
            return self._analyze_jsp_file(file_path)
        else:
            raise ValueError(f"Unsupported file type: {file_path}")

    def _analyze_java_file(self, file_path: str) -> List[SecurityVulnerability]:
        """Analizza un file Java usando javalang."""
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        try:
            tree = javalang.parse.parse(content)
            self._analyze_java_ast(tree)
        except Exception as e:
            print(f"Error parsing Java file {file_path}: {str(e)}")

        return self.vulnerabilities

    def _analyze_jsp_file(self, file_path: str) -> List[SecurityVulnerability]:
        """Analizza un file JSP per vulnerabilità."""
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        # Analizza il codice JSP usando BeautifulSoup
        soup = BeautifulSoup(content, "html.parser")

        # Cerca scriptlet JSP
        scriptlets = soup.find_all("script")
        scriptlets.extend(soup.find_all(string=re.compile(r"<%.*?%>")))

        for scriptlet in scriptlets:
            self._analyze_jsp_scriptlet(scriptlet.string, file_path)

        return self.vulnerabilities

    def _analyze_java_ast(self, tree) -> None:
        """Analizza l'AST Java per vulnerabilità."""
        for path, node in tree.filter(javalang.tree.MethodInvocation):
            # Analizza le chiamate ai metodi
            method_name = node.member

            # Controlla se è una source
            if self._is_source(method_name):
                var_name = self._get_assignment_target(path)
                if var_name:
                    self._mark_as_tainted(var_name)

            # Controlla se è un sink
            for vuln_type, patterns in self.VULNERABILITY_PATTERNS.items():
                if self._is_sink(method_name, patterns["sinks"]):
                    if self._has_tainted_argument(node):
                        self._add_vulnerability(
                            vuln_type,
                            node.position.line if node.position else 0,
                            str(node),
                            patterns["severity"],
                        )

    def _analyze_jsp_scriptlet(self, scriptlet: str, file_path: str) -> None:
        """Analizza uno scriptlet JSP per vulnerabilità."""
        # Cerca pattern di vulnerabilità comuni in JSP
        for vuln_type, patterns in self.VULNERABILITY_PATTERNS.items():
            for source in patterns["sources"]:
                for sink in patterns["sinks"]:
                    if source in scriptlet and sink in scriptlet:
                        # Analisi base della propagazione
                        if self._check_taint_flow(scriptlet, source, sink):
                            self._add_vulnerability(
                                vuln_type,
                                0,  # La posizione esatta richiederebbe più analisi
                                scriptlet,
                                patterns["severity"],
                            )

    def _is_source(self, method_name: str) -> bool:
        """Verifica se un metodo è una source di dati non fidati."""
        return any(
            method_name in patterns["sources"]
            for patterns in self.VULNERABILITY_PATTERNS.values()
        )

    def _is_sink(self, method_name: str, sinks: Set[str]) -> bool:
        """Verifica se un metodo è un sink vulnerabile."""
        return method_name in sinks

    def _mark_as_tainted(self, variable: str) -> None:
        """Marca una variabile come tainted."""
        self.tainted_variables.setdefault("current", set()).add(variable)

    def _has_tainted_argument(self, node) -> bool:
        """Verifica se una chiamata di metodo ha argomenti tainted."""
        if not hasattr(node, "arguments"):
            return False

        return any(
            arg.value in self.tainted_variables.get("current", set())
            if hasattr(arg, "value")
            else False
            for arg in node.arguments
        )

    def _check_taint_flow(self, code: str, source: str, sink: str) -> bool:
        """Analisi base del flusso di taint tra source e sink."""
        # Implementazione semplificata - cerca se c'è un percorso tra source e sink
        source_pos = code.find(source)
        sink_pos = code.find(sink)

        if source_pos == -1 or sink_pos == -1:
            return False

        # Verifica se la source viene usata prima del sink
        return source_pos < sink_pos

    def _add_vulnerability(
        self, vuln_type: str, line: int, code: str, severity: str
    ) -> None:
        """Aggiunge una vulnerabilità trovata alla lista."""
        description = f"Found {vuln_type} vulnerability in code. User input from a source is used in a dangerous sink without proper sanitization."

        self.vulnerabilities.append(
            SecurityVulnerability(
                type=vuln_type,
                line=line,
                code=code,
                file_path=self.current_file,
                description=description,
                severity=severity,
            )
        )

    def analyze_directory(self, directory: str) -> List[SecurityVulnerability]:
        """Analizza ricorsivamente tutti i file Java e JSP in una directory."""
        vulnerabilities = []
        for path in Path(directory).rglob("*"):
            if path.suffix in [".java", ".jsp"]:
                vulnerabilities.extend(self.analyze_file(str(path)))
        return vulnerabilities
