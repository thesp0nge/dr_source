import javalang
import networkx as nx
from typing import List
from .vulnerability import Vulnerability
from .taint_analyzer import TaintAnalyzer


class VariableAssignment:
    def __init__(self, left, right, line):
        self.left = left  # Nome della variabile assegnata
        self.right = right  # Espressione assegnata
        self.line = line  # Numero di riga


class MethodCall:
    def __init__(self, method, arguments, line):
        self.method = method  # Nome del metodo chiamato
        self.arguments = arguments  # Lista di argomenti passati
        self.line = line  # Numero di riga


class JavaAstDetector:
    def __init__(self, code):
        self.code = code
        self.ast = javalang.parse.parse(code)
        self.data_flow_graph = nx.DiGraph()
        self.ast_nodes = self.parse_java_code(self.ast)

        # 🎯 SOURCES: Input non fidati
        self.sources = {
            "SQL_INJECTION": [
                "request.getParameter",
                "request.getQueryString",
                "request.getCookies",
                "session.getAttribute",
                "System.getProperty",
            ],
            "XSS": [
                "request.getParameter",
                "request.getQueryString",
                "request.getHeader",
                "request.getCookies",
                "session.getAttribute",
            ],
            "PATH_TRAVERSAL": [
                "request.getParameter",
                "System.getenv",
                "request.getQueryString",
                "request.getCookies",
            ],
            "COMMAND_INJECTION": [
                "request.getParameter",
                "request.getQueryString",
                "System.getenv",
                "System.getProperty",
            ],
            "SERIALIZATION_ISSUES": [
                "ObjectInputStream.readObject",
                "XMLDecoder.readObject",
            ],
        }

        # ⚠️ SINKS: Metodi vulnerabili a specifici attacchi
        self.sinks = {
            "SQL_INJECTION": {
                "Statement.execute",
                "Statement.executeQuery",
                "Statement.executeUpdate",
                "Connection.prepareStatement",
                "PreparedStatement.execute",
                "PreparedStatement.executeQuery",
                "PreparedStatement.executeUpdate",
            },
            "XSS": {
                "response.getWriter.write",
                "response.getOutputStream.print",
                "response.getOutputStream.println",
                "out.print",
                "out.println",
                "ServletResponse.getWriter().print",
                "ServletResponse.getWriter().println",
            },
            "PATH_TRAVERSAL": {
                "FileInputStream",
                "FileOutputStream",
                "FileReader",
                "FileWriter",
                "BufferedReader",
                "BufferedWriter",
                "File",
                "Files.newInputStream",
                "Files.newOutputStream",
                "Files.readAllBytes",
                "Files.write",
            },
            "COMMAND_INJECTION": {"Runtime.getRuntime.exec", "ProcessBuilder.start"},
            "SERIALIZATION_ISSUE": {
                "ObjectInputStream.readObject",
                "XMLDecoder.readObject",
            },
        }

        # 🔥 Soluzione: Prima raccogliamo TUTTE le variabili esistenti
        self.variables = set()

    def parse_java_code(self, tree):
        nodes = []

        for path, node in tree:
            if isinstance(node, javalang.tree.Assignment):
                # Estrarre la variabile assegnata e il valore
                left = node.expressionl if hasattr(node, "expressionl") else None
                right = node.value if hasattr(node, "value") else None
                line = node.position.line if node.position else -1
                if left and right:
                    nodes.append(VariableAssignment(left, right, node.position.line))

            elif isinstance(node, javalang.tree.MethodInvocation):
                # Estrarre nome del metodo e parametri
                method = node.member
                arguments = [arg for arg in node.arguments]
                line = node.position.line if node.position else -1
                nodes.append(MethodCall(method, arguments, node.position.line))

        return nodes

    def analyze_ast(self, filename: str) -> List[Vulnerability]:
        taint_analyzer = TaintAnalyzer()
        vulnerabilities = []

        for node in self.ast_nodes:
            if isinstance(node, VariableAssignment):
                taint_analyzer.analyze_assignment(node.left, node.right)

            elif isinstance(node, MethodCall):
                # Controlliamo se è una source
                for vuln_type, sources in SOURCES.items():
                    if node.method in sources:
                        taint_analyzer.mark_tainted(node.arguments[0], node.method)

                # Controlliamo se è un sink
                for vuln_type, sinks in SINKS.items():
                    if node.method in sinks:
                        result = taint_analyzer.analyze_sink(
                            node.method, node.arguments[0]
                        )
                        if result:
                            vulnerabilities.append(
                                {
                                    "file": filename,
                                    "type": vuln_type,
                                    "source": result["source"],
                                    "sink": result["sink"],
                                    "variable": result["variable"],
                                    "line": node.line,
                                }
                            )

        return vulnerabilities

    def normalize_method_call(self, node):
        """Normalizza una chiamata a metodo per evitare variazioni nei parametri."""
        if isinstance(node, javalang.tree.MethodInvocation):
            return f"{node.qualifier}.{node.member}" if node.qualifier else node.member
        return None

    def first_pass_collect_variables(self):
        """Passo 1: Raccogliamo tutte le variabili per evitare errori."""
        for path, node in self.ast:
            if isinstance(node, javalang.tree.VariableDeclarator):
                self.variables.add(node.name)
            elif isinstance(node, javalang.tree.MethodInvocation):
                method_call = self.normalize_method_call(node)
                if method_call:
                    self.variables.add(method_call)

    def build_data_flow_graph(self):
        """Costruisce un grafo dei flussi di dati tra source e sink."""
        self.first_pass_collect_variables()  # 📌 Raccogliamo prima tutte le variabili

        # 📌 Step 1: Aggiungiamo tutte le source PRIMA di analizzare il codice
        for source_type, source_list in self.sources.items():
            for source in source_list:
                if source not in self.data_flow_graph:
                    print(f"✅ Aggiungo la source {source} al grafo")
                    self.data_flow_graph.add_node(source)

        # 📌 Step 2: Ora analizziamo il codice e creiamo i collegamenti
        for path, node in self.ast:
            if isinstance(node, javalang.tree.VariableDeclarator) and node.initializer:
                var_name = node.name
                initializer = node.initializer

                if isinstance(initializer, javalang.tree.MethodInvocation):
                    method_call = self.normalize_method_call(initializer)

                    for source_type, source_list in self.sources.items():
                        if method_call in source_list:
                            print(
                                f"🔹 Variabile {var_name} è una source → Aggiungo {method_call} → {var_name}"
                            )
                            self.data_flow_graph.add_edge(method_call, var_name)

    def build_data_flow_graph(self):
        """Costruisce un grafo dei flussi di dati tra source e sink."""
        self.first_pass_collect_variables()  # 📌 Raccogliamo prima tutte le variabili

        print(
            "📌 Nodi iniziali nel grafo:", list(self.data_flow_graph.nodes)
        )  # Debug iniziale

        # 🔹 1️⃣ Aggiungiamo tutte le source al grafo PRIMA di analizzare il codice
        for source_type, source_list in self.sources.items():
            for source in source_list:
                if source not in self.data_flow_graph:
                    print(f"✅ Aggiungo la source {source} al grafo")
                    self.data_flow_graph.add_node(source)

        # 🔹 2️⃣ Analizziamo il codice e creiamo le connessioni
        for path, node in self.ast:
            if isinstance(node, javalang.tree.VariableDeclarator) and node.initializer:
                var_name = node.name
                initializer = node.initializer

                if isinstance(initializer, javalang.tree.MethodInvocation):
                    method_call = self.normalize_method_call(initializer)

                    if method_call in self.sources.get(
                        "input", []
                    ):  # Se è una source conosciuta
                        print(
                            f"🔹 Variabile {var_name} è una source → Aggiungo {method_call} → {var_name}"
                        )
                        self.data_flow_graph.add_edge(method_call, var_name)

            elif isinstance(node, javalang.tree.MethodInvocation):
                method_call = self.normalize_method_call(node)

                if method_call is None:
                    print(f"⚠️ Metodo non riconosciuto: {node}")
                    continue

                for vuln_type, sink_list in self.sinks.items():
                    if method_call in sink_list:
                        for arg in node.arguments:
                            if isinstance(arg, javalang.tree.MemberReference):
                                if arg.member in self.data_flow_graph:
                                    print(
                                        f"⚠️ Flusso trovato: {arg.member} → {method_call}"
                                    )
                                    self.data_flow_graph.add_edge(
                                        arg.member, method_call
                                    )
                                else:
                                    print(
                                        f"🚨 ERRORE: Target {arg.member} non presente nel grafo! Aggiungo il nodo e lo colleghiamo"
                                    )
                                    self.data_flow_graph.add_node(arg.member)
                                    self.data_flow_graph.add_edge(
                                        arg.member, method_call
                                    )

        print(
            "📌 Nodi finali nel grafo:", list(self.data_flow_graph.nodes)
        )  # Debug finale

    def detect_vulnerabilities(self):
        """Trova vulnerabilità verificando se esiste un percorso da una source a un sink."""
        self.build_data_flow_graph()
        vulnerabilities = []

        for source_type, source_list in self.sources.items():
            for source in source_list:
                for vuln_type, sink_list in self.sinks.items():
                    for sink in sink_list:
                        if nx.has_path(self.data_flow_graph, source, sink):
                            vulnerabilities.append(
                                {"type": vuln_type, "source": source, "sink": sink}
                            )

        return vulnerabilities
