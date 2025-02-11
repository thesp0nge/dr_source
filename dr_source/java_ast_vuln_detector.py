import javalang
import networkx as nx


class JavaAstDetector:
    def __init__(self, code):
        self.code = code
        self.ast = javalang.parse.parse(code)
        self.data_flow_graph = nx.DiGraph()

        # 🎯 SOURCES: Input non fidati
        self.sources = {
            "USER_INPUT": {
                "request.getParameter",
                "request.getQueryString",
                "request.getCookies",
                "request.getHeader",
                "request.getHeaders",
                "request.getInputStream",
                "request.getReader",
                "request.getPart",
                "request.getParts",
                "scanner.nextLine",
                "BufferedReader.readLine",
                "System.console.readLine",
            }
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
