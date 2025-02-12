class TaintAnalyzer:
    def __init__(self):
        self.taint_map = {}  # Mappa le variabili ai valori taintati

    def mark_tainted(self, var_name, source):
        """Segna una variabile come taintata se proviene da una source."""
        self.taint_map[var_name] = source

    def is_tainted(self, var_name):
        """Controlla se una variabile è taintata."""
        return var_name in self.taint_map

    def analyze_assignment(self, left_var, right_var):
        """Propaga la taint da una variabile a un’altra."""
        if right_var in self.taint_map:
            self.taint_map[left_var] = self.taint_map[right_var]

    def analyze_sink(self, sink, var_name):
        """Verifica se una variabile taintata finisce in un sink vulnerabile."""
        if self.is_tainted(var_name):
            return {
                "sink": sink,
                "source": self.taint_map[var_name],
                "variable": var_name,
            }
        return None
