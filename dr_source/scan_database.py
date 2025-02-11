import sqlite3
import os
import re
from datetime import datetime


class ScanDatabase:
    def __init__(self, project_name):
        self.project_name = self._sanitize_project_name(project_name)
        self.db_path = f"databases/{self.project_name}.db"
        os.makedirs("databases", exist_ok=True)  # Crea la cartella se non esiste
        self._create_tables()

    def _sanitize_project_name(self, name):
        """Normalizza il nome del progetto per evitare problemi nei file system."""
        if name in {".", ".."}:
            return "default_project"  # Nome predefinito se si usa `.` o `..`
        return re.sub(r"[^\w\-_]", "_", name)  # Sostituisce caratteri non validi

    def _sanitize_project_name(self, name):
        """Normalizza il nome del progetto per evitare problemi nel filesystem."""
        if name in {".", ".."}:
            return "default_project"  # Nome predefinito
        return re.sub(r"[^\w\-_]", "_", name)  # Sostituisce caratteri non validi

    def _create_tables(self):
        """Crea le tabelle scans e vulnerabilities nel database se non esistono."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Tabella delle scansioni
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    num_vulnerabilities INTEGER DEFAULT 0
                )
            """)

            # Tabella delle vulnerabilità
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    file TEXT NOT NULL,
                    vulnerability TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    sink TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)

            conn.commit()

    def start_scan(self):
        """Inserisce una nuova scansione e restituisce l'ID per riferire le vulnerabilità."""
        timestamp = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO scans (timestamp) VALUES (?)", (timestamp,))
            conn.commit()
            return cursor.lastrowid  # Restituisce l'ID della scansione appena creata

    def save_vulnerability(self, scan_id, file, vulnerability, vuln_type, source, sink):
        """Salva una vulnerabilità associata a una scansione."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO vulnerabilities (scan_id, file, vulnerability, vuln_type, source, sink)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (scan_id, file, vulnerability, vuln_type, source, sink),
            )
            conn.commit()

    def update_scan_count(self, scan_id):
        """Aggiorna il numero di vulnerabilità trovate per una scansione."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE scans
                SET num_vulnerabilities = (SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ?)
                WHERE id = ?
            """,
                (scan_id, scan_id),
            )
            conn.commit()

    def get_scan_history(self):
        """Recupera lo storico delle scansioni."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
            return cursor.fetchall()

    def get_vulnerabilities(self, scan_id):
        """Recupera le vulnerabilità di una scansione specifica."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT file, vulnerability, vuln_type, source, sink FROM vulnerabilities
                WHERE scan_id = ?
            """,
                (scan_id,),
            )
            return cursor.fetchall()
