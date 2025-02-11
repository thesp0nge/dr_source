import sqlite3
import os
import datetime


class ScanDatabase:
    def __init__(self, project_name):
        self.db_path = f"{project_name}_drsource.db"
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self._initialize_db()

    def _initialize_db(self):
        """Crea le tabelle del database se non esistono già."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                num_vulnerabilities INTEGER DEFAULT 0,
                num_files_analyzed INTEGER DEFAULT 0,
                scan_duration REAL DEFAULT 0
            )
        """)

        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                source TEXT NOT NULL,
                sink TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        self.conn.commit()

    def start_scan(self):
        """Registra una nuova scansione nel database e restituisce il suo ID."""
        timestamp = datetime.datetime.now().isoformat()
        self.cursor.execute("INSERT INTO scans (timestamp) VALUES (?)", (timestamp,))
        self.conn.commit()
        return self.cursor.lastrowid

    def save_vulnerability(self, scan_id, file_path, vuln_type, source, sink):
        """Salva una vulnerabilità nel database e determina se è nuova o preesistente."""
        existing_vuln = self.cursor.execute(
            """
            SELECT id FROM vulnerabilities 
            WHERE file_path=? AND vuln_type=? AND source=? AND sink=?
        """,
            (file_path, vuln_type, source, sink),
        ).fetchone()

        if existing_vuln:
            status = "existing"
        else:
            status = "new"

        self.cursor.execute(
            """
            INSERT INTO vulnerabilities (scan_id, file_path, vuln_type, source, sink, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (scan_id, file_path, vuln_type, source, sink, status),
        )
        self.conn.commit()

    def update_scan_summary(
        self, scan_id, num_vulnerabilities, num_files_analyzed, scan_duration
    ):
        """Aggiorna il riepilogo della scansione con dati finali."""
        self.cursor.execute(
            """
            UPDATE scans 
            SET num_vulnerabilities=?, num_files_analyzed=?, scan_duration=?
            WHERE id=?
        """,
            (num_vulnerabilities, num_files_analyzed, scan_duration, scan_id),
        )
        self.conn.commit()

    def get_scan_history(self):
        """Restituisce lo storico delle scansioni con numero di vulnerabilità trovate."""
        return self.cursor.execute(
            "SELECT id, timestamp, num_vulnerabilities FROM scans ORDER BY id DESC"
        ).fetchall()

    def close(self):
        self.conn.close()

