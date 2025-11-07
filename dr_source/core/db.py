# dr_source/core/db.py
import sqlite3
import os
import re
from datetime import datetime
from dr_source.api import Vulnerability
from typing import List


class ScanDatabase:
    def __init__(self, project_name):
        # Use default name if project_name is ".", "..", or empty.
        if project_name in {".", "..", ""}:
            project_name = "default_project"
        self.project_name = self._sanitize_project_name(project_name)
        self.db_directory = os.path.join(
            os.path.expanduser("~"), "dr_source", "scans", "dbs"
        )
        self.db_path = os.path.join(
            f"{self.db_directory}",
            f"{self.project_name}.db",
        )
        os.makedirs(self.db_directory, exist_ok=True)
        self._create_tables()

    def _sanitize_project_name(self, name):
        """Sanitize the project name to be safe for file system usage."""
        return re.sub(r"[^\w\-_]", "_", name)

    def _create_tables(self):
        """Creates the 'scans' and 'vulnerabilities' tables if they do not exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                num_vulnerabilities INTEGER DEFAULT 0,
                num_files_analyzed INTEGER DEFAULT 0,
                scan_duration REAL DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                file TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                details TEXT,
                line INTEGER,
                severity TEXT,
                plugin_name TEXT,
                trace TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
        """)
        conn.commit()
        conn.close()

    def initialize(self):
        """
        Drops the existing tables and recreates them from scratch.
        Use this method when the database schema needs to be updated.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS vulnerabilities")
        cursor.execute("DROP TABLE IF EXISTS scans")
        conn.commit()
        conn.close()
        self._create_tables()

    def start_scan(self):
        """Inserts a new scan record and returns its scan_id."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()
        cursor.execute("INSERT INTO scans (timestamp) VALUES (?)", (timestamp,))
        conn.commit()
        scan_id = cursor.lastrowid
        conn.close()
        return scan_id

    def store_vulnerability(self, scan_id, vuln):
        """
        Stores a single vulnerability record.
        'vuln' is a dictionary with keys: 'file', 'vuln_type', 'match', and 'line'.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO vulnerabilities (scan_id, file, vuln_type, details, line)
                VALUES (?, ?, ?, ?, ?)
            """,
                (scan_id, vuln["file"], vuln["vuln_type"], vuln["match"], vuln["line"]),
            )
            conn.commit()
        except sqlite3.OperationalError as e:
            if "no such column: details" in str(e):
                raise sqlite3.OperationalError(
                    "Database schema outdated: 'vulnerabilities' table is missing column 'details'. "
                    "Please reinitialize the database using the --init-db option."
                ) from e
            else:
                raise
        finally:
            conn.close()

    def store_vulnerabilities(self, scan_id, vulns):
        """
        Stores multiple vulnerability records in a single transaction.
        'vulns' is a list of dictionaries with keys: 'file', 'vuln_type', 'match', and 'line'.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            data = [
                (
                    scan_id,
                    vuln.get("file"),
                    vuln.get("vuln_type"),
                    vuln.get("match"),
                    vuln.get("line"),
                    vuln.get("severity"),
                    vuln.get("plugin_name"),
                    vuln.get("trace"),
                )
                for vuln in vulns
            ]
            cursor.executemany(
                """
                INSERT INTO vulnerabilities (
                    scan_id, file, vuln_type, details, line,
                    severity, plugin_name, trace
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                data,
            )
            conn.commit()
        except sqlite3.OperationalError as e:
            if "no such column: details" in str(e):
                raise sqlite3.OperationalError(
                    "Database schema outdated: 'vulnerabilities' table is missing column 'details'. "
                    "Please reinitialize the database using the --init-db option."
                ) from e
            else:
                raise
        finally:
            conn.close()

    def update_scan_summary(
        self, scan_id, num_vulnerabilities, num_files_analyzed, scan_duration
    ):
        """Updates the scan record with summary information."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE scans
            SET num_vulnerabilities = ?, num_files_analyzed = ?, scan_duration = ?
            WHERE id = ?
        """,
            (num_vulnerabilities, num_files_analyzed, scan_duration, scan_id),
        )
        conn.commit()
        conn.close()

    def get_scan_history(self):
        """Returns a list of scan records (id, timestamp, num_vulnerabilities) ordered by most recent."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, timestamp, num_vulnerabilities FROM scans ORDER BY id DESC"
        )
        records = cursor.fetchall()
        conn.close()
        return records

    def get_latest_scan_id(self):
        """Returns the id of the latest scan record, or None if no scans exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
        record = cursor.fetchone()
        conn.close()
        return record[0] if record else None

    def compare_scans(self, old_scan_id, new_scan_id):
        """
        Compares two scans and returns a dictionary with keys 'new', 'resolved', and 'persistent' vulnerabilities.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT file, vuln_type, details, line FROM vulnerabilities WHERE scan_id=?
        """,
            (old_scan_id,),
        )
        old_vulns = set(cursor.fetchall())
        cursor.execute(
            """
            SELECT file, vuln_type, details, line FROM vulnerabilities WHERE scan_id=?
        """,
            (new_scan_id,),
        )
        new_vulns = set(cursor.fetchall())
        conn.close()
        new_issues = new_vulns - old_vulns
        resolved_issues = old_vulns - new_vulns
        persistent_issues = new_vulns & old_vulns
        return {
            "new": list(new_issues),
            "resolved": list(resolved_issues),
            "persistent": list(persistent_issues),
        }

    def get_vulnerabilities_for_scan(self, scan_id: int) -> List[dict]:
        """
        Fetches all vulnerabilities for a given scan_id and returns
        them as a list of dictionaries.
        """
        conn = sqlite3.connect(self.db_path)
        # Make the connection return rows as dictionaries
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT file, vuln_type, details AS match, line, severity, plugin_name, trace
            FROM vulnerabilities WHERE scan_id=?
            """,
            (scan_id,),
        )
        records = cursor.fetchall()
        conn.close()

        # Convert sqlite3.Row objects to standard dicts
        # and re-split the trace string into a list
        results = []
        for row in records:
            res_dict = dict(row)
            res_dict["trace"] = (
                res_dict.get("trace", "").split(" -> ") if res_dict.get("trace") else []
            )
            results.append(res_dict)

        return results
