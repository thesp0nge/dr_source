import os
import tempfile
import sqlite3
from dr_source.core.db import ScanDatabase


def test_database_initialization_and_store():
    # Create a temporary directory for the database
    with tempfile.TemporaryDirectory() as tmpdirname:
        project_name = "test_project"
        db_path = os.path.join(tmpdirname, f"{project_name}.db")
        # Create our ScanDatabase instance pointing to the temporary db
        db = ScanDatabase(project_name)
        db.db_path = db_path  # override path to use temp directory
        db.initialize()  # recreate tables

        scan_id = db.start_scan()
        assert isinstance(scan_id, int) and scan_id > 0

        # Create a dummy vulnerability record
        vuln = {
            "file": "Test.java",
            "vuln_type": "SQL Injection",
            "match": "dummy match",
            "line": 10,
        }
        db.store_vulnerability(scan_id, vuln)
        db.update_scan_summary(scan_id, 1, 1, 0.1)

        # Verify that the vulnerability was stored
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id=?", (scan_id,)
        )
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 1


def test_store_vulnerabilities_batch():
    with tempfile.TemporaryDirectory() as tmpdirname:
        project_name = "test_project"
        db_path = os.path.join(tmpdirname, f"{project_name}.db")
        db = ScanDatabase(project_name)
        db.db_path = db_path
        db.initialize()

        scan_id = db.start_scan()
        vulns = [
            {"file": "Test1.java", "vuln_type": "XSS", "match": "dummy1", "line": 5},
            {"file": "Test2.java", "vuln_type": "XSS", "match": "dummy2", "line": 15},
        ]
        db.store_vulnerabilities(scan_id, vulns)
        db.update_scan_summary(scan_id, len(vulns), 2, 0.2)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id=?", (scan_id,)
        )
        count = cursor.fetchone()[0]
        conn.close()
        assert count == len(vulns)
