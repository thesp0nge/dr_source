class ScanDatabase:
    # (Restante codice invariato)

    def get_vulnerabilities_by_scan(self, scan_id):
        """Restituisce un set con le vulnerabilità della scansione specificata."""
        result = self.cursor.execute(
            """
            SELECT file_path, vuln_type, source, sink FROM vulnerabilities WHERE scan_id=?
        """,
            (scan_id,),
        ).fetchall()
        return set(result)

    def compare_scans(self, old_scan_id, new_scan_id):
        """Confronta due scansioni e restituisce le vulnerabilità nuove, risolte e persistenti."""
        old_vulns = self.get_vulnerabilities_by_scan(old_scan_id)
        new_vulns = self.get_vulnerabilities_by_scan(new_scan_id)

        new_issues = new_vulns - old_vulns
        resolved_issues = old_vulns - new_vulns
        persistent_issues = new_vulns & old_vulns

        return {
            "new": list(new_issues),
            "resolved": list(resolved_issues),
            "persistent": list(persistent_issues),
        }

    def get_latest_scan_id(self):
        """Ottiene l'ID dell'ultima scansione registrata."""
        scan = self.cursor.execute(
            "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return scan[0] if scan else None

    def get_previous_scan_id(self):
        """Ottiene l'ID della scansione precedente all'ultima."""
        scans = self.cursor.execute(
            "SELECT id FROM scans ORDER BY id DESC LIMIT 2"
        ).fetchall()
        return scans[1][0] if len(scans) > 1 else None

