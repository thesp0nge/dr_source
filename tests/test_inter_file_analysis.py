import unittest
import os
import logging
from dr_source.core.scanner import Scanner
from dr_source.logging import setup_logging

class TestInterFileAnalysis(unittest.TestCase):
    def setUp(self):
        setup_logging(debug=True)
        self.base_dir = os.path.join(os.path.dirname(__file__), "test_code", "inter_file")

    def test_python_inter_file_flow(self):
        target = os.path.join(self.base_dir, "python")
        scanner = Scanner(target)
        scanner.scan()
        
        findings = [f for f in scanner.all_findings if "vulnerable_execute" in f.message or "os.system" in f.message]
        self.assertGreater(len(findings), 0, "Failed to detect cross-file Python vulnerability")
        
        vuln = findings[0]
        has_cross_file_trace = any("in inter_file_utils.py" in step for step in vuln.trace)
        self.assertTrue(has_cross_file_trace, f"Trace missing cross-file info: {vuln.trace}")

    def test_java_inter_file_flow(self):
        target = os.path.join(self.base_dir, "java")
        scanner = Scanner(target)
        scanner.scan()
        
        findings = [f for f in scanner.all_findings if "runQuery" in f.message or "executeQuery" in f.message]
        self.assertGreater(len(findings), 0, "Failed to detect cross-file Java vulnerability")
        
        vuln = findings[0]
        has_cross_file_trace = any("in DatabaseHelper.java" in step for step in vuln.trace)
        self.assertTrue(has_cross_file_trace, f"Trace missing cross-file info: {vuln.trace}")

    def test_javascript_inter_file_flow(self):
        target = os.path.join(self.base_dir, "javascript")
        scanner = Scanner(target)
        scanner.scan()
        
        findings = [f for f in scanner.all_findings if "runCommand" in f.message or "exec" in f.message]
        self.assertGreater(len(findings), 0, "Failed to detect cross-file JavaScript vulnerability")
        
        vuln = findings[0]
        has_cross_file_trace = any("in db.js" in step for step in vuln.trace)
        self.assertTrue(has_cross_file_trace, f"Trace missing cross-file info: {vuln.trace}")

if __name__ == "__main__":
    unittest.main()
