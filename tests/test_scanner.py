import os
import tempfile
from dr_source.core.codebase import Codebase, FileObject
from dr_source.core.scanner import Scanner


def test_scanner_integration():
    # Create temporary test files in memory
    file1 = FileObject(
        "Test1.java",
        'String query = "SELECT * FROM users WHERE name = \'" + request.getParameter("username") + "\'";',
    )
    file2 = FileObject(
        "Test2.jsp", '<script>alert(request.getParameter("msg"));</script>'
    )
    codebase = Codebase("/dummy/path")
    codebase.files = [file1, file2]

    scanner = Scanner(codebase)
    results = scanner.scan()
    # We expect at least one vulnerability from each detector type.
    vuln_types = {result["vuln_type"] for result in results}
    assert "SQL Injection (regex)" in vuln_types
    assert "XSS" in vuln_types
