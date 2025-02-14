# tests/test_ast_scanner.py
import pytest
import javalang
from dr_source.core.codebase import FileObject
from dr_source.core.scanner import Scanner


def test_scanner_ast_mode():
    sample = (
        "public class Test {\n"
        "  public void test() {\n"
        '    String username = request.getParameter("username");\n'
        '    String query = "SELECT * FROM users WHERE name = \'" + username + "\'";\n'
        "    stmt.executeQuery(query);\n"
        "  }\n"
        "}"
    )
    file_obj = FileObject("TestSQL.java", sample)

    class DummyCodebase:
        def __init__(self, file_obj):
            self.files = [file_obj]

    codebase = DummyCodebase(file_obj)
    scanner = Scanner(codebase, ast_mode=True)
    results = scanner.scan()
    ast_results = [r for r in results if "SQL Injection (AST Taint)" in r["vuln_type"]]
    assert (
        ast_results
    ), "AST-based SQL Injection vulnerability should be flagged by the scanner"
