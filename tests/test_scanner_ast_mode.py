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
        '    Class cls = Class.forName(request.getParameter("className"));\n'
        '    out.print(request.getParameter("input"));\n'
        "  }\n"
        "}"
    )
    file_obj = FileObject("TestAll.java", sample)

    class DummyCodebase:
        def __init__(self, file_obj):
            self.files = [file_obj]

    codebase = DummyCodebase(file_obj)
    scanner = Scanner(codebase, ast_mode=True)
    results = scanner.scan()
    vuln_types = {r["vuln_type"] for r in results}
    assert any(
        "SQL Injection" in vt for vt in vuln_types
    ), "SQL Injection vulnerability should be flagged"
    assert any(
        "Insecure Reflection" in vt for vt in vuln_types
    ), "Insecure Reflection vulnerability should be flagged"
