import pytest
import javalang
from dr_source.core.codebase import FileObject
from dr_source.core.detectors.sql_injection import SQLInjectionDetector


def test_sql_injection_ast_taint():
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
    tree = javalang.parse.parse(file_obj.content)
    detector = SQLInjectionDetector()
    results = detector.detect_ast_from_tree(file_obj, tree)
    assert results, "AST-based SQL Injection vulnerability should be flagged"
    for res in results:
        assert "SQL Injection" in res["vuln_type"]
        assert res["line"] > 0
