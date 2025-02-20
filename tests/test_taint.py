import pytest
import javalang
from dr_source.core.taint_visitor import TaintVisitor


def test_taint_propagation():
    sample = (
        "public class Test {\n"
        "  public void test() {\n"
        '    String username = request.getParameter("username");\n'
        '    String query = "SELECT * FROM users WHERE name = \'" + username + "\'";\n'
        "    stmt.executeQuery(query);\n"
        "  }\n"
        "}"
    )
    tree = javalang.parse.parse(sample)
    visitor = TaintVisitor()
    visitor.visit(tree)
    vulns = visitor.get_vulnerabilities(tree, ["executeQuery"])
    assert any(
        v["sink"] == "executeQuery" for v in vulns
    ), "Taint propagation should detect vulnerability"
