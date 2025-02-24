import pytest
from dr_source.core.codebase import FileObject
from dr_source.core.detectors.jndi_injection import JNDIInjectionDetector


def test_jndi_injection_detector_regex():
    sample = (
        "public class Test {\n"
        "  public void test() {\n"
        "    InitialContext ctx = new InitialContext();\n"
        '    Object obj = ctx.lookup(request.getParameter("jndiName"));\n'
        "  }\n"
        "}"
    )
    file_obj = FileObject("TestJNDI.java", sample)
    detector = JNDIInjectionDetector()
    results = detector.detect(file_obj)
    assert results, "JNDI Injection detector should flag vulnerability"
    for res in results:
        assert "JNDI Injection" in res["vuln_type"]
        assert res["line"] > 0
