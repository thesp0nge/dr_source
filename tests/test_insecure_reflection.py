import pytest
from dr_source.core.codebase import FileObject
from dr_source.core.detectors.insecure_reflection import InsecureReflectionDetector


def test_insecure_reflection_detector_regex():
    sample = (
        "public class Test {\n"
        "  public void test() {\n"
        '    Class cls = Class.forName(request.getParameter("className"));\n'
        "  }\n"
        "}"
    )
    file_obj = FileObject("TestReflection.java", sample)
    detector = InsecureReflectionDetector()
    results = detector.detect(file_obj)
    assert results, "Insecure Reflection detector should flag vulnerability"
    for res in results:
        assert "Insecure Reflection" in res["vuln_type"]
        assert res["line"] > 0
