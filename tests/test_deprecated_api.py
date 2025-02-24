import pytest
from dr_source.core.codebase import FileObject
from dr_source.core.detectors.deprecated_api import DeprecatedAPIDetector


def test_deprecated_api_detector_regex():
    sample = (
        "public class Test {\n"
        "  public void test() {\n"
        "    Thread.stop();\n"
        "    Thread.suspend();\n"
        "    Thread.resume();\n"
        "    System.runFinalizersOnExit(true);\n"
        "    Runtime.runFinalizersOnExit(true);\n"
        "  }\n"
        "}"
    )
    file_obj = FileObject("TestDeprecated.java", sample)
    detector = DeprecatedAPIDetector()
    results = detector.detect(file_obj)
    assert results, "Deprecated API detector should flag vulnerabilities"
    types = {res["vuln_type"] for res in results}
    assert any("Deprecated API" in vt for vt in types)
