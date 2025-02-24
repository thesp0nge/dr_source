import pytest
from dr_source.core.codebase import FileObject
from dr_source.core.detectors.information_disclosure import (
    InformationDisclosureDetector,
)


def test_information_disclosure_detector_regex():
    sample = (
        "public class Test {\n"
        "  public void test() {\n"
        "    try {\n"
        "      // some code\n"
        "    } catch(Exception e) {\n"
        "      e.printStackTrace();\n"
        "      System.out.println(e);\n"
        "    }\n"
        "  }\n"
        "}"
    )
    file_obj = FileObject("TestInfoDisclosure.java", sample)
    detector = InformationDisclosureDetector()
    results = detector.detect(file_obj)
    assert results, "Information Disclosure detector should flag vulnerability"
    for res in results:
        assert "Information Disclosure" in res["vuln_type"]
        assert res["line"] > 0
