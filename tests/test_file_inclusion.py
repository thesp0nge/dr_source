import pytest
from dr_source.core.codebase import FileObject
from dr_source.core.detectors.file_inclusion import FileInclusionDetector


def test_file_inclusion_detector_regex():
    sample = "<jsp:include page=\"<%= request.getParameter('page') %>\" />"
    file_obj = FileObject("TestInclusion.jsp", sample)
    detector = FileInclusionDetector()
    results = detector.detect(file_obj)
    assert results, "File Inclusion detector should flag vulnerability"
    for res in results:
        assert "File Inclusion" in res["vuln_type"]
        assert res["line"] > 0
