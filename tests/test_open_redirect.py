import pytest
from dr_source.core.codebase import FileObject
from dr_source.core.detectors.open_redirect import OpenRedirectDetector


def test_open_redirect_detector_regex():
    sample = (
        "public class Test {\n"
        "  public void test() {\n"
        '    response.sendRedirect(request.getParameter("url"));\n'
        "  }\n"
        "}"
    )
    file_obj = FileObject("TestRedirect.jsp", sample)
    detector = OpenRedirectDetector()
    results = detector.detect(file_obj)
    assert results, "Open Redirect detector should flag vulnerability"
    for res in results:
        assert "Open Redirect" in res["vuln_type"]
        assert res["line"] > 0
