import pytest
from dr_source.core.codebase import FileObject
from dr_source.core.detectors.insecure_cookie import InsecureCookieDetector


def test_insecure_cookie_detector_regex():
    sample = (
        'Cookie cookie = new Cookie("session", "abc123");\n'
        "cookie.setSecure(false);\n"
        "cookie.setHttpOnly(false);\n"
    )
    file_obj = FileObject("TestCookie.java", sample)
    detector = InsecureCookieDetector()
    results = detector.detect(file_obj)
    assert results, "Insecure Cookie detector should flag vulnerabilities"
    types = {res["vuln_type"] for res in results}
    assert "Insecure Cookie (setSecure)" in types
    assert "Insecure Cookie (setHttpOnly)" in types
