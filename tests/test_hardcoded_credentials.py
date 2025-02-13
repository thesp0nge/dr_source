import pytest
from dr_source.core.codebase import FileObject
from dr_source.core.detectors.hardcoded_credentials import HardcodedCredentialsDetector


def test_hardcoded_credentials_detector():
    test_content = """
    password = "supersecret"
    api_key = "1234567890abcdef"
    aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
    """

    file_obj = FileObject("test_file.py", test_content)
    detector = HardcodedCredentialsDetector()
    results = detector.detect(file_obj)

    assert results, "Hardcode credential"
    for result in results:
        assert "Hardcode credential" in result["vuln_type"]
        assert result["line"] > 0
