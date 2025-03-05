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

    assert results, "Hardcoded credentials should be flagged"
    for result in results:
        assert (
            "Hardcoded Credentials" in result["vuln_type"]
        ), f"Unexpected vuln_type: {result['vuln_type']}"
