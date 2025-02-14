import pytest
from dr_source.core.codebase import FileObject

from dr_source.core.detectors.sql_injection import SQLInjectionDetector
from dr_source.core.detectors.xss import XSSDetector
from dr_source.core.detectors.path_traversal import PathTraversalDetector
from dr_source.core.detectors.command_injection import CommandInjectionDetector
from dr_source.core.detectors.serialization import SerializationDetector

from dr_source.core.detectors.ldap_injection import LDAPInjectionDetector
from dr_source.core.detectors.xxe import XXEDetector
from dr_source.core.detectors.ssrf import SSRFDetector
from dr_source.core.detectors.crypto import CryptoDetector

# Sample content for tests:
SQLI_SAMPLE = 'String query = "SELECT * FROM users WHERE name = \'" + request.getParameter("username") + "\'";'
XSS_SAMPLE = '<script>alert(request.getParameter("msg"));</script>'
PATH_SAMPLE = 'File file = new File(request.getParameter("filename"));'
CMD_SAMPLE = 'Runtime.getRuntime().exec(request.getParameter("cmd"));'
SERIAL_SAMPLE = "Object obj = new ObjectInputStream(in).readObject("


def test_sql_injection_detector():
    file_obj = FileObject("TestSQL.java", SQLI_SAMPLE)
    detector = SQLInjectionDetector()
    results = detector.detect(file_obj)
    assert results, "SQL Injection detector should flag vulnerability"
    for result in results:
        assert "SQL Injection" in result["vuln_type"]
        assert result["line"] > 0


def test_xss_detector():
    file_obj = FileObject("TestXSS.jsp", XSS_SAMPLE)
    detector = XSSDetector()
    results = detector.detect(file_obj)
    # Expect to detect vulnerability only if unsanitized input is used.
    assert results, "XSS detector should flag vulnerability"
    for result in results:
        assert "XSS" in result["vuln_type"]
        assert result["line"] > 0


def test_path_traversal_detector():
    file_obj = FileObject("TestPath.java", PATH_SAMPLE)
    detector = PathTraversalDetector()
    results = detector.detect(file_obj)
    assert results, "Path Traversal detector should flag vulnerability"
    for result in results:
        assert "Path Traversal" in result["vuln_type"]
        assert result["line"] > 0


def test_command_injection_detector():
    file_obj = FileObject("TestCMD.java", CMD_SAMPLE)
    detector = CommandInjectionDetector()
    results = detector.detect(file_obj)
    assert results, "Command Injection detector should flag vulnerability"
    for result in results:
        assert "Command Injection" in result["vuln_type"]
        assert result["line"] > 0


def test_serialization_detector():
    file_obj = FileObject("TestSerialization.java", SERIAL_SAMPLE)
    detector = SerializationDetector()
    results = detector.detect(file_obj)
    assert results, "Serialization detector should flag vulnerability"
    for result in results:
        assert "Serialization Issues" in result["vuln_type"]
        assert result["line"] > 0


def test_ldap_injection_detector():
    sample = 'String url = "ldap://example.com/" + request.getParameter("username");'
    file_obj = FileObject("TestLDAP.java", sample)
    detector = LDAPInjectionDetector()
    results = detector.detect(file_obj)
    assert results, "LDAP Injection vulnerability should be detected"
    for res in results:
        assert "LDAP Injection" in res["vuln_type"]
        assert res["line"] > 0


def test_xxe_detector():
    sample = '<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://example.com/evil.xml"> ]>\n<foo>&xxe;</foo>'
    file_obj = FileObject("TestXXE.xml", sample)
    detector = XXEDetector()
    results = detector.detect(file_obj)
    assert results, "XXE vulnerability should be detected"
    for res in results:
        assert "XXE" in res["vuln_type"]
        assert res["line"] > 0


def test_ssrf_detector():
    sample = 'URL url = new URL("http://" + request.getParameter("host"));'
    file_obj = FileObject("TestSSRF.java", sample)
    detector = SSRFDetector()
    results = detector.detect(file_obj)
    assert results, "SSRF vulnerability should be detected"
    for res in results:
        assert "SSRF" in res["vuln_type"]
        assert res["line"] > 0


def test_crypto_detector_md5():
    sample = 'MessageDigest md = MessageDigest.getInstance("MD5");'
    file_obj = FileObject("TestCrypto.java", sample)
    detector = CryptoDetector()
    results = detector.detect(file_obj)
    assert results, "Crypto detector should flag MD5 usage"
    for res in results:
        assert "Unsafe Crypto/Hashing" in res["vuln_type"]
        assert res["line"] > 0


def test_crypto_detector_sha1():
    sample = 'MessageDigest md = MessageDigest.getInstance("SHA-1");'
    file_obj = FileObject("TestCrypto.java", sample)
    detector = CryptoDetector()
    results = detector.detect(file_obj)
    assert results, "Crypto detector should flag SHA-1 usage"
    for res in results:
        assert "Unsafe Crypto/Hashing" in res["vuln_type"]


def test_crypto_detector_cipher():
    sample = 'Cipher c = Cipher.getInstance("DES");'
    file_obj = FileObject("TestCrypto.java", sample)
    detector = CryptoDetector()
    results = detector.detect(file_obj)
    assert results, "Crypto detector should flag DES usage"
    for res in results:
        assert "Unsafe Crypto/Hashing" in res["vuln_type"]


def test_crypto_detector_no_issue():
    # Use a secure algorithm that should not be flagged (e.g., SHA-256)
    sample = 'MessageDigest md = MessageDigest.getInstance("SHA-256");'
    file_obj = FileObject("TestCrypto.java", sample)
    detector = CryptoDetector()
    results = detector.detect(file_obj)
    assert not results, "Crypto detector should not flag secure algorithms"
