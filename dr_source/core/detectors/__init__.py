# dr_source/core/detectors/__init__.py
from dr_source.core.detectors.sql_injection import SQLInjectionDetector
from dr_source.core.detectors.xss import XSSDetector
from dr_source.core.detectors.path_traversal import PathTraversalDetector
from dr_source.core.detectors.command_injection import CommandInjectionDetector
from dr_source.core.detectors.serialization import SerializationDetector
from dr_source.core.detectors.ldap_injection import LDAPInjectionDetector
from dr_source.core.detectors.xxe import XXEDetector
from dr_source.core.detectors.ssrf import SSRFDetector
from dr_source.core.detectors.crypto import CryptoDetector
from dr_source.core.detectors.open_redirect import OpenRedirectDetector
from dr_source.core.detectors.insecure_cookie import InsecureCookieDetector
from dr_source.core.detectors.insecure_reflection import InsecureReflectionDetector
from dr_source.core.detectors.file_inclusion import FileInclusionDetector
from dr_source.core.detectors.hardcoded_credentials import HardcodedCredentialsDetector
from dr_source.core.detectors.deprecated_api import DeprecatedAPIDetector
from dr_source.core.detectors.jndi_injection import JNDIInjectionDetector
from dr_source.core.detectors.session_fixation import SessionFixationDetector
from dr_source.core.detectors.information_disclosure import (
    InformationDisclosureDetector,
)

DETECTORS = [
    SQLInjectionDetector,
    XSSDetector,
    PathTraversalDetector,
    CommandInjectionDetector,
    SerializationDetector,
    LDAPInjectionDetector,
    XXEDetector,
    SSRFDetector,
    CryptoDetector,
    OpenRedirectDetector,
    InsecureCookieDetector,
    InsecureReflectionDetector,
    FileInclusionDetector,
    HardcodedCredentialsDetector,
    DeprecatedAPIDetector,
    JNDIInjectionDetector,
    SessionFixationDetector,
    InformationDisclosureDetector,
]
