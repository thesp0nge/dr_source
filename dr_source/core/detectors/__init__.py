# dr_source/core/detectors/__init__.py
from dr_source.core.detectors.sql_injection import SQLInjectionDetector
from dr_source.core.detectors.xss import XSSDetector
from dr_source.core.detectors.path_traversal import PathTraversalDetector
from dr_source.core.detectors.command_injection import CommandInjectionDetector
from dr_source.core.detectors.serialization import SerializationDetector

DETECTORS = [
    SQLInjectionDetector,
    XSSDetector,
    PathTraversalDetector,
    CommandInjectionDetector,
    SerializationDetector,
]

__all__ = ["DETECTORS"]
