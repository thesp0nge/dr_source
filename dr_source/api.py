# File: dr_source/api.py

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Literal

# Define standard severity levels
Severity = Literal["HIGH", "MEDIUM", "LOW", "INFO"]

# --- 1. The Standard Vulnerability Object ---


@dataclass
class Vulnerability:
    """
    A standardized dataclass to represent a single finding.
    All plugins *must* return a list of these objects.
    """

    # What was found?
    vulnerability_type: str  # e.g., "SQL_INJECTION", "RCE", "HARDCODED_SECRET"
    message: str  # e.g., "Taint flow from 'request.getParameter' to 'executeQuery'"
    severity: Severity  # "HIGH", "MEDIUM", "LOW", or "INFO"

    # Where was it found?
    file_path: str
    line_number: int

    # Who found it?
    plugin_name: str  # e.g., "Java AST Analyzer"

    trace: List[str] = field(default_factory=list)


# --- 2. The Analyzer Plugin "Contract" ---


class AnalyzerPlugin(ABC):
    """
    This is the Abstract Base Class (the "contract") for all analyzers.

    The Core Orchestrator will find all classes that implement this
    interface and will only interact with them using these methods.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        A user-friendly name for this plugin.
        Used for logging and in the Vulnerability object.

        Example: "Java AST Taint Analyzer"
        """
        pass

    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """
        Tells the orchestrator which files this plugin cares about.

        - [".java"] for a Java-only analyzer.
        - [".py", ".pyw"] for a Python analyzer.
        - [".*"] for a general-purpose plugin (like a secret scanner).
        """
        pass

    @abstractmethod
    def analyze(self, file_path: str) -> List[Vulnerability]:
        """
        The main analysis engine.

        The orchestrator will call this method for every file that
        matches the plugin's supported extensions.

        Args:
            file_path (str): The absolute path to the file to analyze.

        Returns:
            List[Vulnerability]: A list of 0 or more findings.
        """
        pass
