"""Explicit services shared throughout one scanner lifecycle."""

from dataclasses import dataclass

from dr_source.core.diagnostics import ScanDiagnostics
from dr_source.core.project_index import ProjectIndex


@dataclass(frozen=True)
class AnalysisContext:
    project_index: ProjectIndex
    project_root: str
    diagnostics: ScanDiagnostics
