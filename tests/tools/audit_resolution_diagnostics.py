"""Investigation-only fixture audit; no production reporting or classification.

Run from the repository root:
    PYTHONPATH=. python tests/tools/audit_resolution_diagnostics.py > /tmp/resolution-audit.json

Each fixture subtree is an independent project. Only its real language analyzer
is loaded; factory security knowledge and the Scanner lifecycle are unchanged.
User/project rule overlays are excluded to make the audit reproducible.
The database boundary is mocked to avoid persistent history writes. No fixture
program or dependency/network analyzer is executed.
"""

import json
import hashlib
import importlib.metadata
import sys
import logging
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from dr_source.core.scanner import Scanner
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from dr_source.plugins.java.plugin import JavaAstAnalyzer
from dr_source.plugins.javascript.plugin import JavaScriptAstAnalyzer
from dr_source.plugins.python.plugin import PythonAstAnalyzer

ROOT = Path(__file__).resolve().parents[2]
ANALYZERS = {"python": PythonAstAnalyzer, "java": JavaAstAnalyzer,
             "javascript": JavaScriptAstAnalyzer}


class AuditLogs(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = []

    def emit(self, record):
        self.messages.append({"level": record.levelname, "message": record.getMessage()})


def relative(path):
    return str(Path(path).relative_to(ROOT)) if path else None


def audit_tree(language, target):
    analyzer_class = ANALYZERS[language]
    entry = SimpleNamespace(name=language, load=lambda: analyzer_class)
    logs = AuditLogs()
    logger = logging.getLogger("dr_source")
    logger.addHandler(logs)
    try:
        factory_rules = ROOT / "dr_source" / "config" / "knowledge_base.yaml"
        with patch("importlib.metadata.entry_points", return_value=[entry]), \
                patch("dr_source.core.scanner.ScanDatabase", MagicMock()), \
                patch.object(KnowledgeBaseLoader, "_get_default_search_paths",
                             return_value=[str(factory_rules)]):
            scanner = Scanner(str(target))
            scanner.scan()
    finally:
        logger.removeHandler(logs)
    plugin = next(iter(scanner.extension_map.values()))[0]
    events = []
    for event in scanner.diagnostics.resolution_events():
        row = {
            "language": event.language, "file": relative(event.file_path),
            "line": event.line, "column": event.column, "call_name": event.call_name,
            "status": event.status.value, "reason": event.reason.value,
            "candidate_count": len(event.candidates),
            "candidates": [{"file": relative(candidate.file_path), "name": candidate.name,
                            "position": candidate.declaration_position} for candidate in event.candidates],
            "source_line": Path(event.file_path).read_text(encoding="utf-8").splitlines()[event.line - 1],
        }
        if language == "python":
            file, name, explicit = plugin.python_context.resolve_binding(event.file_path, event.call_name)
            binding = plugin.python_context.binding(event.file_path, event.call_name.split(".")[0])
            row["binding"] = {
                "explicit": explicit, "target_file": relative(file), "target_name": name,
                "module": binding.module_name if binding else None,
                "supported": binding.supported if binding else None,
            }
        events.append(row)
    summary = scanner.diagnostics.summary()
    assert summary.total_project_resolution_sites == sum((summary.resolved, summary.unresolved,
                                                        summary.ambiguous, summary.unsupported))
    return {
        "root": relative(target), "language": language,
        "files_analyzed": scanner.num_files_analyzed,
        "findings": len(scanner.all_findings),
        "summary": summary.__dict__, "logs": logs.messages, "events": events,
    }


def main():
    scans = [audit_tree(language, ROOT / "tests" / "test_code" / subtree / language)
             for language in ANALYZERS for subtree in ("", "inter_file")]
    counts = Counter((event["language"], event["status"], event["reason"], event["call_name"])
                     for scan in scans for event in scan["events"])
    aggregates = [{"language": language, "status": status, "reason": reason,
                   "call_name": name, "sites": count}
                  for (language, status, reason, name), count in sorted(counts.items())]
    metadata = {
        "python": sys.version.split()[0],
        "versions": {name: importlib.metadata.version(name) for name in (
            "dr_source", "tree-sitter", "tree-sitter-java", "tree-sitter-javascript", "pyyaml")},
        "knowledge_base_sha256": hashlib.sha256(
            (ROOT / "dr_source" / "config" / "knowledge_base.yaml").read_bytes()).hexdigest(),
        "knowledge_base": "factory only; user/project overlays excluded",
    }
    print(json.dumps({"metadata": metadata, "scans": scans, "aggregates": aggregates},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
