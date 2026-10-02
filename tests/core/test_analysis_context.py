from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import MagicMock
import os

import pytest

from dr_source.api import AnalyzerPlugin
from dr_source.core.scanner import Scanner


class PreparedAnalyzer(AnalyzerPlugin):
    name = "Prepared analyzer"

    def __init__(self):
        self.contexts = []
        self.phases = []

    def get_supported_extensions(self):
        return [".py", ".*"]

    def prepare(self, context):
        assert not self.phases
        self.contexts.append(context)

    def index(self, file_path, project_index):
        assert project_index is self.contexts[0].project_index
        self.phases.append(("index", self.contexts[0]))

    def analyze(self, file_path):
        self.phases.append(("analyze", self.contexts[0]))
        return []


def make_scanner(monkeypatch, target, classes):
    monkeypatch.setattr("dr_source.core.scanner.ScanDatabase", MagicMock())
    entries = [SimpleNamespace(name=str(i), load=lambda cls=cls: cls)
               for i, cls in enumerate(classes)]
    monkeypatch.setattr("importlib.metadata.entry_points", lambda **kwargs: entries)
    return Scanner(str(target))


def test_preparation_once_shared_context_before_all_files(monkeypatch, tmp_path):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("pass\n")
    scanner = make_scanner(monkeypatch, tmp_path / ".", [PreparedAnalyzer, PreparedAnalyzer])
    plugins = scanner.extension_map[".py"]
    scanner.scan()
    context = scanner.analysis_context
    assert context.project_index is scanner.project_index
    assert context.diagnostics is scanner.diagnostics
    assert context.project_root == scanner.project_root == os.path.normpath(str(tmp_path))
    for plugin in plugins:
        assert plugin.contexts == [context]
        assert [phase for phase, _ in plugin.phases] == ["index", "index", "analyze", "analyze"]
        assert all(received is context for _, received in plugin.phases)
    assert scanner.diagnostics.summary().total_project_resolution_sites == 0
    with pytest.raises(FrozenInstanceError):
        context.project_root = "other"
    scanner.scan()
    assert all(len(plugin.contexts) == 1 for plugin in plugins)
    other = make_scanner(monkeypatch, tmp_path, [PreparedAnalyzer])
    assert other.project_index is not scanner.project_index
    assert other.diagnostics is not scanner.diagnostics
    assert other.analysis_context is not context


def test_default_prepare_legacy_adapter_and_file_root(monkeypatch, tmp_path):
    class LegacyAnalyzer(PreparedAnalyzer):
        prepare = AnalyzerPlugin.prepare

        def __init__(self):
            self.project_index = None

        def index(self, file_path, project_index):
            assert self.project_index is project_index

        def analyze(self, file_path):
            assert self.project_index is scanner.project_index
            return []

    source = tmp_path / "app.py"
    source.write_text("pass\n")
    scanner = make_scanner(monkeypatch, source, [LegacyAnalyzer])
    scanner.scan()
    assert scanner.project_root == str(tmp_path)


def test_builtins_receive_context_and_ordinary_scan_has_no_events(monkeypatch, tmp_path):
    from dr_source.plugins.python.plugin import PythonAstAnalyzer
    from dr_source.plugins.java.plugin import JavaAstAnalyzer
    from dr_source.plugins.javascript.plugin import JavaScriptAstAnalyzer
    from dr_source.plugins.regex.plugin import RegexAnalyzer
    from dr_source.plugins.dependency.plugin import DependencyAnalyzer
    from dr_source.plugins.pattern.plugin import PatternAnalyzer
    from dr_source.plugins.php.plugin import PHPAstAnalyzer
    from dr_source.plugins.ruby.plugin import RubyAstAnalyzer

    classes = [PythonAstAnalyzer, JavaAstAnalyzer, JavaScriptAstAnalyzer,
               RegexAnalyzer, DependencyAnalyzer, PatternAnalyzer, PHPAstAnalyzer, RubyAstAnalyzer]
    calls = []
    for cls in classes:
        original = cls.prepare
        def prepare(self, context, original=original):
            calls.append((self, context))
            original(self, context)
        monkeypatch.setattr(cls, "prepare", prepare)
    (tmp_path / "app.py").write_text("def helper():\n    return 1\nhelper()\n")
    scanner = make_scanner(monkeypatch, tmp_path, classes)
    scanner.scan()
    assert len(calls) == len(classes)
    assert all(context is scanner.analysis_context for _, context in calls)
    for plugin, _ in calls:
        if isinstance(plugin, (RegexAnalyzer, DependencyAnalyzer, PatternAnalyzer)):
            continue
        assert plugin.analysis_context is scanner.analysis_context
        assert not hasattr(plugin, "project_index")
    assert scanner.diagnostics.resolution_events() == ()
    assert scanner.diagnostics.summary().total_project_resolution_sites == 0


def test_preparation_failure_stops_before_indexing(monkeypatch, tmp_path):
    class FailingAnalyzer(PreparedAnalyzer):
        def prepare(self, context):
            raise RuntimeError("preparation failed")

    (tmp_path / "app.py").write_text("pass\n")
    scanner = make_scanner(monkeypatch, tmp_path, [FailingAnalyzer])
    plugin = scanner.extension_map[".py"][0]
    with pytest.raises(RuntimeError, match="preparation failed"):
        scanner.scan()
    assert plugin.phases == []
