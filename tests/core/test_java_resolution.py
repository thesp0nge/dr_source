"""Structured Java project-call resolution outcomes."""

from dr_source.core.project_index import ProjectIndex
from dr_source.core.resolution import ResolutionReason, ResolutionStatus
from dr_source.plugins.java.taint_visitor import TaintVisitor


def _visitor(index):
    return TaintVisitor([], [], [], b"", project_index=index)


def test_java_unique_project_method_is_resolved_and_retrievable():
    index = ProjectIndex()
    node = object()
    index.register_function("runQuery", "DatabaseHelper.java", node, "java")

    result = _visitor(index)._resolve_project_call("runQuery")

    assert result.status is ResolutionStatus.RESOLVED
    assert result.reason is ResolutionReason.NONE
    assert result.symbol is not None
    assert index.get_definition(result.symbol).node is node


def test_java_missing_project_method_is_unresolved():
    result = _visitor(ProjectIndex())._resolve_project_call("runQuery")

    assert result.status is ResolutionStatus.UNRESOLVED
    assert result.reason is ResolutionReason.NO_CANDIDATES
    assert result.symbol is None
    assert result.candidates == ()


def test_java_ambiguous_project_methods_preserve_candidates_and_order():
    registrations = [("B.java", object()), ("A.java", object())]
    indexes = [ProjectIndex(), ProjectIndex()]
    for index, entries in zip(indexes, (registrations, reversed(registrations))):
        for path, node in entries:
            index.register_function("runQuery", path, node, "java")

    results = [_visitor(index)._resolve_project_call("runQuery") for index in indexes]

    assert all(result.status is ResolutionStatus.AMBIGUOUS for result in results)
    assert all(result.reason is ResolutionReason.MULTIPLE_CANDIDATES for result in results)
    assert all(result.symbol is None for result in results)
    assert results[0].candidates == results[1].candidates
    assert [symbol.file_path for symbol in results[0].candidates] == ["A.java", "B.java"]


def test_java_resolution_ignores_foreign_language_candidates():
    index = ProjectIndex()
    java_node = object()
    index.register_function("runQuery", "DatabaseHelper.java", java_node, "java")
    index.register_function("runQuery", "helper.py", object(), "python")
    index.register_function("runQuery", "helper.js", object(), "javascript")

    result = _visitor(index)._resolve_project_call("runQuery")

    assert result.status is ResolutionStatus.RESOLVED
    assert result.symbol is not None
    assert result.symbol.language == "java"
    assert index.get_definition(result.symbol).node is java_node
