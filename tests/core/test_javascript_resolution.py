"""Structured JavaScript project-call resolution outcomes."""

from dr_source.core.project_index import ProjectIndex
from dr_source.core.resolution import ResolutionReason, ResolutionStatus
from dr_source.plugins.javascript.taint_visitor import JavaScriptTaintVisitor


def _visitor(index):
    return JavaScriptTaintVisitor(set(), [], set(), b"", project_index=index)


def test_javascript_unique_project_function_is_resolved_and_retrievable():
    index = ProjectIndex()
    node = object()
    index.register_function("runCommand", "commands.js", node, "javascript")

    result = _visitor(index)._resolve_project_call("runCommand")

    assert result.status is ResolutionStatus.RESOLVED
    assert result.reason is ResolutionReason.NONE
    assert result.symbol is not None
    assert index.get_definition(result.symbol).node is node


def test_javascript_missing_project_function_is_unresolved():
    result = _visitor(ProjectIndex())._resolve_project_call("runCommand")

    assert result.status is ResolutionStatus.UNRESOLVED
    assert result.reason is ResolutionReason.NO_CANDIDATES
    assert result.symbol is None
    assert result.candidates == ()


def test_javascript_ambiguity_is_deterministic_and_preserves_candidates():
    registrations = [("commands_b.js", object()), ("commands_a.js", object())]
    indexes = [ProjectIndex(), ProjectIndex()]
    for index, entries in zip(indexes, (registrations, reversed(registrations))):
        for path, node in entries:
            index.register_function("runCommand", path, node, "javascript")

    results = [_visitor(index)._resolve_project_call("runCommand") for index in indexes]

    assert all(result.status is ResolutionStatus.AMBIGUOUS for result in results)
    assert all(result.reason is ResolutionReason.MULTIPLE_CANDIDATES for result in results)
    assert all(result.symbol is None for result in results)
    assert results[0].candidates == results[1].candidates
    assert [symbol.file_path for symbol in results[0].candidates] == [
        "commands_a.js", "commands_b.js"
    ]


def test_javascript_resolution_ignores_foreign_language_candidates():
    index = ProjectIndex()
    js_node = object()
    index.register_function("runCommand", "commands.js", js_node, "javascript")
    index.register_function("runCommand", "commands.py", object(), "python")
    index.register_function("runCommand", "commands.java", object(), "java")

    result = _visitor(index)._resolve_project_call("runCommand")

    assert result.status is ResolutionStatus.RESOLVED
    assert result.symbol is not None
    assert result.symbol.language == "javascript"
    assert index.get_definition(result.symbol).node is js_node


def test_javascript_dotted_name_remains_exact_lookup():
    index = ProjectIndex()
    index.register_function("execute", "commands.js", object(), "javascript")

    result = _visitor(index)._resolve_project_call("service.execute")

    assert result.status is ResolutionStatus.UNRESOLVED
    assert result.reason is ResolutionReason.NO_CANDIDATES
