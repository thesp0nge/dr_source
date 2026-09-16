"""Structured ProjectIndex resolution outcomes."""

from dr_source.core.project_index import ProjectIndex
from dr_source.core.resolution import Resolution, ResolutionReason, ResolutionStatus


def _register(index, name, path, language="python"):
    node = object()
    index.register_function(name, path, node, language)
    return node


def test_resolve_unique_reports_no_candidates():
    result = ProjectIndex().resolve_unique("execute", language="python")

    assert result.status is ResolutionStatus.UNRESOLVED
    assert result.symbol is None
    assert result.candidates == ()
    assert result.reason is ResolutionReason.NO_CANDIDATES


def test_resolve_unique_reports_single_symbol_and_definition_is_retrievable():
    index = ProjectIndex()
    node = _register(index, "execute", "service.py")

    result = index.resolve_unique("execute", language="python")

    assert result.status is ResolutionStatus.RESOLVED
    assert result.symbol is not None
    assert result.candidates == (result.symbol,)
    assert result.reason is ResolutionReason.NONE
    assert index.get_definition(result.symbol).node is node


def test_resolve_unique_preserves_deterministic_ambiguity():
    registrations = [("service_b.py", object()), ("service_a.py", object())]
    indexes = [ProjectIndex(), ProjectIndex()]
    for index, entries in zip(indexes, (registrations, reversed(registrations))):
        for path, node in entries:
            index.register_function("execute", path, node, "python")

    results = [index.resolve_unique("execute", language="python") for index in indexes]

    assert all(result.status is ResolutionStatus.AMBIGUOUS for result in results)
    assert all(result.symbol is None for result in results)
    assert all(result.reason is ResolutionReason.MULTIPLE_CANDIDATES for result in results)
    assert results[0].candidates == results[1].candidates
    assert [symbol.file_path for symbol in results[0].candidates] == [
        "service_a.py",
        "service_b.py",
    ]


def test_resolve_unique_scopes_candidates_by_language():
    index = ProjectIndex()
    python_node = _register(index, "execute", "service.py", "python")
    _register(index, "execute", "service.js", "javascript")

    result = index.resolve_unique("execute", language="python")

    assert result.status is ResolutionStatus.RESOLVED
    assert index.get_definition(result.symbol).node is python_node


def test_unsupported_resolution_has_structured_reason():
    result = Resolution.unsupported(ResolutionReason.UNSUPPORTED_BINDING)

    assert result.status is ResolutionStatus.UNSUPPORTED
    assert result.symbol is None
    assert result.candidates == ()
    assert result.reason is ResolutionReason.UNSUPPORTED_BINDING


def test_find_function_remains_legacy_unique_only_adapter(caplog):
    index = ProjectIndex()
    node = _register(index, "execute", "service.py")
    assert index.find_function("execute", language="python").node is node

    assert index.find_function("missing", language="python") is None
    _register(index, "execute", "other.py")
    assert index.find_function("execute", language="python") is None
