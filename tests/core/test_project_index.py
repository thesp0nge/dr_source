"""Collision-safe storage and explicit legacy lookup ambiguity."""

from dataclasses import FrozenInstanceError
import logging

import pytest

from dr_source.core.project_index import ProjectIndex


@pytest.mark.parametrize(
    "second_file, second_language",
    [
        pytest.param("service_b.py", "python", id="same-language-different-files"),
        pytest.param("service_b.js", "javascript", id="cross-language"),
    ],
)
def test_same_name_definitions_are_preserved(second_file, second_language, caplog):
    index = ProjectIndex()
    first_node, second_node = object(), object()
    index.register_function("execute", "service_a.py", first_node, "python")
    index.register_function("execute", second_file, second_node, second_language)

    assert len(index.functions) == 2
    candidates = index.find_candidates("execute")
    assert [(item.file_path, item.language) for item in candidates] == [
        ("service_a.py", "python"),
        (second_file, second_language),
    ]
    assert candidates[0].node is first_node
    assert candidates[1].node is second_node
    assert [index.functions[item.symbol_id] for item in candidates] == candidates
    for language in {"python", second_language}:
        assert index.find_candidates("execute", language) == [
            item for item in candidates if item.language == language
        ]
    assert index.find_candidates("execute", "java") == []

    with caplog.at_level(logging.WARNING, logger="dr_source.core.project_index"):
        assert index.find_function("execute") is None
    assert "Ambiguous function 'execute': 2 candidates" in caplog.text
    assert "service_a.py" in caplog.text
    assert second_file in caplog.text


def test_unique_and_missing_legacy_lookup():
    index = ProjectIndex()
    node = object()
    assert index.find_function("execute") is None
    assert index.find_candidates("execute") == []
    index.register_function("execute", "service.py", node, "python")

    definition = index.find_function("execute")
    assert definition is not None
    assert definition.name == "execute"
    assert definition.file_path == "service.py"
    assert definition.language == "python"
    assert definition.node is node
    assert definition.symbol_id.owner is None
    assert definition.symbol_id.signature is None
    assert index.find_candidates("execute", "python") == [definition]
    with pytest.raises(FrozenInstanceError):
        definition.symbol_id.name = "other"


def test_language_distinguishes_definitions_with_the_same_file_and_name():
    index = ProjectIndex()
    nodes = {"python": object(), "javascript": object()}
    for language, node in nodes.items():
        index.register_function("execute", "shared.source", node, language)

    assert len(index.functions) == 2
    for language, node in nodes.items():
        candidates = index.find_candidates("execute", language)
        assert len(candidates) == 1
        assert candidates[0].symbol_id.language == language
        assert candidates[0].node is node


def test_candidate_identities_and_diagnostics_ignore_registration_order(caplog):
    registrations = [
        ("execute", "service_b.py", object(), "python"),
        ("execute", "service_a.py", object(), "python"),
        ("execute", "service_a.js", object(), "javascript"),
    ]
    indexes = [ProjectIndex(), ProjectIndex()]
    for index, entries in zip(indexes, (registrations, reversed(registrations))):
        for entry in entries:
            index.register_function(*entry)

    first_ids = [item.symbol_id for item in indexes[0].find_candidates("execute")]
    second_ids = [item.symbol_id for item in indexes[1].find_candidates("execute")]
    assert first_ids == second_ids
    assert [(item.language, item.file_path, item.name) for item in first_ids] == [
        ("javascript", "service_a.js", "execute"),
        ("python", "service_a.py", "execute"),
        ("python", "service_b.py", "execute"),
    ]
    assert [item.symbol_id for item in indexes[0].find_candidates("execute", "python")] == [
        item.symbol_id for item in indexes[1].find_candidates("execute", "python")
    ]
    messages = []
    for index in indexes:
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="dr_source.core.project_index"):
            assert index.find_function("execute") is None
        messages.append(caplog.messages)
    assert messages[0] == messages[1]


def test_source_positions_distinguish_same_name_declarations_in_one_file():
    index = ProjectIndex()
    for position in ((8, 4), (2, 4)):
        index.register_function(
            "execute", "Service.java", object(), "java",
            declaration_position=position,
        )
    candidates = index.find_candidates("execute", "java")
    assert [item.symbol_id.declaration_position for item in candidates] == [(2, 4), (8, 4)]
    assert len(index.functions) == 2
    assert index.find_function("execute") is None


def test_repeat_registration_does_not_duplicate_candidates():
    index = ProjectIndex()
    node = object()
    for _ in range(2):
        index.register_function("execute", "service.py", node, "python")
    assert len(index.functions) == 1
    assert index.find_candidates("execute") == [index.find_function("execute")]


def test_conflicting_identity_is_rejected_without_overwriting():
    index = ProjectIndex()
    original = object()
    index.register_function("execute", "service.py", original, "python")
    with pytest.raises(ValueError, match="Conflicting registration"):
        index.register_function("execute", "service.py", object(), "python")
    assert index.find_function("execute").node is original
    assert len(index.functions) == 1
