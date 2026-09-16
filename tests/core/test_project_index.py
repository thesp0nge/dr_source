"""Characterize current collisions, not the desired future symbol isolation."""

import pytest

from dr_source.core.project_index import FunctionDefinition, ProjectIndex


@pytest.mark.parametrize(
    "second_file, second_language",
    [
        pytest.param("service_b.py", "python", id="same-language-different-files"),
        pytest.param("service_b.js", "javascript", id="cross-language"),
    ],
)
def test_same_name_registration_replaces_previous_definition(second_file, second_language):
    index = ProjectIndex()
    # The index stores opaque AST payloads without interpreting them.
    first_node, second_node = object(), object()

    index.register_function("execute", "service_a.py", first_node, "python")
    first_definition = index.find_function("execute")
    assert first_definition == FunctionDefinition(
        "execute", "service_a.py", first_node, "python"
    )

    index.register_function("execute", second_file, second_node, second_language)
    replacement = index.find_function("execute")
    assert replacement == FunctionDefinition(
        "execute", second_file, second_node, second_language
    )
    assert replacement is not first_definition
    assert index.functions == {"execute": replacement}
