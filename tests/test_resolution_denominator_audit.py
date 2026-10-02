"""Small real-fixture checks for the denominator's semantic limitations."""

from pathlib import Path

from dr_source.core.resolution import ResolutionStatus
from dr_source.core.scanner import Scanner
from dr_source.plugins.javascript.plugin import JavaScriptAstAnalyzer
from dr_source.plugins.java.plugin import JavaAstAnalyzer

FIXTURES = Path(__file__).parent / "test_code"


def scan_language(monkeypatch, language, analyzer):
    def load(scanner):
        scanner.extension_map = {".js" if language == "javascript" else ".java": [analyzer()]}
    monkeypatch.setattr(Scanner, "load_plugins", load)
    scanner = Scanner(str(FIXTURES / language))
    scanner.scan()
    return scanner.diagnostics.resolution_events()


def test_real_rules_probe_logging_but_unconditionally_handle_java_framework_sink(monkeypatch):
    javascript = scan_language(monkeypatch, "javascript", JavaScriptAstAnalyzer)
    logging_sites = [event for event in javascript if event.call_name == "console.log"]
    assert {(Path(event.file_path).name, event.line) for event in logging_sites} == {
        ("new_rules_test.js", 8), ("new_rules_test.js", 15), ("vulnerable_express.js", 16),
    }
    assert all(event.status is ResolutionStatus.UNRESOLVED and not event.candidates
               for event in logging_sites)
    java = scan_language(monkeypatch, "java", JavaAstAnalyzer)
    legacy = [event for event in java if Path(event.file_path).name == "LegacyAndHibernate.java"]
    # Framework sink handling runs independently of the current detector's KB sinks.
    assert all(event.call_name not in {"createQuery", "getWriter"} for event in legacy)
    assert any(event.call_name == "getResultList" for event in legacy)


def test_unnamed_javascript_chain_calls_have_distinct_source_spans(monkeypatch):
    from tree_sitter import Language, Parser
    import tree_sitter_javascript

    parser = Parser()
    parser.language = Language(tree_sitter_javascript.language())
    source = (FIXTURES / "javascript" / "crypto_tests.js").read_bytes()
    tree = parser.parse(source)
    def calls(node):
        yield from ([node] if node.type == "call_expression" else [])
        for child in node.children:
            yield from calls(child)
    chain_calls = [node for node in calls(tree.root_node) if node.start_point == (4, 11)]
    assert len(chain_calls) == 3  # createHash, update, digest begin at the same byte.
    events = scan_language(monkeypatch, "javascript", JavaScriptAstAnalyzer)
    site = [event for event in events if Path(event.file_path).name == "crypto_tests.js"
            and event.line == 5 and event.column == 11]
    assert {event.call_name for event in site} == {"", "crypto.createHash"}
    assert len(site) == 3  # Each complete call span now has its own identity.
    assert {(event.end_line, event.end_column) for event in site} == {
        (node.end_point[0] + 1, node.end_point[1]) for node in chain_calls
    }
    assert len({event.identity for event in site}) == 3
    assert all(event.status is ResolutionStatus.UNRESOLVED for event in site)
    assert len(events) == 45  # Previously 42 across the main JavaScript fixtures.
