import pytest
from dr_source.core.codebase import FileObject
from dr_source.core.detectors.session_fixation import SessionFixationDetector


def test_session_fixation_detector_regex():
    # Caso in cui viene chiamato request.getSession() e non viene invocato changeSessionId o invalidate.
    sample = (
        "public class Test {\n"
        "  public void test() {\n"
        "    HttpSession session = request.getSession();\n"
        "    // No safe call to changeSessionId() or invalidate()\n"
        "  }\n"
        "}"
    )
    file_obj = FileObject("TestSessionFixation.java", sample)
    detector = SessionFixationDetector()
    results = detector.detect(file_obj)
    assert results, "Session Fixation detector should flag vulnerability"
    for res in results:
        assert "Session Fixation" in res["vuln_type"]
        assert res["line"] > 0


def test_session_fixation_detector_ast():
    sample = (
        "public class Test {\n"
        "  public void test() {\n"
        "    HttpSession session = request.getSession();\n"
        "  }\n"
        "}"
    )
    file_obj = FileObject("TestSessionFixation.java", sample)
    import javalang

    tree = javalang.parse.parse(file_obj.content)
    detector = SessionFixationDetector()
    results = detector.detect_ast_from_tree(file_obj, tree)
    # In modalità AST, se non viene trovato un metodo safe, dovrebbe essere segnalato.
    assert results, "AST-based Session Fixation vulnerability should be flagged"
