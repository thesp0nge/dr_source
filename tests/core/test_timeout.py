import time
import pytest
from typing import Any
from dr_source.core.utils import timeout_session, TimeoutException
from dr_source.core.scanner import Scanner
from dr_source.api import AnalyzerPlugin, Vulnerability
import os

def test_timeout_session_basic():
    """Test that timeout_session raises TimeoutException."""
    start_time = time.time()
    with pytest.raises(TimeoutException):
        with timeout_session(1):
            time.sleep(2)
    duration = time.time() - start_time
    assert 1.0 <= duration < 2.0

def test_timeout_session_no_timeout():
    """Test that timeout_session doesn't raise if finished in time."""
    with timeout_session(2):
        time.sleep(1)
    # If we get here, it passed

class HangingPlugin(AnalyzerPlugin):
    @property
    def name(self) -> str:
        return "Hanging Plugin"
    
    def get_supported_extensions(self):
        return [".java"]
    
    def analyze(self, file_path: str):
        if "hanging" in file_path:
            time.sleep(5)
        return [Vulnerability(
            vulnerability_type="TEST",
            message=f"Found in {os.path.basename(file_path)}",
            severity="LOW",
            file_path=file_path,
            line_number=1,
            plugin_name=self.name
        )]

    def index(self, file_path: str, project_index: Any):
        if "hanging" in file_path:
            time.sleep(5)

def test_scanner_timeout(tmp_path):
    """Test that Scanner handles per-file timeouts gracefully."""
    # Create a hanging file
    d = tmp_path / "subdir"
    d.mkdir()
    hanging_file = d / "hanging.java"
    hanging_file.write_text("timeout me")
    
    # Create a safe file
    safe_file = d / "safe.java"
    safe_file.write_text("i am safe")
    
    scanner = Scanner(target_path=str(tmp_path), timeout=1)
    scanner.extension_map[".java"] = [HangingPlugin()]
    
    start_time = time.time()
    scanner.scan()
    duration = time.time() - start_time
    
    # It should have timed out at least twice (once for indexing, once for analysis)
    # Each timeout is 1s, so duration should be at least 2s for hanging.java 
    # and very fast for safe.java
    assert duration >= 2.0
    
    # Findings from safe.java should be present
    # Findings from hanging.java should NOT be present in analysis because it timed out
    # Wait, my mock plugin returns a finding AFTER sleep. 
    # If it times out, analyze() is interrupted, so no finding.
    
    finding_messages = [f.message for f in scanner.all_findings]
    assert "Found in safe.java" in finding_messages
    assert "Found in hanging.java" not in finding_messages

if __name__ == "__main__":
    pytest.main([__file__])
