import json
from importlib.metadata import version

from click.testing import CliRunner

from dr_source.cli import main
from dr_source.reports.sarif import SARIFReport


def test_sarif_tool_version_matches_installed_package():
    report = json.loads(SARIFReport().generate([]))
    assert report["runs"][0]["tool"]["driver"]["version"] == version("dr_source")
    assert report["version"] == "2.1.0"  # SARIF format version is independent.


def test_cli_version_matches_installed_package():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert result.output == f"DRSource version {version('dr_source')}\n"


def test_sarif_without_installed_metadata_reports_unknown(monkeypatch):
    from dr_source.reports import sarif

    def missing_version(package):
        assert package == "dr_source"
        raise sarif.PackageNotFoundError(package)

    monkeypatch.setattr(sarif, "get_version", missing_version)
    report = json.loads(SARIFReport().generate([]))
    assert report["runs"][0]["tool"]["driver"]["version"] == "unknown"
