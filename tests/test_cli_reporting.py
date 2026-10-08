import json
import re
import sqlite3
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from dr_source import cli
from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.db import ScanDatabase
from dr_source.core.result import ScanMetrics, ScanResult
from dr_source.core.scanner import Scanner
from dr_source.reports.ascii import ASCIIReport
from dr_source.reports.sarif import SARIFReport


def finding(path='app.py', trace=None):
    return Vulnerability('TEST', 'unsafe message', 'HIGH', path, 7, 'controlled',
                         ['source', 'sink'] if trace is None else trace)


def persisted_row(v):
    # Characterize the existing SQLite serialization/read-back contract.
    trace = ' -> '.join(v.trace)
    return dict(file=v.file_path, vuln_type=v.vulnerability_type, match=v.message,
                line=v.line_number, severity=v.severity, plugin_name=v.plugin_name,
                trace=trace.split(' -> ') if trace else [])


@pytest.fixture
def current_scan(monkeypatch, tmp_path):
    result = ScanResult((finding('z.py'), finding('a.py')), (), ScanMetrics(3, 1.25))
    database = MagicMock(project_name='project')
    database.get_vulnerabilities_for_scan.side_effect = AssertionError('current scan reloaded')
    scanner = SimpleNamespace(scan=MagicMock(return_value=result), db=database,
                              scan_id=42, num_files_analyzed=999,
                              scan_duration=999.0, all_findings=[])
    monkeypatch.setattr(cli, 'Scanner', MagicMock(return_value=scanner))
    monkeypatch.setattr(cli, 'ScanDatabase', MagicMock(return_value=database))
    return scanner, result, tmp_path


def test_console_uses_result_and_does_not_reload(current_scan):
    scanner, result, target = current_scan
    output = CliRunner().invoke(cli.main, [str(target), '--show-trace'])
    assert output.exit_code == 0, output.exception
    assert '[HIGH][TEST] a.py:7 -> unsafe message' in output.output
    assert 'Trace: source -> sink' in output.output
    assert output.output.index('a.py:7') < output.output.index('z.py:7')
    for label, value in [('Files Analyzed', '3'), ('Scan Duration', '1.25s'),
                         ('Total Vulnerabilities', '2')]:
        assert re.search(re.escape(label) + r'\s+' + re.escape(value), output.output)
    assert '999' not in output.output
    scanner.db.get_vulnerabilities_for_scan.assert_not_called()
    plain = CliRunner().invoke(cli.main, [str(target)])
    assert plain.exit_code == 0
    assert 'Trace:' not in plain.output


@pytest.mark.parametrize('format', ['json', 'ascii', 'sarif'])
def test_exports_match_persisted_representation(current_scan, format):
    scanner, result, target = current_scan
    path = target / ('report.' + format)
    output = CliRunner().invoke(cli.main, [str(target), '--export', format, '--output', str(path)])
    assert output.exit_code == 0, output.exception
    rows = [persisted_row(v) for v in result.findings]
    if format == 'json':
        assert json.loads(path.read_text()) == rows
        assert set(rows[0]) == {'file', 'vuln_type', 'match', 'line', 'severity', 'plugin_name', 'trace'}
        assert isinstance(json.loads(path.read_text())[0]['trace'], list)
    elif format == 'ascii':
        assert path.read_text() == ASCIIReport().generate(rows)
    else:
        actual = json.loads(path.read_text())['runs'][0]
        expected = json.loads(SARIFReport().generate(rows))['runs'][0]
        assert actual['results'] == expected['results']
        assert actual['tool'] == expected['tool']
    scanner.db.get_vulnerabilities_for_scan.assert_not_called()


def test_default_filename_and_ascii_stdout(current_scan, monkeypatch):
    scanner, result, target = current_scan
    monkeypatch.chdir(target)
    output = CliRunner().invoke(cli.main, [str(target), '--export', 'json'])
    assert output.exit_code == 0
    assert (target / 'project_scan_42.json').exists()
    output = CliRunner().invoke(cli.main, [str(target), '--export', 'ascii'])
    assert ASCIIReport().generate([persisted_row(v) for v in result.findings]) in output.output


@pytest.mark.parametrize('trace', [[], [''], ['source', 'sink'], ['source -> nested', 'sink'], ['source', '']])
def test_adapter_trace_matches_real_database(tmp_path, trace):
    database = ScanDatabase(str(tmp_path))
    scan_id = database.start_scan()
    v = finding(trace=trace)
    row = persisted_row(v)
    database.store_vulnerabilities(scan_id, [dict(row, trace=' -> '.join(trace))])
    assert cli._finding_to_report_dict(v) == database.get_vulnerabilities_for_scan(scan_id)[0]


@pytest.mark.parametrize('option', ['--history', '--compare', '--list-scans'])
def test_historical_commands_stay_database_backed(monkeypatch, tmp_path, option):
    database = MagicMock()
    database.get_scan_history.return_value = [(5, 'timestamp', 2)]
    database.get_latest_scan_id.return_value = 5
    database.compare_scans.return_value = {'new': ['new'], 'resolved': [], 'persistent': []}
    database.list_all_project_scans.return_value = [dict(project_name='project', total_scans=1,
                                                       last_scanned_at='timestamp', last_vuln_count=2)]
    monkeypatch.setattr(cli, 'ScanDatabase', MagicMock(return_value=database))
    scanner = MagicMock(side_effect=AssertionError('historical command scanned'))
    monkeypatch.setattr(cli, 'Scanner', scanner)
    args = [str(tmp_path), option] + (['1', '--verbose'] if option == '--compare' else [])
    output = CliRunner().invoke(cli.main, args)
    assert output.exit_code == 0, output.exception
    if option == '--history':
        database.get_scan_history.assert_called_once_with()
        assert 'ID 5 | Vulnerabilities found: 2' in output.output
    elif option == '--compare':
        database.compare_scans.assert_called_once_with(1, 5)
        assert 'New vulnerabilities: 1' in output.output
    else:
        database.list_all_project_scans.assert_called_once_with()
        assert 'project' in output.output
    scanner.assert_not_called()


def test_scan_failure_does_not_export(current_scan):
    scanner, result, target = current_scan
    scanner.scan.side_effect = RuntimeError('fatal scan')
    path = target / 'report.json'
    output = CliRunner().invoke(cli.main, [str(target), '--export', 'json', '--output', str(path)])
    assert isinstance(output.exception, RuntimeError)
    assert not path.exists()
    assert 'SCAN SUMMARY' not in output.output


def test_real_cli_scan_keeps_sqlite_writes_without_reporting_reload(monkeypatch, tmp_path):
    class ControlledAnalyzer(AnalyzerPlugin):
        name = 'controlled'
        def get_supported_extensions(self):
            return ['.py']
        def analyze(self, file_path):
            return [finding(file_path)]

    (tmp_path / 'app.py').write_text('pass\n')
    monkeypatch.setattr(Scanner, 'load_plugins',
                        lambda scanner: setattr(scanner, 'extension_map', {'.py': [ControlledAnalyzer()]}))
    instances = []
    results = []
    def create(**kwargs):
        scanner = Scanner(**kwargs)
        for method in ('start_scan', 'store_vulnerabilities', 'update_scan_summary'):
            monkeypatch.setattr(scanner.db, method, MagicMock(wraps=getattr(scanner.db, method)))
        scan = scanner.scan
        def capture_result():
            result = scan()
            results.append(result)
            return result
        scanner.scan = capture_result
        instances.append(scanner)
        return scanner
    monkeypatch.setattr(cli, 'Scanner', create)
    original_read = ScanDatabase.get_vulnerabilities_for_scan
    monkeypatch.setattr(ScanDatabase, 'get_vulnerabilities_for_scan',
                        MagicMock(side_effect=AssertionError('reporting reload')))
    path = tmp_path / 'report.json'
    output = CliRunner().invoke(cli.main, [str(tmp_path), '--export', 'json', '--output', str(path)])
    assert output.exit_code == 0, output.exception
    scanner = instances[0]
    for method in ('start_scan', 'store_vulnerabilities', 'update_scan_summary'):
        getattr(scanner.db, method).assert_called_once()
    rows = original_read(scanner.db, scanner.scan_id)
    assert json.loads(path.read_text()) == rows
    assert len(rows) == len(results[0].findings) == len(scanner.all_findings) == 1
    assert sorted(rows, key=lambda row: (row["file"], row["line"])) == sorted(
        [persisted_row(v) for v in results[0].findings], key=lambda row: (row["file"], row["line"]))
    with sqlite3.connect(scanner.db.db_path) as connection:
        summary = connection.execute('SELECT num_vulnerabilities, num_files_analyzed, scan_duration FROM scans WHERE id=?',
                                     (scanner.scan_id,)).fetchone()
    assert summary == (1, 1, scanner.scan_duration)
