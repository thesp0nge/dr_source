import json
from copy import deepcopy
from importlib.metadata import version

import pytest
from tabulate import tabulate

from dr_source.api import Vulnerability
from dr_source.reports.ascii import ASCIIReport
from dr_source.reports.sarif import SARIFReport


@pytest.fixture
def findings():
    return (Vulnerability('SQL_INJECTION', 'unsafe query', 'HIGH', 'app.py', 12,
                          'analyzer', ['request', 'execute']),)


def test_ascii_structured_input_preserves_table(findings):
    assert ASCIIReport().generate(findings) == tabulate(
        [['SQL_INJECTION', 'app.py', '12']],
        headers=['Vulnerability', 'File', 'Line'], tablefmt='grid')


def test_sarif_structured_input_preserves_semantics(findings):
    report = json.loads(SARIFReport().generate(findings))
    run = report['runs'][0]
    assert report['version'] == '2.1.0'
    assert run['tool']['driver']['version'] == version('dr_source')
    assert run['tool']['driver']['rules'] == [{'id': 'SQL_INJECTION', 'name': 'SQL_INJECTION'}]
    assert run['results'] == [{
        'ruleId': 'SQL_INJECTION', 'level': 'error',
        'message': {'text': 'Possible SQL_INJECTION vulnerability detected.'},
        'locations': [{'physicalLocation': {
            'artifactLocation': {'uri': 'app.py', 'uriBaseId': '%SRCROOT%'},
            'region': {'startLine': 12, 'endLine': 12}}}],
        'properties': {'details': 'unsafe query'},
    }]


@pytest.mark.parametrize('reporter', [ASCIIReport, SARIFReport])
def test_reporters_do_not_mutate_findings_or_traces(findings, reporter):
    before = deepcopy(findings)
    trace = findings[0].trace
    reporter().generate(findings)
    assert findings == before
    assert findings[0].trace is trace


def test_empty_structured_reports():
    assert ASCIIReport().generate(()) == 'No vulnerabilities found.'
    run = json.loads(SARIFReport().generate(()))['runs'][0]
    assert run['results'] == []
    assert run['tool']['driver']['rules'] == []
