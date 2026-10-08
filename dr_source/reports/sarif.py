# dr_source/reports/sarif.py
import json
from datetime import datetime
from typing import Sequence

from dr_source.api import Vulnerability

try:
    from importlib.metadata import PackageNotFoundError, version as get_version
except ImportError:
    from importlib_metadata import PackageNotFoundError, version as get_version


class SARIFReport:
    def generate(self, findings: Sequence[Vulnerability]) -> str:
        """Render structured findings without modifying their payloads."""
        try:
            package_version = get_version("dr_source")
        except PackageNotFoundError:
            package_version = "unknown"
        sarif_results = []
        for finding in findings:
            sarif_results.append(
                {
                    "ruleId": finding.vulnerability_type,
                    "level": "error",
                    "message": {
                        "text": f"Possible {finding.vulnerability_type} vulnerability detected."
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": finding.file_path,
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": finding.line_number,
                                    "endLine": finding.line_number,
                                },
                            }
                        }
                    ],
                    "properties": {"details": finding.message},
                }
            )
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DRSource",
                            "version": package_version,
                            "informationUri": "https://github.com/thesp0nge/dr_source",
                            "rules": [
                                {"id": finding.vulnerability_type, "name": finding.vulnerability_type}
                                for finding in findings
                            ],
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.utcnow().isoformat() + "Z",
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                    "results": sarif_results,
                }
            ],
        }
        return json.dumps(sarif_report, indent=2)
