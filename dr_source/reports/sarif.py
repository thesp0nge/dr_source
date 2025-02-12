# dr_source/reports/sarif.py
import json
from datetime import datetime


class SARIFReport:
    def generate(self, results):
        sarif_results = []
        for res in results:
            sarif_results.append(
                {
                    "ruleId": res["vuln_type"],
                    "level": "error",
                    "message": {
                        "text": f"Possible {res['vuln_type']} vulnerability detected."
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": res["file"],
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": res["line"],
                                    "endLine": res["line"],
                                },
                            }
                        }
                    ],
                    "properties": {"details": res["match"]},
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
                            "version": "1.0.0",
                            "informationUri": "https://github.com/thesp0nge/dr_source",
                            "rules": [
                                {"id": res["vuln_type"], "name": res["vuln_type"]}
                                for res in results
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
