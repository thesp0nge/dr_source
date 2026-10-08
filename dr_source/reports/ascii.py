# dr_source/reports/ascii.py
import logging
from typing import Sequence

from dr_source.api import Vulnerability

logger = logging.getLogger(__name__)


class ASCIIReport:
    def generate(self, findings: Sequence[Vulnerability]) -> str:
        """
        Generates an ASCII table report as a string.
        Consumes structured findings without modifying their payloads.
        """
        if not findings:
            return "No vulnerabilities found."

        headers = ["Vulnerability", "File", "Line"]
        rows = []
        for finding in findings:
            vuln = finding.vulnerability_type
            file = finding.file_path
            line = str(finding.line_number)
            rows.append([vuln, file, line])

        # Try to use the tabulate library if available.
        try:
            from tabulate import tabulate

            report = tabulate(rows, headers=headers, tablefmt="grid")
        except ImportError:
            # Otherwise, build the table manually.
            col_widths = [
                max(len(str(x)) for x in col) for col in zip(*([headers] + rows))
            ]
            sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
            header_line = (
                "| "
                + " | ".join(str(h).ljust(w) for h, w in zip(headers, col_widths))
                + " |"
            )
            lines = [sep, header_line, sep]
            for row in rows:
                row_line = (
                    "| "
                    + " | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths))
                    + " |"
                )
                lines.append(row_line)
            lines.append(sep)
            report = "\n".join(lines)
        return report

