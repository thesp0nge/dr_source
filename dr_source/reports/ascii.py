# dr_source/reports/ascii.py
import logging
from tabulate import tabulate

logger = logging.getLogger(__name__)

class ASCIIReport:
    def generate(self, results):
        """
        Generates an ASCII table report as a string.
        Expects results to be a list of dictionaries with keys: vuln_type, file, line.
        """
        if not results:
            return "No vulnerabilities found."

        headers = ["vuln_type", "file", "line"]

        return tabulate(
            ([r[h] for h in headers] for r in results),
            headers=headers,
            tablefmt="simple_grid"
        )
