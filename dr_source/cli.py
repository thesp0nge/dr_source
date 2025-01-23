import click
import json
from .analyzer import DRSourceAnalyzer
from .analyzer import VulnerabilityDetector
from tqdm import tqdm


@click.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option(
    "--output", "-o", default="drsource_report.json", help="Output report file"
)
@click.option(
    "--vulnerabilities",
    "-v",
    multiple=True,
    type=click.Choice(
        [
            "XSS",
            "SQL_INJECTION",
            "COMMAND_INJECTION",
            "PATH_TRAVERSAL",
            "DESERIALIZATION",
            "SENSITIVE_DATA_EXPOSURE",
        ]
    ),
    help="Specify vulnerability types to scan",
)
def main(project_path, output, vulnerabilities):
    """DRSource: Java and JSP Vulnerability Scanner"""
    analyzer = DRSourceAnalyzer(project_path)

    # Filter vulnerability types if specified
    if vulnerabilities:
        VulnerabilityDetector.VULNERABILITY_PATTERNS = {
            vuln: patterns
            for vuln, patterns in VulnerabilityDetector.VULNERABILITY_PATTERNS.items()
            if vuln in vulnerabilities
        }

    # Get project files with progress bar
    project_files = analyzer.find_project_files()

    all_vulnerabilities = []
    with tqdm(total=len(project_files), desc="Analyzing Files") as pbar:
        for file_path, file_type in project_files:
            file_vulnerabilities = analyzer.analyze_file(file_path, file_type)

            if file_vulnerabilities:
                analyzer._store_vulnerabilities(file_path, file_vulnerabilities)
                all_vulnerabilities.extend(file_vulnerabilities)

            pbar.update(1)

    click.echo(f"Found {len(all_vulnerabilities)} potential vulnerabilities")

    report = analyzer.generate_report()
    with open(output, "w") as f:
        json.dump(report, f, indent=2)

    click.echo(f"Report saved to {output}")


if __name__ == "__main__":
    main()
