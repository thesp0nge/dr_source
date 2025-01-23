import click
import json
from .analyzer import DRSourceAnalyzer


@click.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option(
    "--output", "-o", default="drsource_report.json", help="Output report file"
)
def main(project_path, output):
    """DRSource: Java and JSP Vulnerability Scanner"""
    analyzer = DRSourceAnalyzer(project_path)
    vulnerabilities = analyzer.analyze_project()

    click.echo(f"Found {len(vulnerabilities)} potential vulnerabilities")

    report = analyzer.generate_report()
    with open(output, "w") as f:
        json.dump(report, f, indent=2)

    click.echo(f"Report saved to {output}")


if __name__ == "__main__":
    main()
