import os
import click
import pkg_resources
import json
from .analyzer import DRSourceAnalyzer
from .re_vulnerability_detector import ReVulnerabilityDetector
from .scan_database import ScanDatabase
from tqdm import tqdm


def get_version():
    try:
        return pkg_resources.get_distribution("dr_source").version
    except pkg_resources.DistributionNotFound:
        return "unknown"  # Default version if not installed


# Funzione per determinare il nome del progetto
def get_project_name(target_path):
    if os.path.isdir(target_path):
        return os.path.basename(
            os.path.abspath(target_path)
        )  # Usa il nome della cartella
    return os.path.splitext(os.path.basename(target_path))[
        0
    ]  # Usa il nome del file senza estensione


@click.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--history", is_flag=True, help="Show scan history for a given project.")
@click.option(
    "--output", "-o", default="drsource_report.json", help="Output report file"
)
@click.option(
    "--lang",
    "-L",
    multiple=True,
    type=click.Choice(["java", "jsp"]),
    help="Choose the file type to scan",
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
@click.option(
    "--stdout", is_flag=True, default=False, help="Print vulnerabilities to stdout"
)
@click.option(
    "--exclude-test",
    "-T",
    is_flag=True,
    default=False,
    help="Exclude test files from analysis",
)
@click.version_option(version=get_version(), prog_name="dr_source")
def main(project_path, output, lang, vulnerabilities, stdout, exclude_test, history):
    """DRSource: Java and JSP Vulnerability Scanner"""
    project_name = get_project_name(project_path)
    # Inizializziamo il database delle scansioni
    db = ScanDatabase(project_name)

    # Se l'opzione --history è attivata, mostriamo lo storico e usciamo
    if history:
        click.echo(f"\n📌 Storico delle scansioni per '{project_name}':")
        history_records = db.get_scan_history()

        if not history_records:
            click.echo("🔍 Nessuna scansione registrata per questo progetto.")
        else:
            for scan in history_records:
                click.echo(
                    f"[{scan[1]}] Scansione ID {scan[0]} | Vulnerabilità trovate: {scan[2]}"
                )

        return  # Uscita dopo aver mostrato lo storico

    if lang:
        # Filter source file extension to analyze
        DRSourceAnalyzer.KNOWN_EXTENSIONS = {
            extension
            for extension in DRSourceAnalyzer.KNOWN_EXTENSIONS
            if extension in lang
        }

    # Filter vulnerability types if specified
    if vulnerabilities:
        ReVulnerabilityDetector.RE_VULNERABILITY_PATTERNS = {
            vuln: patterns
            for vuln, patterns in ReVulnerabilityDetector.RE_VULNERABILITY_PATTERNS.items()
            if vuln in vulnerabilities
        }

    analyzer = DRSourceAnalyzer(project_path)
    # Get project files with progress bar
    project_files = analyzer.find_project_files(lang, exclude_test)

    start_time = time.time()
    scan_id = db.start_scan()
    all_vulnerabilities = []

    with tqdm(total=len(project_files), desc="Analyzing Files") as pbar:
        for file_path, file_type in project_files:
            file_vulnerabilities = analyzer.analyze_file(file_path, file_type)

            if file_vulnerabilities:
                if stdout:
                    for vuln in file_vulnerabilities:
                        click.echo(f"Vulnerability in {file_path}:")
                        click.echo(f"  Type: {vuln.type}")
                        click.echo(f"  Line: {vuln.line}")
                        click.echo(f"  Description: {vuln.description}")
                        click.echo(f"  Severity: {vuln.severity}")
                        click.echo(f"  Snippet: {vuln.match}")
                        click.echo("-" * 50)
                all_vulnerabilities.extend(file_vulnerabilities)

            pbar.update(1)
    for vuln in file_vulnerabilities:
        db.save_vulnerability(scan_id, *vuln)
    elapsed_time = time.time() - start_time

    db.update_scan_summary(
        scan_id, len(vulnerabilities), num_files_analyzed=10, scan_duration=elapsed_time
    )

    click.echo(f"Found {len(all_vulnerabilities)} potential vulnerabilities")

    report = analyzer.generate_report(all_vulnerabilities)
    with open(output, "w") as f:
        json.dump(report, f, indent=2)

    click.echo(f"Report saved to {output}")


if __name__ == "__main__":
    main()
