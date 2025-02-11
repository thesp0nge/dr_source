import os
import click
import pkg_resources
import json
from .analyzer import DRSourceAnalyzer
from .re_vulnerability_detector import ReVulnerabilityDetector
from .scan_database import ScanDatabase
from tqdm import tqdm
import uuid
from datetime import datetime


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
@click.option(
    "--compare",
    type=int,
    help="Compare last scan with a previous saved in the database.",
)
@click.option(
    "--export", type=click.Choice(["json", "html"]), help="Exporet last scan results."
)
def main(project_path, output, lang, vulnerabilities, stdout, exclude_test, history):
    """DRSource: Java and JSP Vulnerability Scanner"""
    project_name = get_project_name(project_path)
    # Inizializziamo il database delle scansioni
    db = ScanDatabase(project_name)

    # Se l'opzione --history è attivata, mostriamo lo storico e usciamo
    if history:
        click.echo(f"\n📌 Storico delle scansioni per '{project_name}':")
        for scan in db.get_scan_history():
            click.echo(f"[{scan[1]}] ID {scan[0]} | Vulnerabilità trovate: {scan[2]}")
        return

    if compare:
        latest_scan_id = db.get_latest_scan_id()
        if not latest_scan_id:
            click.echo("❌ Nessuna scansione registrata.")
            return

        click.echo(f"🔍 Confronto tra scansione {compare} e {latest_scan_id}...")
        comparison = db.compare_scans(compare, latest_scan_id)

        click.echo(f"📌 Nuove vulnerabilità: {len(comparison['new'])}")
        click.echo(f"✅ Risolte: {len(comparison['resolved'])}")
        click.echo(f"⚠️ Persistenti: {len(comparison['persistent'])}")

        for vuln in comparison["new"]:
            click.echo(f"🆕 {vuln}")

        for vuln in comparison["resolved"]:
            click.echo(f"✅ {vuln}")

        return

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

    if export:
        export_results(project_name, scan_id, export)


def export_results(project_name, scan_id, format):
    db = ScanDatabase(project_name)
    results = db.get_vulnerabilities_by_scan(scan_id)

    if format == "json":
        with open(f"{project_name}_scan_{scan_id}.json", "w") as f:
            json.dump(
                [
                    {"file": v[0], "type": v[1], "source": v[2], "sink": v[3]}
                    for v in results
                ],
                f,
                indent=4,
            )
        click.echo(f"📄 Risultati esportati in {project_name}_scan_{scan_id}.json")

    elif format == "html":
        with open(f"{project_name}_scan_{scan_id}.html", "w") as f:
            f.write("<html><head><title>Report Scansione</title></head><body>")
            f.write(f"<h1>Report Scansione {scan_id}</h1><ul>")
            for vuln in results:
                f.write(
                    f"<li><b>{vuln[1]}</b> in <i>{vuln[0]}</i> (Source: {vuln[2]} → Sink: {vuln[3]})</li>"
                )
            f.write("</ul></body></html>")
        click.echo(f"📄 Risultati esportati in {project_name}_scan_{scan_id}.html")

    elif format == "sarif":
        sarif_output = generate_sarif(results, project_name, scan_id)
        sarif_file = f"{project_name}_scan_{scan_id}.sarif"
        with open(sarif_file, "w") as f:
            json.dump(sarif_output, f, indent=4)
        click.echo(f"📄 Risultati esportati in {sarif_file}")


def generate_sarif(results, project_name, scan_id):
    """Genera un report SARIF per le vulnerabilità rilevate"""
    run_uuid = str(uuid.uuid4())

    sarif_results = []
    for vuln in results:
        file_path, vuln_type, source, sink = vuln

        sarif_results.append(
            {
                "ruleId": vuln_type,
                "level": "error",
                "message": {"text": f"Possible {vuln_type} vulnerability detected."},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1
                            },  # Se possiamo ottenere la riga esatta, aggiorniamo questo valore
                        }
                    }
                ],
                "properties": {"source": source, "sink": sink},
            }
        )

    sarif_report = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dr_source",
                        "version": "1.0",
                        "informationUri": "https://github.com/thesp0nge/dr_source",
                        "rules": [
                            {
                                "id": vuln[1],
                                "name": vuln[1],
                                "shortDescription": {"text": vuln[1]},
                            }
                            for vuln in results
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

    return sarif_report


if __name__ == "__main__":
    main()
