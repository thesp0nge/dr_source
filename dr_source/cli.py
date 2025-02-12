# dr_source/cli.py
import click
import time
import os
import json
from dr_source.core.codebase import Codebase
from dr_source.core.scanner import Scanner
from dr_source.core.db import ScanDatabase
from dr_source.logging import setup_logging


@click.command()
@click.argument("target_path", type=click.Path(exists=True))
@click.option("--history", is_flag=True, help="Show the scan history for this project.")
@click.option(
    "--compare",
    type=int,
    help="Compare the latest scan with the previous scan specified by ID.",
)
@click.option(
    "--export",
    type=click.Choice(["sarif", "json", "html"]),
    help="Export results in the specified format.",
)
@click.option("--verbose", is_flag=True, help="Show detailed output during comparison.")
@click.option(
    "--output",
    type=click.Path(),
    help="Output file for the exported report (if not specified, a default name is used).",
)
@click.option("--debug", is_flag=True, help="Enable debug logging.")
@click.option("--version", is_flag=True, help="Show DRSource version and exit.")
@click.option("--verbose", is_flag=True, help="Show detailed output during comparison.")
@click.option("--init-db", is_flag=True, help="Initialize the database from scratch.")
def main(
    target_path, history, compare, export, verbose, output, debug, version, init_db
):
    """
    DRSource - A static analysis tool for detecting vulnerabilities in Java/JSP projects.

    TARGET_PATH is the path of the codebase to analyze.
    """
    if version:
        click.echo(f"DRSource version {__version__}")
        return

    setup_logging(debug=debug)
    project_name = os.path.basename(os.path.abspath(target_path))
    db = ScanDatabase(project_name)

    if init_db:
        click.echo("🔄 Initializing the database...")
        db.initialize()
        click.echo("✅ Database initialized successfully.")
        return

    if history:
        click.echo(f"\n📌 Scan history for '{project_name}':")
        history_records = db.get_scan_history()
        if not history_records:
            click.echo("🔍 No scan history found for this project.")
        else:
            for scan in history_records:
                click.echo(
                    f"[{scan[1]}] ID {scan[0]} | Vulnerabilities found: {scan[2]}"
                )
        return

    if compare:
        latest_scan_id = db.get_latest_scan_id()
        if not latest_scan_id:
            click.echo("❌ No scan history available.")
            return
        click.echo(f"🔍 Comparing scan {compare} with latest scan {latest_scan_id}...")
        comparison = db.compare_scans(compare, latest_scan_id)
        click.echo(f"📌 New vulnerabilities: {len(comparison['new'])}")
        click.echo(f"✅ Resolved: {len(comparison['resolved'])}")
        click.echo(f"⚠️ Persistent: {len(comparison['persistent'])}")
        if verbose:
            if comparison["new"]:
                click.echo("\n🆕 New vulnerabilities:")
                for vuln in comparison["new"]:
                    click.echo(f"  - {vuln}")
            if comparison["resolved"]:
                click.echo("\n✅ Resolved vulnerabilities:")
                for vuln in comparison["resolved"]:
                    click.echo(f"  - {vuln}")
            if comparison["persistent"]:
                click.echo("\n⚠️ Persistent vulnerabilities:")
                for vuln in comparison["persistent"]:
                    click.echo(f"  - {vuln}")
        return

    start_time = time.time()
    click.echo(f"🔍 Starting scan on {target_path}...")

    codebase = Codebase(target_path)
    codebase.load_files()

    scanner = Scanner(codebase)
    results = scanner.scan()
    scan_duration = time.time() - start_time
    num_files = len(codebase.files)
    num_vulns = len(results)

    click.echo(
        f"\n✅ Scan completed: {num_files} files analyzed, {num_vulns} vulnerabilities found in {scan_duration:.2f} seconds."
    )

    scan_id = db.start_scan()
    for res in results:
        db.save_vulnerability(
            scan_id, res["file"], res["vuln_type"], res["match"], res["line"]
        )
    db.update_scan_summary(scan_id, num_vulns, num_files, scan_duration)

    if export:
        out_file = output if output else f"{project_name}_scan_{scan_id}.{export}"
        if export == "sarif":
            from dr_source.reports.sarif import SARIFReport

            reporter = SARIFReport()
            report_content = reporter.generate(results)
            with open(out_file, "w") as f:
                f.write(report_content)
            click.echo(f"📄 Results exported to {out_file}")
        elif export == "json":
            with open(out_file, "w") as f:
                json.dump(results, f, indent=2)
            click.echo(f"📄 Results exported to {out_file}")
        elif export == "html":
            click.echo("📄 HTML export not yet implemented.")
    else:
        for res in results:
            click.echo(
                f"[{res['vuln_type']}] {res['file']}:{res['line']} -> {res['match']}"
            )


if __name__ == "__main__":
    setup_logging()  # Default logging configuration
    main()
