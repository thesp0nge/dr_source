#!/usr/bin/env python3
import click
import time
import os
import json
from dr_source.core.codebase import Codebase
from dr_source.core.scanner import Scanner
from dr_source.core.db import ScanDatabase
from dr_source.logging import setup_logging
from dr_source.reports.sarif import SARIFReport
from dr_source.reports.ascii import ASCIIReport
from dr_source.core.usage import where_is_it_used

try:
    from importlib.metadata import version as get_version
except ImportError:
    from importlib_metadata import version as get_version


@click.command(context_settings=dict(ignore_unknown_options=True))
@click.argument("target_path", required=False, type=click.Path(exists=True))
@click.option("--init-db", is_flag=True, help="Initialize the database from scratch.")
@click.option("--history", is_flag=True, help="Show the scan history for this project.")
@click.option(
    "--compare", type=int, help="Compare the latest scan with the scan specified by ID."
)
@click.option(
    "--export",
    type=click.Choice(["sarif", "json", "html", "ascii"]),
    help="Export results in the specified format.",
)
@click.option(
    "--where-used", type=str, help="Show classes that use the specified class."
)
@click.option("--verbose", is_flag=True, help="Show detailed output during comparison.")
@click.option(
    "--output", type=click.Path(), help="Output file for the exported report."
)
@click.option("--debug", is_flag=True, help="Enable debug logging.")
@click.option(
    "--show-trace",
    is_flag=True,
    help="Display full call trace for AST-based vulnerabilities.",
)
@click.option(
    "--version", "show_version", is_flag=True, help="Show DRSource version and exit."
)
def main(
    target_path,
    init_db,
    history,
    compare,
    export,
    where_used,
    verbose,
    output,
    debug,
    show_trace,
    show_version,
):
    """
    DRSource - A multi-language static analysis tool.
    TARGET_PATH is the path of the codebase to analyze.
    """
    if show_version:
        try:
            pkg_version = get_version("dr_source")
        except Exception:
            pkg_version = "unknown"
        click.echo(f"DRSource version {pkg_version}")
        return

    setup_logging(debug=debug)

    if where_used:
        if not target_path:
            ctx = click.get_current_context()
            ctx.fail("Missing argument 'TARGET_PATH' when using --where-used.")
        codebase = Codebase(target_path)
        codebase.load_files()
        usage_results = where_is_it_used(codebase, where_used)
        if not usage_results:
            click.echo(f"No usage found for class '{where_used}'.")
        else:
            # Genera un report ASCII
            headers = ["Class", "File"]
            rows = [[res["class"], res["file"]] for res in usage_results]
            try:
                from tabulate import tabulate

                click.echo(tabulate(rows, headers=headers, tablefmt="grid"))
            except ImportError:
                click.echo(headers)
                for row in rows:
                    click.echo(row)
        return

    if not target_path:
        ctx = click.get_current_context()
        ctx.fail("Missing argument 'TARGET_PATH'.")

    db = ScanDatabase(target_path)

    if init_db:
        click.echo("Initializing database...")
        db.initialize()
        click.echo("Database initialized successfully.")
        return

    if history:
        click.echo(f"Scan history for '{target_path}':")
        history_records = db.get_scan_history()
        if not history_records:
            click.echo("No scan history found.")
        else:
            for scan in history_records:
                click.echo(
                    f"[{scan[1]}] ID {scan[0]} | Vulnerabilities found: {scan[2]}"
                )
        return

    if compare:
        latest_scan_id = db.get_latest_scan_id()
        if not latest_scan_id:
            click.echo("No scan history available.")
            return
        click.echo(f"Comparing scan {compare} with latest scan {latest_scan_id}...")
        comparison = db.compare_scans(compare, latest_scan_id)
        click.echo(f"New vulnerabilities: {len(comparison['new'])}")
        click.echo(f"Resolved: {len(comparison['resolved'])}")
        click.echo(f"Persistent: {len(comparison['persistent'])}")
        if verbose:
            if comparison["new"]:
                click.echo("New vulnerabilities:")
                for vuln in comparison["new"]:
                    click.echo(f"  - {vuln}")
            if comparison["resolved"]:
                click.echo("Resolved vulnerabilities:")
                for vuln in comparison["resolved"]:
                    click.echo(f"  - {vuln}")
            if comparison["persistent"]:
                click.echo("Persistent vulnerabilities:")
                for vuln in comparison["persistent"]:
                    click.echo(f"  - {vuln}")
        return

    click.echo(f"Starting scan on {target_path}...")

    # 1. Instantiate and run the new scanner
    scanner = Scanner(target_path=target_path)
    scanner.scan()  # This does everything

    # 2. Get results back from the scanner's DB instance
    #    (We need to fetch them for reporting)
    scan_id = scanner.scan_id
    results_list_of_dicts = scanner.db.get_vulnerabilities_for_scan(scan_id)

    num_vulns = len(results_list_of_dicts)
    num_files = scanner.num_files_analyzed
    scan_duration = scanner.scan_duration

    click.echo(
        f"Scan completed: {num_files} files analyzed, {num_vulns} vulnerabilities found in {scan_duration:.2f} seconds."
    )

    # 3. Reporting logic (now works with 'results_list_of_dicts')
    if export:
        project_name = scanner.db.project_name  # Get sanitized name
        out_file = output if output else f"{project_name}_scan_{scan_id}.{export}"

        if export == "sarif":
            reporter = SARIFReport()
            report_content = reporter.generate(results_list_of_dicts)
            with open(out_file, "w") as f:
                f.write(report_content)
            click.echo(f"Results exported to {out_file}")

        elif export == "json":
            with open(out_file, "w") as f:
                json.dump(results_list_of_dicts, f, indent=2)
            click.echo(f"Results exported to {out_file}")

        elif export == "html":
            click.echo("HTML export not yet implemented.")

        elif export == "ascii":
            reporter = ASCIIReport()
            report_content = reporter.generate(results_list_of_dicts)
            if output:
                with open(out_file, "w") as f:
                    f.write(report_content)
                click.echo(f"Results exported to {out_file}")
            else:
                click.echo(report_content)
    else:
        # 4. Standard console output
        #    (Updated to use new dict keys and --show-trace)
        for res in results_list_of_dicts:
            output_line = (
                f"[{res.get('severity', 'N/A')}][{res.get('vuln_type')}] "
                f"{res.get('file')}:{res.get('line')} -> {res.get('match')}"
            )
            click.echo(output_line)

            if show_trace and res.get("trace"):
                click.echo("    Trace: " + " -> ".join(res["trace"]))


if __name__ == "__main__":
    main()
