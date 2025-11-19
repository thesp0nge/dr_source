import os
import logging
import time
import importlib.metadata
from typing import List, Dict, Callable
from tqdm import tqdm

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.db import ScanDatabase

logger = logging.getLogger(__name__)


class Scanner:
    """
    The main orchestrator. Scans a codebase by loading and
    running all registered analyzer plugins.
    """

    def __init__(self, target_path: str):
        self.target_path = target_path
        # Use the target_path to initialize the database
        # This reuses your existing sanitization logic in the DB class
        self.db = ScanDatabase(project_name=target_path)

        # This will hold { ".java": [JavaPlugin], ".*": [RegexPlugin], ... }
        self.extension_map: Dict[str, List[AnalyzerPlugin]] = {}

        self.scan_id: int = -1
        self.num_files_analyzed: int = 0
        self.scan_duration: float = 0.0
        self.all_findings: List[Vulnerability] = []

        self.load_plugins()

    def load_plugins(self):
        """
        Discovers and loads all plugins registered under
        the 'dr_source.plugins' entry point.
        """
        logger.info("Loading analyzer plugins...")

        try:
            entry_points = importlib.metadata.entry_points(group="dr_source.plugins")
        except Exception as e:
            logger.error(f"Error loading entry points: {e}")
            entry_points = []

        for ep in entry_points:
            try:
                plugin_class = ep.load()
                plugin_instance: AnalyzerPlugin = plugin_class()

                logger.info(f"  - Loaded plugin: {plugin_instance.name}")

                for ext in plugin_instance.get_supported_extensions():
                    if ext not in self.extension_map:
                        self.extension_map[ext] = []
                    self.extension_map[ext].append(plugin_instance)

            except Exception as e:
                logger.error(f"Failed to load plugin {ep.name}: {e}")

    def scan(self):
        """
        Walks the target directory, delegates files to plugins,
        and saves all results to the database.
        """
        logger.info(f"Starting scan on: {self.target_path}")

        self.scan_id = self.db.start_scan()
        start_time = time.time()

        all_findings_dataclass: List[Vulnerability] = []

        # 1. Collection Phase: Find all files that have at least one plugin
        logger.info("Collecting files to scan...")
        files_to_scan = []
        for root, _, files in os.walk(self.target_path):
            for file in files:
                _, ext = os.path.splitext(file)

                # Check if we have specific plugins OR a catch-all plugin (like regex)
                # This filtering ensures the progress bar count is accurate
                plugins = self.extension_map.get(ext, []) + self.extension_map.get(
                    ".*", []
                )

                if plugins:
                    files_to_scan.append(os.path.join(root, file))

        # 2. Analysis Phase: Iterate with Progress Bar
        #    tqdm wraps the list and handles the UI automatically
        for file_path in tqdm(files_to_scan, desc="Analyzing files", unit="file"):
            _, ext = os.path.splitext(file_path)

            # Re-fetch plugins (fast)
            plugins_to_run = self.extension_map.get(ext, [])
            plugins_to_run.extend(self.extension_map.get(".*", []))

            for plugin in plugins_to_run:
                try:
                    findings = plugin.analyze(file_path)
                    all_findings_dataclass.extend(findings)
                except Exception as e:
                    # Log to file/stderr so it doesn't break the progress bar
                    logger.error(f"Plugin {plugin.name} failed on {file_path}: {e}")

        # 3. Save Results
        all_findings_dict = []
        for vuln in all_findings_dataclass:
            all_findings_dict.append(
                {
                    "file": vuln.file_path,
                    "vuln_type": vuln.vulnerability_type,
                    "match": vuln.message,
                    "line": vuln.line_number,
                    "severity": vuln.severity,
                    "plugin_name": vuln.plugin_name,
                    "trace": " -> ".join(vuln.trace),
                }
            )

        if all_findings_dict:
            try:
                self.db.store_vulnerabilities(self.scan_id, all_findings_dict)
            except Exception as e:
                logger.error(f"Failed to store vulnerabilities in database: {e}")

        scan_duration = time.time() - start_time

        self.num_files_analyzed = len(files_to_scan)
        self.scan_duration = scan_duration
        self.all_findings = all_findings_dataclass

        self.db.update_scan_summary(
            self.scan_id,
            num_vulnerabilities=len(all_findings_dict),
            num_files_analyzed=self.num_files_analyzed,
            scan_duration=self.scan_duration,
        )
