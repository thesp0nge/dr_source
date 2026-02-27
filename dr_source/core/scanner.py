import os
import logging
import time
import importlib.metadata
from typing import List, Dict, Callable
from tqdm import tqdm

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.db import ScanDatabase
from dr_source.core.project_index import ProjectIndex
from dr_source.core.utils import timeout_session, TimeoutException

logger = logging.getLogger(__name__)


class Scanner:
    """
    The main orchestrator. Scans a codebase by loading and
    running all registered analyzer plugins.
    """

    def __init__(self, target_path: str, timeout: int = 0):
        self.target_path = target_path
        self.timeout = timeout
        self.db = ScanDatabase(project_name=target_path)
        self.project_index = ProjectIndex()

        # This will hold { ".java": [JavaPlugin], ".*": [RegexPlugin], ... }
        self.extension_map: Dict[str, List[AnalyzerPlugin]] = {}

        self.scan_id: int = -1
        self.num_files_analyzed: int = 0
        self.scan_duration: float = 0.0
        self.all_findings: List[Vulnerability] = []
        self.last_interrupt_time: float = 0.0

        self.load_plugins()
        logger.debug(f"Extension Map: {self.extension_map.keys()}")
        
        # Define common directories and file extensions to ignore
        self.ignored_dirs = [
            ".git", ".svn", ".hg", "__pycache__", "node_modules", "vendor",
            "dist", "build", "target", "out", "bin", "tmp", "temp", "log",
            "test-output", "report", "results" # Added 'results' based on previous observation
        ]
        self.ignored_extensions = [
            ".log", ".tmp", ".temp", ".bak", ".swp", ".class", ".jar", ".war",
            ".ear", ".dll", ".exe", ".o", ".so", ".obj", ".pyc", ".pyo",
            ".iml", ".ipr", ".iws", ".md", ".txt", ".json", ".xml", ".yaml", ".yml"
        ]

    def load_plugins(self):
        """
        Discovers and loads all plugins registered under
        the 'dr_source.plugins' entry point.
        """
        logger.debug("Loading analyzer plugins...")

        try:
            entry_points = importlib.metadata.entry_points(group="dr_source.plugins")
        except Exception as e:
            logger.error(f"Error loading entry points: {e}")
            entry_points = []

        for ep in entry_points:
            try:
                plugin_class = ep.load()
                plugin_instance: AnalyzerPlugin = plugin_class()

                logger.debug(f"  - Loaded plugin: {plugin_instance.name}")

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
        logger.debug(f"Starting scan on: {self.target_path}")

        self.scan_id = self.db.start_scan()
        start_time = time.time()

        all_findings_dataclass: List[Vulnerability] = []

        # 1. Collection Phase: Find all files that have at least one plugin
        logger.debug("Collecting files to scan...")
        files_to_scan = []

        if os.path.isfile(self.target_path):
            file = os.path.basename(self.target_path)
            # Skip ignored file extensions
            if not any(file.endswith(ext) for ext in self.ignored_extensions):
                _, ext = os.path.splitext(file)
                plugins = self.extension_map.get(ext, []) + self.extension_map.get(".*", [])
                if plugins:
                    files_to_scan.append(self.target_path)
        elif os.path.isdir(self.target_path):
            for root, dirs, files in os.walk(self.target_path):
                for file in files:
                    # Skip ignored directories
                    for ignored_dir in self.ignored_dirs:
                        if ignored_dir in root:
                            continue # Skip to next file
                    
                    # Skip ignored file extensions
                    if any(file.endswith(ext) for ext in self.ignored_extensions):
                        continue # Skip to next file

                    _, ext = os.path.splitext(file)

                    # Check if we have specific plugins OR a catch-all plugin (like regex)
                    # This filtering ensures the progress bar count is accurate
                    plugins = self.extension_map.get(ext, []) + self.extension_map.get(
                        ".*", []
                    )

                    if plugins:
                        files_to_scan.append(os.path.join(root, file))
        else:
            logger.warning(f"Target path '{self.target_path}' is neither a file nor a directory. Skipping scan.")

        logger.debug(f"Files to scan: {files_to_scan}")

        # 1.5 Indexing Phase: Collect global symbols across all files
        for file_path in tqdm(files_to_scan, desc="Indexing project", unit="file"):
            _, ext = os.path.splitext(file_path)
            plugins = self.extension_map.get(ext, []) + self.extension_map.get(".*", [])
            
            try:
                with timeout_session(self.timeout):
                    for plugin in plugins:
                        try:
                            plugin.index(file_path, self.project_index)
                        except TimeoutException:
                            raise
                        except Exception as e:
                            logger.error(f"Indexing failed for {plugin.name} on {file_path}: {e}")
            except TimeoutException:
                logger.error(f"Indexing timed out for {file_path} after {self.timeout} seconds. Skipping file.")
                continue
            except KeyboardInterrupt:
                current_time = time.time()
                if current_time - self.last_interrupt_time < 2:
                    logger.warning("\nDouble Ctrl+C detected. Aborting scan...")
                    raise
                self.last_interrupt_time = current_time
                logger.warning(f"\nIndexing interrupted by user for {file_path}. Skipping to next file... (Press Ctrl+C again to abort)")
                continue

        # 2. Analysis Phase: Iterate with Progress Bar
        for file_path in tqdm(files_to_scan, desc="Analyzing files", unit="file"):
            _, ext = os.path.splitext(file_path)

            # Re-fetch plugins (fast)
            plugins_to_run = self.extension_map.get(ext, [])
            plugins_to_run.extend(self.extension_map.get(".*", []))

            try:
                with timeout_session(self.timeout):
                    for plugin in plugins_to_run:
                        try:
                            # Pass the project index to the plugin if it supports it
                            if hasattr(plugin, 'project_index'):
                                plugin.project_index = self.project_index
                            
                            findings = plugin.analyze(file_path)
                            all_findings_dataclass.extend(findings)
                        except TimeoutException:
                            raise
                        except Exception as e:
                            # Log to file/stderr so it doesn't break the progress bar
                            logger.error(f"Plugin {plugin.name} failed on {file_path}: {e}")
            except TimeoutException:
                logger.error(f"Analysis timed out for {file_path} after {self.timeout} seconds. Skipping file.")
                continue
            except KeyboardInterrupt:
                current_time = time.time()
                if current_time - self.last_interrupt_time < 2:
                    logger.warning("\nDouble Ctrl+C detected. Aborting scan...")
                    raise
                self.last_interrupt_time = current_time
                logger.warning(f"\nAnalysis interrupted by user for {file_path}. Skipping to next file... (Press Ctrl+C again to abort)")
                continue

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
