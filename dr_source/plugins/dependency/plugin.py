import os
import json
import logging
import subprocess
import shutil
import urllib.request
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

from dr_source.api import AnalyzerPlugin, Vulnerability, Severity

logger = logging.getLogger(__name__)


class DependencyAnalyzer(AnalyzerPlugin):
    """
    Scans dependency definition files for known vulnerabilities.
    - Python: requirements.txt (via pip-audit)
    - Java: pom.xml (via OSV API)
    """

    @property
    def name(self) -> str:
        return "Dependency Analyzer"

    def get_supported_extensions(self) -> List[str]:
        return [".txt", ".xml"]

    def analyze(self, file_path: str) -> List[Vulnerability]:
        filename = os.path.basename(file_path)

        if filename == "requirements.txt":
            return self._scan_pip_requirements(file_path)
        elif filename == "pom.xml":
            return self._scan_maven_pom(file_path)

        return []

    def _scan_pip_requirements(self, file_path: str) -> List[Vulnerability]:
        findings = []
        if not shutil.which("pip-audit"):
            logger.warning("pip-audit not found. Skipping python dependency scan.")
            return []

        try:
            cmd = [
                "pip-audit",
                "-r",
                file_path,
                "-f",
                "json",
                "--progress-spinner",
                "off",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    deps = (
                        data if isinstance(data, list) else data.get("dependencies", [])
                    )

                    for dep in deps:
                        if "vulns" in dep and dep["vulns"]:
                            for v in dep["vulns"]:
                                findings.append(
                                    Vulnerability(
                                        vulnerability_type="VULNERABLE_DEPENDENCY",
                                        # --- FIX: Use standard package==version format ---
                                        message=f"Dependency {dep['name']}=={dep.get('version', '?')} has vulnerability {v['id']}: {v.get('description', 'No description')}",
                                        # --- END FIX ---
                                        severity="HIGH",
                                        file_path=file_path,
                                        line_number=1,
                                        plugin_name=self.name,
                                    )
                                )
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse pip-audit output for {file_path}")
        except Exception as e:
            logger.error(f"Dependency analysis failed for {file_path}: {e}")

        return findings

    def _scan_maven_pom(self, file_path: str) -> List[Vulnerability]:
        findings = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Handle XML Namespaces (Maven POMs usually have one)
            ns = {}
            if root.tag.startswith("{"):
                uri = root.tag.split("}")[0].strip("{")
                ns = {"mvn": uri}

            # Find all dependencies
            dep_path = (
                "mvn:dependencies/mvn:dependency" if ns else "dependencies/dependency"
            )

            for dep in root.findall(dep_path, ns):
                group_id = dep.find("mvn:groupId" if ns else "groupId", ns)
                artifact_id = dep.find("mvn:artifactId" if ns else "artifactId", ns)
                version = dep.find("mvn:version" if ns else "version", ns)

                if (
                    group_id is not None
                    and artifact_id is not None
                    and version is not None
                ):
                    g = group_id.text
                    a = artifact_id.text
                    v = version.text

                    # Query OSV
                    vulns = self._query_osv_maven(g, a, v)

                    for vuln in vulns:
                        findings.append(
                            Vulnerability(
                                vulnerability_type="VULNERABLE_DEPENDENCY",
                                message=f"Maven package '{g}:{a}' version {v} has vulnerability {vuln['id']}: {vuln.get('summary', 'No summary')}",
                                severity="HIGH",
                                file_path=file_path,
                                line_number=1,
                                plugin_name=self.name,
                            )
                        )

        except ET.ParseError:
            logger.error(f"Failed to parse XML file: {file_path}")
        except Exception as e:
            logger.error(f"Error scanning POM file {file_path}: {e}")

        return findings

    def _query_osv_maven(self, group_id, artifact_id, version) -> List[Dict]:
        """
        Queries the OSV API for vulnerabilities in a Maven package.
        """
        url = "https://api.osv.dev/v1/query"
        purl = f"pkg:maven/{group_id}/{artifact_id}@{version}"

        payload = {"package": {"purl": purl}}
        data = json.dumps(payload).encode("utf-8")

        try:
            req = urllib.request.Request(
                url, data=data, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    result = json.loads(response.read().decode())
                    return result.get("vulns", [])
        except Exception as e:
            logger.warning(f"OSV API request failed for {purl}: {e}")

        return []
