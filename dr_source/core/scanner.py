# dr_source/core/scanner.py
from concurrent.futures import ThreadPoolExecutor, as_completed
import click
from dr_source.core.detectors import DETECTORS


class Scanner:
    def __init__(self, codebase):
        self.codebase = codebase
        # Instantiate each detector once
        self.detectors = [detector() for detector in DETECTORS]

    def scan(self):
        results = []
        files = self.codebase.files
        with ThreadPoolExecutor() as executor:
            # Submit each file to be scanned in parallel
            future_to_file = {
                executor.submit(self.scan_file, file_obj): file_obj
                for file_obj in files
            }
            # Create a progress bar with total number of files
            with click.progressbar(
                length=len(future_to_file), label="Scanning files"
            ) as bar:
                for future in as_completed(future_to_file):
                    file_results = future.result()
                    if file_results:
                        results.extend(file_results)
                    bar.update(1)
        return results

    def scan_file(self, file_obj):
        file_results = []
        for detector in self.detectors:
            res = detector.detect(file_obj)
            if res:
                file_results.extend(res)
        return file_results
