# dr_source/core/scanner.py
from concurrent.futures import ThreadPoolExecutor, as_completed
import click
import javalang
from dr_source.core.detectors import DETECTORS


class Scanner:
    def __init__(self, codebase, ast_mode=False):
        self.codebase = codebase
        self.ast_mode = ast_mode
        # Instantiate each detector once
        self.detectors = [detector() for detector in DETECTORS]

    def scan(self):
        results = []
        files = self.codebase.files
        with ThreadPoolExecutor() as executor:
            future_to_file = {
                executor.submit(self.scan_file, file_obj): file_obj
                for file_obj in files
            }
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
        ast_tree = None
        if self.ast_mode and file_obj.path.endswith(".java"):
            try:
                ast_tree = javalang.parse.parse(file_obj.content)
            except Exception as e:
                ast_tree = None
        for detector in self.detectors:
            if (
                self.ast_mode
                and hasattr(detector, "detect_ast_from_tree")
                and ast_tree is not None
            ):
                file_results.extend(detector.detect_ast_from_tree(file_obj, ast_tree))
            else:
                file_results.extend(detector.detect(file_obj))
        return file_results
