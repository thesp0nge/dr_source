# dr_source/core/scanner.py
from dr_source.core.detectors import DETECTORS


class Scanner:
    def __init__(self, codebase):
        self.codebase = codebase
        # Instantiate each detector once
        self.detectors = [detector() for detector in DETECTORS]

    def scan(self):
        all_results = []
        for file_obj in self.codebase.files:
            for detector in self.detectors:
                results = detector.detect(file_obj)
                if results:
                    all_results.extend(results)
        return all_results
