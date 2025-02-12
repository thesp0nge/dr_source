# dr_source/core/detectors/base.py
class BaseDetector:
    def detect(self, file_object):
        """
        Given a file_object (with attributes path and content),
        returns a list of dictionaries with vulnerability details.
        """
        raise NotImplementedError(
            "The detect() method must be implemented in subclasses."
        )
