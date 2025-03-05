import os
import yaml
import logging

logger = logging.getLogger(__name__)


class DetectionRules:
    _instance = None

    def __init__(self):
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "detection_rules.yaml"
        )
        self.rules = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    self.rules = yaml.safe_load(f)
                    logger.debug(
                        "Detection rules loaded successfully from %s", config_path
                    )
            except Exception as e:
                logger.error(
                    "Error loading detection rules from %s: %s", config_path, e
                )
        else:
            logger.warning("Detection rules file not found: %s", config_path)

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = DetectionRules()
        return cls._instance

    def get_rules(self, detector_key):
        return self.rules.get(detector_key, {})
