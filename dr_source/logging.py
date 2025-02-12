import logging
import sys


def setup_logging(debug=False):
    logger = logging.getLogger()
    # Set log level to DEBUG if debug flag is True; otherwise, INFO.
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger


# if __name__ == "__main__":
#     setup_logging(debug=True)
#     logging.debug("Logging configured correctly.")
