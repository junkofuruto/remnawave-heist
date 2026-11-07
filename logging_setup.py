import copy
import logging
import os
import sys


class PrettyFormatter(logging.Formatter):
    LEVELS = {
        logging.DEBUG: "DBG",
        logging.INFO: "INF",
        logging.WARNING: "WRN",
        logging.ERROR: "ERR",
        logging.CRITICAL: "CRT",
    }
    COLORS = {
        logging.DEBUG: "\033[36m",
        logging.INFO: "\033[32m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[1;31m",
    }
    RESET = "\033[0m"

    def __init__(self, use_color=False):
        super().__init__("[%(shortlevel)s] %(asctime)s.%(msecs)03d | %(message)s", datefmt="%H:%M:%S")
        self.use_color = use_color

    def format(self, record):
        formatted_record = copy.copy(record)
        formatted_record.shortlevel = self.LEVELS.get(record.levelno, record.levelname[:3].upper())
        message = super().format(formatted_record)
        color = self.COLORS.get(record.levelno)
        return f"{color}{message}{self.RESET}" if self.use_color and color else message


def configure_logging():
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(PrettyFormatter(use_color=sys.stderr.isatty() and "NO_COLOR" not in os.environ))
    logger = logging.getLogger("remnawave")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
