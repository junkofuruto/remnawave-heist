import copy
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


class PrivateRotatingFileHandler(RotatingFileHandler):
    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.fchmod(fd, 0o600)
            return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)
        except BaseException:
            os.close(fd)
            raise

    def handleError(self, record):
        # Do not let logging's default traceback print record contents.
        try:
            print("error: could not write log file", file=sys.stderr)
        except OSError:
            pass


class PrettyFormatter(logging.Formatter):
    LEVELS = {
        logging.DEBUG: "DBG",
        logging.INFO: "INF",
        logging.WARNING: "WRN",
        logging.ERROR: "ERR",
        logging.CRITICAL: "CRT",
    }
    BACKGROUNDS = {
        logging.DEBUG: "\033[30;46m",
        logging.INFO: "\033[30;42m",
        logging.WARNING: "\033[30;43m",
        logging.ERROR: "\033[97;41m",
        logging.CRITICAL: "\033[97;45m",
    }
    RESET = "\033[0m"

    def __init__(self, use_color=False, include_date=False):
        datefmt = "%Y-%m-%d %H:%M:%S" if include_date else "%H:%M:%S"
        super().__init__("[%(shortlevel)s] %(asctime)s.%(msecs)03d | %(message)s", datefmt=datefmt)
        self.use_color = use_color

    def format(self, record):
        formatted_record = copy.copy(record)
        formatted_record.shortlevel = self.LEVELS.get(record.levelno, record.levelname[:3].upper())
        message = super().format(formatted_record)
        color = self.BACKGROUNDS.get(record.levelno)
        if self.use_color and color:
            badge = f"[{formatted_record.shortlevel}]"
            message = f"{color}{badge}{self.RESET}" + message[len(badge):]
        return message


def configure_logging(log_file=None):
    logger = logging.getLogger("remnawave")
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(PrettyFormatter(use_color=sys.stderr.isatty() and "NO_COLOR" not in os.environ))
    handlers = [console]
    if log_file is not None:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = PrivateRotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
        file_handler.setFormatter(PrettyFormatter(include_date=True))
        handlers.append(file_handler)
    for old in logger.handlers[:]:
        logger.removeHandler(old)
        old.close()
    for handler in handlers:
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
