
import copy
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


class PrivateRotatingFileHandler(RotatingFileHandler):
    def _open(self):
        fd = os.open(
            self.baseFilename,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        try:
            os.fchmod(fd, 0o600)
            return os.fdopen(
                fd,
                self.mode,
                encoding=self.encoding,
                errors=self.errors,
            )
        except BaseException:
            os.close(fd)
            raise

    def handleError(self, record):
        try:
            print(
                "logging: failed to write log file",
                file=sys.stderr,
            )
        except OSError:
            pass


class PrettyFormatter(logging.Formatter):
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"

    COLORS = {
        logging.DEBUG: "\033[38;5;245m",
        logging.INFO: "\033[38;5;82m",
        logging.WARNING: "\033[38;5;214m",
        logging.ERROR: "\033[38;5;203m",
        logging.CRITICAL: "\033[38;5;199m",
    }

    LABELS = {
        logging.DEBUG: "DBG",
        logging.INFO: "INF",
        logging.WARNING: "WRN",
        logging.ERROR: "ERR",
        logging.CRITICAL: "CRT",
    }

    def __init__(self, use_color=False, include_date=False):
        super().__init__()
        self.use_color = use_color
        self.datefmt = (
            "%Y-%m-%d %H:%M:%S"
            if include_date
            else "%H:%M:%S"
        )

    def format(self, record):
        record = copy.copy(record)

        timestamp = self.formatTime(record, self.datefmt)
        timestamp += f".{record.msecs:03.0f}"

        level = self.LABELS.get(
            record.levelno,
            record.levelname[:5].upper().ljust(5),
        )

        message = record.getMessage()

        if self.use_color:
            color = self.COLORS.get(record.levelno, "")
            timestamp = f"{self.DIM}{timestamp}{self.RESET}"
            level = f"{color}{self.BOLD}{level}{self.RESET}"
            separator = f"{self.DIM}│{self.RESET}"
        else:
            separator = "│"

        output = f"{timestamp}  {level} {separator} {message}"

        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
            output += "\n" + record.exc_text

        if record.stack_info:
            output += "\n" + self.formatStack(record.stack_info)

        return output


def configure_logging(log_file=None, level=logging.INFO):
    logger = logging.getLogger("remnawave")

    handlers = []

    # Console
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(
        PrettyFormatter(
            use_color=(
                sys.stderr.isatty()
                and "NO_COLOR" not in os.environ
            )
        )
    )
    handlers.append(console)

    # Private rotating log file
    if log_file is not None:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = PrivateRotatingFileHandler(
            path,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )

        file_handler.setFormatter(
            PrettyFormatter(include_date=True)
        )

        handlers.append(file_handler)

    # Replace existing handlers
    for old in logger.handlers[:]:
        logger.removeHandler(old)
        old.close()

    for handler in handlers:
        logger.addHandler(handler)

    logger.setLevel(level)
    logger.propagate = False

    return logger

