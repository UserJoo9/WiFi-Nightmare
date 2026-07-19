import logging
import sys
import os
from logging.handlers import RotatingFileHandler
from wifi_nightmare.config import LOG_FILE


class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[0;36m',
        'INFO': '\033[0;32m',
        'WARNING': '\033[0;33m',
        'ERROR': '\033[0;31m',
        'CRITICAL': '\033[1;31m',
    }
    RESET = '\033[0m'

    def format(self, record):
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logger(name="WiFiNightmare", level=logging.INFO, log_to_file=True):
    lg = logging.getLogger(name)
    lg.setLevel(logging.DEBUG)

    if lg.handlers:
        return lg

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(ColoredFormatter('%(levelname)s: %(message)s'))
    lg.addHandler(console_handler)

    if log_to_file:
        log_dir = os.path.dirname(LOG_FILE)
        os.makedirs(log_dir, exist_ok=True)

        log_file = LOG_FILE
        file_handler = RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=5, encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        lg.addHandler(file_handler)
        lg.debug(f"Logging to file: {log_file}")

    return lg


logger = setup_logger()


def get_logger(name=None):
    if name:
        return logging.getLogger(f"WiFiNightmare.{name}")
    return logger
