"""
Wi-Fi Nightmare - Logging Framework
Provides centralized logging for the entire application
"""

import logging
import sys
import os
from datetime import datetime
from config import SCRIPT_DIR

class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for console output"""
    
    COLORS = {
        'DEBUG': '\033[0;36m',    # Cyan
        'INFO': '\033[0;32m',     # Green
        'WARNING': '\033[0;33m',  # Yellow
        'ERROR': '\033[0;31m',    # Red
        'CRITICAL': '\033[1;31m', # Bold Red
    }
    RESET = '\033[0m'
    
    def format(self, record):
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logger(name="WiFiNightmare", level=logging.INFO, log_to_file=True):
    """
    Configure logging for the application
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_to_file: Whether to log to file
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Capture everything, filter at handler level
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler (INFO and above, with colors)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_formatter = ColoredFormatter(
        '%(levelname)s: %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (DEBUG and above, detailed)
    if log_to_file:
        log_dir = os.path.join(SCRIPT_DIR, "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(log_dir, f"wifi_nightmare_{timestamp}.log")
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Log the log file location
        logger.debug(f"Logging to file: {log_file}")
    
    return logger


# Global logger instance
logger = setup_logger()


def get_logger(name=None):
    """
    Get a logger instance
    
    Args:
        name: Optional logger name (uses default if None)
        
    Returns:
        Logger instance
    """
    if name:
        return logging.getLogger(f"WiFiNightmare.{name}")
    return logger
