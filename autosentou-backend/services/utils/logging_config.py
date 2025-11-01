"""
Centralized logging configuration for the automated pentesting tool.
Provides both console and file logging with appropriate formatting.
"""
import logging
import sys
from pathlib import Path
from datetime import datetime


def setup_logging(log_level=logging.INFO):
    """
    Configure application-wide logging with both console and file handlers.

    Args:
        log_level: The logging level (default: INFO)

    Returns:
        Configured root logger
    """
    # Create logs directory if it doesn't exist
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    # Create a timestamped log file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = logs_dir / f"pentest_{timestamp}.log"

    # Define log format with detailed information
    detailed_format = logging.Formatter(
        fmt='%(asctime)s | %(levelname)-8s | %(name)-30s | %(funcName)-25s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Simpler format for console output
    console_format = logging.Formatter(
        fmt='[%(asctime)s] %(levelname)-8s | %(name)-20s | %(message)s',
        datefmt='%H:%M:%S'
    )

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove any existing handlers
    root_logger.handlers.clear()

    # Create console handler (outputs to terminal)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_format)

    # Create file handler (outputs to file)
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)  # File gets all messages
    file_handler.setFormatter(detailed_format)

    # Add handlers to root logger
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # Log initial message
    root_logger.info("="*80)
    root_logger.info(f"Logging system initialized - Log file: {log_file}")
    root_logger.info("="*80)

    return root_logger


def get_logger(name: str):
    """
    Get a logger instance for a specific module.

    Args:
        name: Name of the module (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


# Create a default logger for the application
def configure_app_logging():
    """Configure logging for the entire application on startup."""
    logger = setup_logging(log_level=logging.INFO)

    # Reduce noise from third-party libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('httpcore').setLevel(logging.WARNING)

    return logger
