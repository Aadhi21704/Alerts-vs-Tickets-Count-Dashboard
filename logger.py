import logging

from pathlib import Path

from logging.handlers import (
    RotatingFileHandler
)

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

handler = RotatingFileHandler(
    "logs/dashboard.log",
    maxBytes=5 * 1024 * 1024,
    backupCount=3
)

formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s"
)

handler.setFormatter(formatter)

logger = logging.getLogger("dashboard")

logger.setLevel(logging.INFO)

logger.addHandler(handler)