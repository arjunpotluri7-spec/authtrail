"""Structured logging to stderr (reports go to stdout or --output, never mixed with logs)."""

import json
import logging
import sys
from datetime import UTC, datetime

LOGGER_NAME = "authtrail"
_STANDARD_ATTRS = frozenset(vars(logging.LogRecord("x", 0, "x", 0, "x", None, None))) | {
    "message",
    "asctime",
}


def _extra_fields(record: logging.LogRecord) -> dict[str, object]:
    return {
        key: value
        for key, value in record.__dict__.items()
        if key not in _STANDARD_ATTRS and not key.startswith("_")
    }


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ts, level, logger, msg, plus any ``extra`` fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        payload.update(_extra_fields(record))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, sort_keys=False)


class TextFormatter(logging.Formatter):
    """``LEVEL message key=value ...`` for humans."""

    def format(self, record: logging.LogRecord) -> str:
        fields = " ".join(f"{k}={v}" for k, v in _extra_fields(record).items())
        line = f"{record.levelname} {record.getMessage()}"
        return f"{line} {fields}" if fields else line


def setup_logging(level: str = "WARNING", fmt: str = "text") -> logging.Logger:
    """Configure the ``authtrail`` logger to write to the current stderr."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    """Child logger under ``authtrail``."""
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
