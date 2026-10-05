"""
Log setup shared by the services.

Two formats, chosen with the LOG_FORMAT environment variable:

    text  (default) one readable line per event, for a developer's terminal
    json  one JSON object per line, for containers and log collectors

JSON lines can be filtered by field instead of by text search, for example
every failed handshake, or every reading from one device:

    docker compose logs gateway | jq 'select(.event == "handshake_failed")'

Fields passed with logging's `extra=` argument become top-level JSON keys, so
call sites attach facts as data rather than only inside the message text:

    log.info("forwarded %s", device, extra={"event": "forwarded",
                                            "device_id": device})

Only the standard library is used, so this adds no dependency to either
service.
"""

import json
import logging
import os
import sys
from datetime import UTC, datetime

# Attributes every LogRecord has. Anything else on a record came from extra=.
_STANDARD_ATTRS = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}

TEXT_FORMAT = "%(asctime)s %(name)s %(levelname)s %(message)s"


class JsonFormatter(logging.Formatter):
    """Formats each record as one JSON object on one line."""

    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="milliseconds"),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and key not in entry:
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        # default=str: an unexpected value type in extra= must never make a
        # log call raise. Losing a log line is better than losing a reading.
        return json.dumps(entry, default=str)


def configure(service: str, log_format: str | None = None,
              level: str | None = None, adopt: tuple[str, ...] = ()) -> None:
    """Send all log records to stderr in the chosen format.

    Configures the root logger, so the service's own loggers and those of its
    libraries share one format. Calling it again replaces the handler rather
    than adding a second one, so lines are never printed twice.

    Args:
        service: name written into every JSON line.
        log_format: "text" or "json"; defaults to $LOG_FORMAT, then "text".
        level: a logging level name; defaults to $LOG_LEVEL, then "INFO".
        adopt: names of library loggers that install their own handlers
            (uvicorn does). In JSON mode their handlers are removed and their
            records sent through ours, so one stream never mixes JSON and
            plain text lines, which a log collector could not parse.
    """
    log_format = (log_format or os.environ.get("LOG_FORMAT", "text")).lower()
    level = (level or os.environ.get("LOG_LEVEL", "INFO")).upper()

    handler = logging.StreamHandler(sys.stderr)
    handler.set_name("observability")
    if log_format == "json":
        handler.setFormatter(JsonFormatter(service))
    else:
        handler.setFormatter(logging.Formatter(TEXT_FORMAT))

    root = logging.getLogger()
    for existing in [h for h in root.handlers if h.get_name() == "observability"]:
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    if log_format == "json":
        for name in adopt:
            library_logger = logging.getLogger(name)
            library_logger.handlers.clear()
            library_logger.propagate = True
