"""
Log formatters for crabctl.

Two formats are supported:
  text   — human-readable ``LEVEL  logger: message`` lines (default)
  json   — one JSON object per line, suitable for Loki / Splunk / ECS ingest
"""

import datetime
import json
import logging

TEXT_FORMAT = "%(levelname)s  %(name)s: %(message)s"
TEXT_FORMAT_WITH_TIME = "%(asctime)s  %(levelname)s  %(name)s: %(message)s"


class JsonFormatter(logging.Formatter):
    """
    Emit each log record as a single-line JSON object.

    Output fields:
      timestamp   ISO-8601 UTC with milliseconds, e.g. ``2026-04-16T04:00:01.234Z``
      level       ``DEBUG`` / ``INFO`` / ``WARNING`` / ``ERROR`` / ``CRITICAL``
      logger      Logger name (e.g. ``crab.crl``)
      message     Formatted log message
      exception   Formatted traceback (only present when exc_info is set)
    """

    def format(self, record):
        # type: (logging.LogRecord) -> str
        ts = (
            datetime.datetime.utcfromtimestamp(record.created)
            .strftime("%Y-%m-%dT%H:%M:%S")
            + ".{:03d}Z".format(int(record.msecs))
        )
        obj = {
            "timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(obj, ensure_ascii=False)


def make_formatter(fmt, with_time=False):
    # type: (str, bool) -> logging.Formatter
    """
    Return a :class:`logging.Formatter` for the given format name.

    :param fmt: ``"text"`` or ``"json"``
    :param with_time: For text format, prepend a timestamp.  Ignored for JSON
        (JSON always includes a timestamp).
    """
    if fmt == "json":
        return JsonFormatter()
    if with_time:
        return logging.Formatter(TEXT_FORMAT_WITH_TIME)
    return logging.Formatter(TEXT_FORMAT)
