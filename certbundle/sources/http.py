"""
HTTP download helpers used by IGTF and CRL sources.

Only HTTP and HTTPS URLs are accepted.  All other schemes (file://, ftp://,
gopher://, etc.) are rejected to prevent SSRF and local file-read issues.
"""

import logging
import os
import tempfile
import time
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Default timeouts and retry parameters
_CONNECT_TIMEOUT = 15   # seconds
_READ_TIMEOUT = 60      # seconds
_MAX_RETRIES = 3
_RETRY_BACKOFF = 2      # seconds (doubles each retry)
_MAX_CONTENT_MB = 200   # sanity cap

_ALLOWED_SCHEMES = frozenset(["http", "https"])


def _validate_url(url):
    # type: (str) -> None
    """Raise ValueError if *url* is not a plain HTTP(S) URL."""
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError("Unparseable URL {!r}: {}".format(url, exc))
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValueError(
            "Only http:// and https:// URLs are supported, got: {!r}".format(url)
        )
    if not parsed.netloc:
        raise ValueError("URL has no host: {!r}".format(url))


def download_to_bytes(
    url,                    # type: str
    verify_tls=True,        # type: bool
    timeout=None,           # type: Optional[tuple]
    max_bytes=None,         # type: Optional[int]
):
    # type: (...) -> bytes
    """
    Download *url* and return its content as bytes.

    Only HTTP and HTTPS URLs are accepted.
    Raises :exc:`ValueError` for unsupported schemes.
    Raises :exc:`IOError` on persistent download failure.
    """
    import requests  # lazy import — not required on all code paths

    _validate_url(url)

    if timeout is None:
        timeout = (_CONNECT_TIMEOUT, _READ_TIMEOUT)
    if max_bytes is None:
        max_bytes = _MAX_CONTENT_MB * 1024 * 1024

    last_exc = None
    delay = _RETRY_BACKOFF

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            logger.debug("Downloading %s (attempt %d/%d)", url, attempt, _MAX_RETRIES)
            resp = requests.get(
                url,
                timeout=timeout,
                verify=verify_tls,
                stream=True,
            )
            resp.raise_for_status()

            chunks = []
            total = 0
            for chunk in resp.iter_content(chunk_size=65536):
                total += len(chunk)
                if total > max_bytes:
                    raise IOError(
                        "Response from {} exceeds {} MB limit".format(
                            url, _MAX_CONTENT_MB
                        )
                    )
                chunks.append(chunk)
            data = b"".join(chunks)
            logger.debug("Downloaded %d bytes from %s", len(data), url)
            return data

        except (ValueError, IOError):
            raise  # don't retry on programmer/config errors
        except Exception as exc:
            last_exc = exc
            if attempt < _MAX_RETRIES:
                logger.warning(
                    "Download attempt %d/%d failed for %s: %s — retrying in %ds",
                    attempt, _MAX_RETRIES, url, exc, delay,
                )
                time.sleep(delay)
                delay *= 2

    raise IOError("Failed to download {} after {} attempts: {}".format(
        url, _MAX_RETRIES, last_exc
    ))


def download_to_file(
    url,                    # type: str
    dest_path,              # type: str
    verify_tls=True,        # type: bool
):
    # type: (...) -> None
    """Download *url* and write to *dest_path* atomically."""
    data = download_to_bytes(url, verify_tls=verify_tls)
    dest_dir = os.path.dirname(os.path.abspath(dest_path)) or "."
    fd, tmp = tempfile.mkstemp(dir=dest_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, dest_path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
