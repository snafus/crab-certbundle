"""
HTTP download helpers used by IGTF and CRL sources.

Only HTTP and HTTPS URLs are accepted.  All other schemes (file://, ftp://,
gopher://, etc.) are rejected to prevent SSRF and local file-read issues.
"""

import hashlib
import json
import logging
import os
import tempfile
import time
from typing import Optional, Tuple
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


# ---------------------------------------------------------------------------
# Cache-aware download
# ---------------------------------------------------------------------------

def _cache_paths(url, cache_dir):
    # type: (str, str) -> Tuple[str, str]
    """Return *(data_path, meta_path)* for a cached URL inside *cache_dir*.

    The filename is derived from the last path component of the URL plus an
    8-character SHA-256 prefix of the full URL so that two URLs with the same
    basename don't collide.
    """
    parsed = urlparse(url)
    basename = os.path.basename(parsed.path) or "bundle"
    stem = os.path.splitext(basename)[0]
    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]
    name = "{}-{}".format(stem, url_hash)
    return (
        os.path.join(cache_dir, name + ".tar.gz"),
        os.path.join(cache_dir, name + ".meta"),
    )


def _evict_stale_cache(cache_dir, keep_path, ttl_days):
    # type: (str, str, int) -> None
    """Delete ``*.tar.gz`` cache files (and their ``.meta`` sidecars) in
    *cache_dir* that are older than *ttl_days*, excluding *keep_path*."""
    cutoff = time.time() - ttl_days * 86400
    try:
        for name in os.listdir(cache_dir):
            if not name.endswith(".tar.gz"):
                continue
            full = os.path.join(cache_dir, name)
            if os.path.abspath(full) == os.path.abspath(keep_path):
                continue
            try:
                if os.path.getmtime(full) < cutoff:
                    os.unlink(full)
                    meta = full[:-len(".tar.gz")] + ".meta"
                    if os.path.isfile(meta):
                        os.unlink(meta)
                    logger.debug("Evicted stale cache file: %s", full)
            except OSError as exc:
                logger.debug("Could not evict %s: %s", full, exc)
    except OSError as exc:
        logger.debug("Could not scan cache dir for eviction: %s", exc)


def download_with_cache(
    url,                    # type: str
    cache_dir,              # type: str
    verify_tls=True,        # type: bool
    cache_ttl_days=30,      # type: int
    cache_pinned=False,     # type: bool
):
    # type: (...) -> bytes
    """
    Download *url* into *cache_dir*, using a conditional GET on repeat calls.

    Behaviour:
    - **First call**: downloads and stores the tarball in *cache_dir* along
      with a JSON sidecar recording the ETag / Last-Modified response headers.
    - **Subsequent calls**: sends ``If-None-Match`` / ``If-Modified-Since``
      request headers; if the server replies 304 Not Modified, the cached copy
      is returned immediately without re-reading the body.
    - **Network failure with cached copy**: emits a WARNING and returns the
      cached copy, allowing offline and air-gapped rebuilds to succeed.
    - **Network failure without cached copy**: raises :exc:`IOError`.

    Parameters:
        cache_ttl_days: Delete cache files in *cache_dir* older than this many
            days when a new version is written.  Set to 0 to disable eviction.
            Default: 30.
        cache_pinned: If ``True`` and a cached copy already exists, return it
            immediately without any network request.  Useful for air-gapped
            sites that manually populate *cache_dir*, or for reproducible
            builds locked to a specific version.  Default: ``False``.

    Raises :exc:`ValueError` for non-HTTP(S) URLs (same as
    :func:`download_to_bytes`).
    """
    import requests  # lazy import

    _validate_url(url)

    data_path, meta_path = _cache_paths(url, cache_dir)

    # Pinned mode: return cached copy immediately, no network contact
    if cache_pinned and os.path.isfile(data_path):
        logger.debug("Pinned — using cached copy without network check: %s", data_path)
        with open(data_path, "rb") as fh:
            return fh.read()

    # Load existing cache metadata (ETag / Last-Modified)
    meta = {}  # type: dict
    if os.path.isfile(meta_path) and os.path.isfile(data_path):
        try:
            with open(meta_path, "r") as fh:
                meta = json.load(fh)
        except Exception as exc:
            logger.debug("Could not read cache metadata %s: %s", meta_path, exc)

    # Build conditional request headers
    req_headers = {}
    if meta.get("etag"):
        req_headers["If-None-Match"] = meta["etag"]
    if meta.get("last_modified"):
        req_headers["If-Modified-Since"] = meta["last_modified"]

    timeout = (_CONNECT_TIMEOUT, _READ_TIMEOUT)
    max_bytes = _MAX_CONTENT_MB * 1024 * 1024

    try:
        logger.debug("Fetching %s (conditional=%s)", url, bool(req_headers))
        resp = requests.get(
            url,
            headers=req_headers,
            timeout=timeout,
            verify=verify_tls,
            stream=True,
        )

        if resp.status_code == 304:
            logger.debug("304 Not Modified — using cached copy: %s", data_path)
            with open(data_path, "rb") as fh:
                return fh.read()

        resp.raise_for_status()

        # Stream body with size cap
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            total += len(chunk)
            if total > max_bytes:
                raise IOError(
                    "Response from {} exceeds {} MB limit".format(url, _MAX_CONTENT_MB)
                )
            chunks.append(chunk)
        data = b"".join(chunks)

        # Persist to cache atomically; log but don't fail if we can't write
        try:
            os.makedirs(cache_dir, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                dir=os.path.abspath(cache_dir), suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                os.replace(tmp, data_path)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            # Write metadata sidecar
            new_meta = {"url": url}
            if resp.headers.get("ETag"):
                new_meta["etag"] = resp.headers["ETag"]
            if resp.headers.get("Last-Modified"):
                new_meta["last_modified"] = resp.headers["Last-Modified"]
            with open(meta_path, "w") as fh:
                json.dump(new_meta, fh)
            # Evict old cache files for superseded versions
            if cache_ttl_days > 0:
                _evict_stale_cache(cache_dir, data_path, cache_ttl_days)
        except Exception as exc:
            logger.warning("Could not write cache for %s: %s", url, exc)

        logger.debug("Downloaded %d bytes from %s", len(data), url)
        return data

    except (ValueError, IOError):
        raise
    except Exception as exc:
        # Network / server error — fall back to cached copy if one exists
        if os.path.isfile(data_path):
            logger.warning(
                "Download failed for %s (%s); using cached copy from %s",
                url, exc, data_path,
            )
            with open(data_path, "rb") as fh:
                return fh.read()
        raise IOError("Failed to download {}: {}".format(url, exc))
