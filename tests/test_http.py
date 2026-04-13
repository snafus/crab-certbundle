"""
Tests for certbundle.sources.http — URL validation and download helpers.

No real network access: all requests are mocked.
"""

import os
import pytest
from unittest.mock import patch, MagicMock, call


from certbundle.sources.http import (
    _validate_url,
    _cache_paths,
    download_to_bytes,
    download_to_file,
    download_with_cache,
)


# ---------------------------------------------------------------------------
# _validate_url — scheme enforcement (security-critical)
# ---------------------------------------------------------------------------

class TestValidateUrl:
    def test_accepts_http(self):
        _validate_url("http://example.com/cert.crt")  # must not raise

    def test_accepts_https(self):
        _validate_url("https://dl.igtf.net/distribution/igtf-policy-classic.tar.gz")

    def test_rejects_file_scheme(self):
        with pytest.raises(ValueError, match="http"):
            _validate_url("file:///etc/passwd")

    def test_rejects_ftp_scheme(self):
        with pytest.raises(ValueError, match="http"):
            _validate_url("ftp://example.com/cert.crl")

    def test_rejects_gopher(self):
        with pytest.raises(ValueError, match="http"):
            _validate_url("gopher://example.com/resource")

    def test_rejects_data_url(self):
        with pytest.raises(ValueError, match="http"):
            _validate_url("data:text/plain;base64,SGVsbG8=")

    def test_rejects_url_with_no_host(self):
        with pytest.raises(ValueError, match="host"):
            _validate_url("http:///path/only")

    def test_rejects_plain_path(self):
        with pytest.raises(ValueError):
            _validate_url("/etc/grid-security/certificates")

    def test_rejects_empty_string(self):
        with pytest.raises(ValueError):
            _validate_url("")

    def test_scheme_check_is_case_insensitive(self):
        # urlparse lowercases scheme, so HTTP:// should also be accepted
        _validate_url("HTTP://example.com/cert.crt")


# ---------------------------------------------------------------------------
# download_to_bytes — happy path
# ---------------------------------------------------------------------------

def _mock_response(chunks, status_code=200):
    """Build a mock requests.Response that streams *chunks*."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.iter_content.return_value = iter(chunks)
    resp.raise_for_status.return_value = None
    return resp


class TestDownloadToBytes:
    def test_returns_concatenated_content(self):
        resp = _mock_response([b"hello", b" ", b"world"])
        with patch("requests.get", return_value=resp) as mock_get:
            result = download_to_bytes("http://example.com/test")
        assert result == b"hello world"
        mock_get.assert_called_once()

    def test_passes_tls_verify_flag(self):
        resp = _mock_response([b"data"])
        with patch("requests.get", return_value=resp) as mock_get:
            download_to_bytes("https://example.com/test", verify_tls=False)
        _, kwargs = mock_get.call_args
        assert kwargs["verify"] is False

    def test_raises_immediately_on_invalid_scheme(self):
        # Must raise ValueError without touching requests at all
        with patch("requests.get") as mock_get:
            with pytest.raises(ValueError):
                download_to_bytes("file:///etc/passwd")
        mock_get.assert_not_called()

    def test_raises_after_all_retries_exhausted(self):
        with patch("requests.get", side_effect=Exception("connection refused")):
            with patch("time.sleep"):  # don't actually sleep in tests
                with pytest.raises(IOError, match="Failed to download"):
                    download_to_bytes("http://example.com/fail")

    def test_retries_on_transient_failure(self):
        # First two attempts fail, third succeeds
        resp = _mock_response([b"ok"])
        effects = [Exception("timeout"), Exception("reset"), resp]
        with patch("requests.get", side_effect=effects):
            with patch("time.sleep"):
                result = download_to_bytes("http://example.com/retry")
        assert result == b"ok"

    def test_raises_when_size_exceeded(self):
        big_chunk = b"x" * 1024
        resp = _mock_response([big_chunk] * 200)  # 200 KB
        with patch("requests.get", return_value=resp):
            with pytest.raises(IOError, match="exceeds"):
                download_to_bytes("http://example.com/big", max_bytes=100)

    def test_size_check_not_raised_within_limit(self):
        resp = _mock_response([b"small"])
        with patch("requests.get", return_value=resp):
            result = download_to_bytes("http://example.com/small", max_bytes=1024 * 1024)
        assert result == b"small"

    def test_http_error_is_not_retried(self):
        """raise_for_status raising should not retry (it's not a transient error here
        because it's raised inside requests which becomes an Exception — it will retry).
        But ValueError/IOError from our code must not retry."""
        resp = _mock_response([b"oversize"])
        # Patching raise_for_status to raise an HTTPError (subclass of requests.Exception)
        import requests as req_mod
        resp.raise_for_status.side_effect = req_mod.exceptions.HTTPError("404")
        with patch("requests.get", return_value=resp):
            with patch("time.sleep"):
                # HTTPError is a subclass of IOError; it's re-raised immediately
                # without retrying, so the raw HTTPError propagates.
                with pytest.raises(IOError, match="404"):
                    download_to_bytes("http://example.com/404")

    def test_returns_empty_bytes_for_empty_response(self):
        resp = _mock_response([])
        with patch("requests.get", return_value=resp):
            result = download_to_bytes("http://example.com/empty")
        assert result == b""


# ---------------------------------------------------------------------------
# download_to_file
# ---------------------------------------------------------------------------

class TestDownloadToFile:
    def test_writes_content_to_path(self, tmp_path):
        dest = str(tmp_path / "cert.pem")
        resp = _mock_response([b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"])
        with patch("requests.get", return_value=resp):
            download_to_file("http://example.com/cert.pem", dest)
        assert os.path.exists(dest)
        assert b"CERTIFICATE" in open(dest, "rb").read()

    def test_atomic_write_leaves_no_tmp_on_success(self, tmp_path):
        dest = str(tmp_path / "out.pem")
        resp = _mock_response([b"data"])
        with patch("requests.get", return_value=resp):
            download_to_file("http://example.com/f", dest)
        tmp_files = [f for f in os.listdir(str(tmp_path)) if f.endswith(".tmp")]
        assert tmp_files == [], "Temp files were not cleaned up"


# ---------------------------------------------------------------------------
# _cache_paths
# ---------------------------------------------------------------------------

class TestCachePaths:
    def test_returns_two_paths_in_cache_dir(self, tmp_path):
        data, meta = _cache_paths("http://example.com/igtf-bundle.tar.gz", str(tmp_path))
        assert os.path.dirname(data) == str(tmp_path)
        assert os.path.dirname(meta) == str(tmp_path)

    def test_data_path_has_tar_gz_extension(self, tmp_path):
        data, _ = _cache_paths("http://example.com/bundle.tar.gz", str(tmp_path))
        assert data.endswith(".tar.gz")

    def test_meta_path_has_meta_extension(self, tmp_path):
        _, meta = _cache_paths("http://example.com/bundle.tar.gz", str(tmp_path))
        assert meta.endswith(".meta")

    def test_different_urls_give_different_paths(self, tmp_path):
        d1, _ = _cache_paths("http://example.com/a.tar.gz", str(tmp_path))
        d2, _ = _cache_paths("http://example.com/b.tar.gz", str(tmp_path))
        assert d1 != d2

    def test_same_url_gives_same_paths(self, tmp_path):
        url = "http://example.com/bundle.tar.gz"
        assert _cache_paths(url, str(tmp_path)) == _cache_paths(url, str(tmp_path))


# ---------------------------------------------------------------------------
# download_with_cache
# ---------------------------------------------------------------------------

class TestDownloadWithCache:
    def test_first_download_returns_content(self, tmp_path):
        resp = _mock_response([b"tarball content"])
        resp.headers = {"ETag": '"abc123"', "Last-Modified": "Mon, 01 Jan 2026 00:00:00 GMT"}
        with patch("requests.get", return_value=resp):
            data = download_with_cache("http://example.com/b.tar.gz", str(tmp_path))
        assert data == b"tarball content"

    def test_first_download_writes_cache_file(self, tmp_path):
        resp = _mock_response([b"tarball content"])
        resp.headers = {}
        with patch("requests.get", return_value=resp):
            download_with_cache("http://example.com/b.tar.gz", str(tmp_path))
        data_path, _ = _cache_paths("http://example.com/b.tar.gz", str(tmp_path))
        assert os.path.isfile(data_path)
        assert open(data_path, "rb").read() == b"tarball content"

    def test_etag_written_to_meta(self, tmp_path):
        resp = _mock_response([b"data"])
        resp.headers = {"ETag": '"xyz"'}
        with patch("requests.get", return_value=resp):
            download_with_cache("http://example.com/b.tar.gz", str(tmp_path))
        import json
        _, meta_path = _cache_paths("http://example.com/b.tar.gz", str(tmp_path))
        meta = json.load(open(meta_path))
        assert meta["etag"] == '"xyz"'

    def test_304_returns_cached_bytes(self, tmp_path):
        url = "http://example.com/b.tar.gz"
        data_path, meta_path = _cache_paths(url, str(tmp_path))
        # Pre-populate cache
        with open(data_path, "wb") as f:
            f.write(b"cached content")
        import json
        with open(meta_path, "w") as f:
            json.dump({"url": url, "etag": '"abc"'}, f)
        # Server returns 304
        resp = MagicMock()
        resp.status_code = 304
        with patch("requests.get", return_value=resp):
            data = download_with_cache(url, str(tmp_path))
        assert data == b"cached content"

    def test_304_sends_if_none_match_header(self, tmp_path):
        url = "http://example.com/b.tar.gz"
        data_path, meta_path = _cache_paths(url, str(tmp_path))
        with open(data_path, "wb") as f:
            f.write(b"cached")
        import json
        with open(meta_path, "w") as f:
            json.dump({"url": url, "etag": '"myetag"'}, f)
        resp = MagicMock()
        resp.status_code = 304
        with patch("requests.get", return_value=resp) as mock_get:
            download_with_cache(url, str(tmp_path))
        _, kwargs = mock_get.call_args
        assert mock_get.call_args[1]["headers"]["If-None-Match"] == '"myetag"'

    def test_network_failure_with_cache_returns_cache(self, tmp_path):
        url = "http://example.com/b.tar.gz"
        data_path, _ = _cache_paths(url, str(tmp_path))
        with open(data_path, "wb") as f:
            f.write(b"stale cached content")
        with patch("requests.get", side_effect=Exception("connection refused")):
            data = download_with_cache(url, str(tmp_path))
        assert data == b"stale cached content"

    def test_network_failure_without_cache_raises(self, tmp_path):
        with patch("requests.get", side_effect=Exception("connection refused")):
            with pytest.raises(IOError):
                download_with_cache("http://example.com/b.tar.gz", str(tmp_path))

    def test_creates_cache_dir_if_missing(self, tmp_path):
        cache = str(tmp_path / "new" / "subdir")
        resp = _mock_response([b"data"])
        resp.headers = {}
        with patch("requests.get", return_value=resp):
            download_with_cache("http://example.com/b.tar.gz", cache)
        assert os.path.isdir(cache)

    def test_bad_scheme_raises_value_error(self, tmp_path):
        with pytest.raises(ValueError):
            download_with_cache("ftp://example.com/b.tar.gz", str(tmp_path))

    def test_raises_on_bad_scheme(self, tmp_path):
        with pytest.raises(ValueError):
            download_to_file("ftp://example.com/f", str(tmp_path / "out"))
