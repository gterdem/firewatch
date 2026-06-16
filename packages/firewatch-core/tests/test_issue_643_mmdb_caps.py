"""Tests for issue #643 — geo_mmdb_fetch hardening: compressed-size cap + HTTPS guard.

EARS criteria covered:

  GEO-1  WHEN the compressed download stream exceeds _MAX_COMPRESSED_BYTES,
         _download_and_install SHALL abort with ValueError and leave no partial
         install (fail-closed; compressed cap fires before decompression begins).
         Real DB-IP files are ~20-60 MB gzipped; the cap is set at ~200 MB.

  GEO-2  WHEN the compressed download stream is within _MAX_COMPRESSED_BYTES,
         the download MUST succeed (no false-positive rejection).

  GEO-3  WHEN _download_and_install is called with a non-HTTPS URL (url not
         starting with 'https://'), it SHALL raise AssertionError immediately
         (runtime HTTPS guard), so a future URL-param refactor fails closed.

  GEO-4  WHEN _download_and_install is called with a valid HTTPS URL, no
         AssertionError is raised (GEO-3 guard is not a false positive).

Tests never make real network calls — all HTTP is mocked via http_client_factory.
RFC 5737 / RFC 1918 IPs are not used here (no IPs in fetch tests).
"""
from __future__ import annotations

import gzip
import hashlib
import io
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest


# ---------------------------------------------------------------------------
# Helpers (pattern from test_issue_382_mmdb_fetch.py)
# ---------------------------------------------------------------------------


def _make_fake_mmdb_gz(content: bytes = b"fake mmdb content") -> bytes:
    """Return gzip-compressed bytes simulating a DB-IP MMDB download."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(content)
    return buf.getvalue()


def _sha1_hex(data: bytes) -> str:
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def _make_streaming_client(gz_bytes: bytes, sha1: str) -> MagicMock:
    """Build a mock httpx.Client that streams *gz_bytes* with the given SHA1."""
    client = MagicMock(spec=httpx.Client)
    client.close = MagicMock()

    sha1_resp = MagicMock(spec=httpx.Response)
    sha1_resp.text = sha1 + "  dbip-test.mmdb.gz"
    sha1_resp.raise_for_status = MagicMock()
    client.get.return_value = sha1_resp

    stream_resp = MagicMock(spec=httpx.Response)
    stream_resp.raise_for_status = MagicMock()

    def _iter_bytes(chunk_size: int = 65536) -> Any:
        yield gz_bytes

    stream_resp.iter_bytes = _iter_bytes

    stream_cm = MagicMock()
    stream_cm.__enter__ = MagicMock(return_value=stream_resp)
    stream_cm.__exit__ = MagicMock(return_value=False)
    client.stream.return_value = stream_cm

    return client


def _make_oversized_compressed_client(cap: int) -> tuple[MagicMock, bytes]:
    """Return a client that streams cap+1 bytes of compressed data (no SHA1 verification).

    The gz payload itself is just raw bytes chunked out — we are testing the
    compressed-size cap, so we skip SHA1 verification by returning a 404 for
    the .sha1 sidecar (the 404 path is already tested and accepted per ADR-0039
    amendment). This isolates the compressed-cap test.
    """
    # Build a blob of 'cap + 1' bytes that the streaming mock emits as-is.
    # It doesn't need to be valid gzip — the size cap fires before decompression.
    oversized_gz = b"G" * (cap + 1)

    client = MagicMock(spec=httpx.Client)
    client.close = MagicMock()

    # Return 404 for the .sha1 sidecar so checksum is skipped (size cap tested in isolation)
    sha1_resp = MagicMock(spec=httpx.Response)
    sha1_resp.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=MagicMock(status_code=404),
        )
    )
    client.get.return_value = sha1_resp

    stream_resp = MagicMock(spec=httpx.Response)
    stream_resp.raise_for_status = MagicMock()

    def _iter_bytes(chunk_size: int = 65536) -> Any:
        # Yield in two chunks so the cap triggers mid-stream
        half = cap // 2 + 1
        yield oversized_gz[:half]
        yield oversized_gz[half:]

    stream_resp.iter_bytes = _iter_bytes

    stream_cm = MagicMock()
    stream_cm.__enter__ = MagicMock(return_value=stream_resp)
    stream_cm.__exit__ = MagicMock(return_value=False)
    client.stream.return_value = stream_cm

    return client, oversized_gz


# ---------------------------------------------------------------------------
# GEO-1 — Compressed-size cap fires before decompression
# ---------------------------------------------------------------------------


class TestCompressedSizeCap:
    """GEO-1 — compressed download exceeding _MAX_COMPRESSED_BYTES aborts with ValueError."""

    def test_oversized_compressed_stream_raises_value_error(self, tmp_path: Path) -> None:
        """Streaming more than _MAX_COMPRESSED_BYTES raises ValueError (fail-closed)."""
        from firewatch_core.adapters.geo_mmdb_fetch import (
            _MAX_COMPRESSED_BYTES,
            _download_and_install,
        )

        client, _ = _make_oversized_compressed_client(_MAX_COMPRESSED_BYTES)
        dest = tmp_path / "city.mmdb"

        with pytest.raises(ValueError, match="[Cc]ompressed"):
            _download_and_install(
                client=client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

    def test_oversized_compressed_stream_no_partial_install(self, tmp_path: Path) -> None:
        """No partial file is left after the compressed-size cap triggers (fail-closed)."""
        from firewatch_core.adapters.geo_mmdb_fetch import (
            _MAX_COMPRESSED_BYTES,
            _download_and_install,
        )

        client, _ = _make_oversized_compressed_client(_MAX_COMPRESSED_BYTES)
        dest = tmp_path / "city.mmdb"

        with pytest.raises(ValueError):
            _download_and_install(
                client=client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        assert not dest.exists(), "No partial install after compressed-size cap"

    def test_oversized_compressed_no_temp_files_left(self, tmp_path: Path) -> None:
        """No temp files remain after the compressed-size cap triggers."""
        from firewatch_core.adapters.geo_mmdb_fetch import (
            _MAX_COMPRESSED_BYTES,
            _download_and_install,
        )

        client, _ = _make_oversized_compressed_client(_MAX_COMPRESSED_BYTES)
        dest = tmp_path / "city.mmdb"

        with pytest.raises(ValueError):
            _download_and_install(
                client=client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        leftover = list(tmp_path.glob(".fw_mmdb*"))
        assert leftover == [], f"Temp files must be cleaned up; found: {leftover}"

    def test_compressed_cap_constant_is_reasonable(self) -> None:
        """_MAX_COMPRESSED_BYTES is >= 100 MB and <= 500 MB (sanity bounds).

        Real DB-IP files are ~20-60 MB gzipped. The cap should be generous
        enough to allow real files (>100 MB headroom) while still capping an
        adversarial payload well before it reaches disk (<=500 MB).
        """
        from firewatch_core.adapters.geo_mmdb_fetch import _MAX_COMPRESSED_BYTES

        _100_MB = 100 * 1024 * 1024
        _500_MB = 500 * 1024 * 1024
        assert _100_MB <= _MAX_COMPRESSED_BYTES <= _500_MB, (
            f"_MAX_COMPRESSED_BYTES={_MAX_COMPRESSED_BYTES} is outside expected range "
            f"[{_100_MB}, {_500_MB}]"
        )


# ---------------------------------------------------------------------------
# GEO-2 — Small compressed stream succeeds (no false-positive cap)
# ---------------------------------------------------------------------------


class TestCompressedSizeCapNoFalsePositive:
    """GEO-2 — a legitimate small .gz stream is not rejected by the cap."""

    def test_small_compressed_file_installs_successfully(self, tmp_path: Path) -> None:
        """A small compressed payload (well under the cap) installs without error."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        raw = b"small mmdb content"
        gz_bytes = _make_fake_mmdb_gz(raw)
        sha1 = _sha1_hex(gz_bytes)
        client = _make_streaming_client(gz_bytes, sha1)
        dest = tmp_path / "city.mmdb"

        _download_and_install(
            client=client,
            mmdb_url="https://example.invalid/test.mmdb.gz",
            sha1_url="https://example.invalid/test.mmdb.gz.sha1",
            dest_path=dest,
            root_dir=tmp_path,
        )

        assert dest.exists(), "Small compressed file must install successfully"
        assert dest.read_bytes() == raw, "Installed content must be decompressed MMDB"


# ---------------------------------------------------------------------------
# GEO-3 — HTTPS runtime guard
# ---------------------------------------------------------------------------


class TestHttpsRuntimeGuard:
    """GEO-3 — _download_and_install raises ValueError for non-HTTPS URLs.

    The URL constants are hardcoded HTTPS (structural enforcement), but the
    docstring/ADR describe a call-time check. An explicit raise makes a future
    URL-param refactor fail closed immediately (defence-in-depth). A bare
    ``assert`` is deliberately NOT used here: it is stripped under ``python -O``
    (PYTHONOPTIMIZE), which would silently disable a security guard.
    """

    def test_http_url_raises_value_error(self, tmp_path: Path) -> None:
        """A plain http:// URL raises ValueError before any download is attempted."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"data")
        sha1 = _sha1_hex(gz_bytes)
        client = _make_streaming_client(gz_bytes, sha1)
        dest = tmp_path / "city.mmdb"

        with pytest.raises(ValueError):
            _download_and_install(
                client=client,
                mmdb_url="http://example.invalid/test.mmdb.gz",   # NOT https
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

    def test_http_url_no_download_attempted(self, tmp_path: Path) -> None:
        """No HTTP call is made when the URL is non-HTTPS (guard fires first)."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"data")
        sha1 = _sha1_hex(gz_bytes)
        client = _make_streaming_client(gz_bytes, sha1)
        dest = tmp_path / "city.mmdb"

        with pytest.raises(ValueError):
            _download_and_install(
                client=client,
                mmdb_url="http://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        # Guard must fire before any network call
        client.get.assert_not_called()
        client.stream.assert_not_called()

    def test_ftp_url_raises_value_error(self, tmp_path: Path) -> None:
        """A ftp:// URL also raises ValueError (any non-HTTPS scheme rejected)."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"data")
        sha1 = _sha1_hex(gz_bytes)
        client = _make_streaming_client(gz_bytes, sha1)
        dest = tmp_path / "city.mmdb"

        with pytest.raises(ValueError):
            _download_and_install(
                client=client,
                mmdb_url="ftp://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

    def test_non_https_sha1_url_raises_value_error(self, tmp_path: Path) -> None:
        """A non-HTTPS *sha1_url* is rejected too (guard covers both URLs)."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"data")
        sha1 = _sha1_hex(gz_bytes)
        client = _make_streaming_client(gz_bytes, sha1)
        dest = tmp_path / "city.mmdb"

        with pytest.raises(ValueError):
            _download_and_install(
                client=client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="http://example.invalid/test.mmdb.gz.sha1",   # NOT https
                dest_path=dest,
                root_dir=tmp_path,
            )

        client.get.assert_not_called()
        client.stream.assert_not_called()


# ---------------------------------------------------------------------------
# GEO-4 — HTTPS guard does not false-positive on valid HTTPS URLs
# ---------------------------------------------------------------------------


class TestHttpsGuardNoFalsePositive:
    """GEO-4 — valid https:// URLs are not rejected by the runtime guard."""

    def test_https_url_not_rejected(self, tmp_path: Path) -> None:
        """A valid https:// mmdb_url does not raise AssertionError."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"data")
        sha1 = _sha1_hex(gz_bytes)
        client = _make_streaming_client(gz_bytes, sha1)
        dest = tmp_path / "city.mmdb"

        # Must not raise AssertionError — completes normally
        _download_and_install(
            client=client,
            mmdb_url="https://example.invalid/test.mmdb.gz",
            sha1_url="https://example.invalid/test.mmdb.gz.sha1",
            dest_path=dest,
            root_dir=tmp_path,
        )

        assert dest.exists(), "Valid HTTPS URL must install successfully"
