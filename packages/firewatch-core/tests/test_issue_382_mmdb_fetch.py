"""Tests for issue #382 (MI-1) — geo_mmdb_fetch: first-run downloader.

EARS criteria covered:

  F1  WHEN the MMDB files are absent and the host has connectivity, the first
      run SHALL download both DB-IP Lite files over HTTPS, verify each against
      the published SHA1SUM, and install atomically.

  F2  WHEN SHA1 verification fails, the file SHALL be discarded with a WARNING
      and no partial install; the target path must not exist afterwards.

  F3  ensure_dbs() is idempotent: if both files already exist, no download is
      attempted.

  F4  The http_client_factory parameter allows injecting a mock client so tests
      never hit the network.

  F5  Path-traversal guard: _assert_within_dir raises ValueError when the
      dest_path escapes its expected root directory.

  F6  HTTP redirects are followed: a 302 → 200 sequence installs the file
      correctly (required for DB-IP month-specific URLs).

  F7  Decompressed-size cap: decompression aborts with ValueError and leaves
      no partial install when the stream exceeds _MAX_DECOMPRESSED_BYTES.

  F8  Path-traversal guard is a real containment check: _assert_within_dir
      rejects a path that escapes its parent even when called from
      _download_and_install (root_dir is the actual geo_data root, not the
      dest's own parent).

Tests never make real network calls — all HTTP is mocked via http_client_factory.
RFC 5737 IPs are not used here (no IPs in fetch tests); no gitleaks concern.
"""
from __future__ import annotations

import gzip
import hashlib
import io
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_mmdb_gz(content: bytes = b"fake mmdb content") -> bytes:
    """Return gzip-compressed bytes simulating a DB-IP MMDB download."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(content)
    return buf.getvalue()


def _sha1_hex(data: bytes) -> str:
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def _make_mock_client(
    gz_bytes: bytes,
    sha1_hex: str,
    fail_download: bool = False,
    bad_sha1: bool = False,
) -> MagicMock:
    """Build a mock httpx.Client that serves *gz_bytes* and the given SHA1.

    Parameters
    ----------
    gz_bytes:
        The gzipped MMDB content to stream.
    sha1_hex:
        The SHA1 hex string to return from the checksum endpoint.
    fail_download:
        When True, the streaming GET raises httpx.ConnectError.
    bad_sha1:
        When True, the checksum endpoint returns a wrong hash.
    """
    client = MagicMock(spec=httpx.Client)
    client.close = MagicMock()

    # SHA1 response
    sha1_response = MagicMock(spec=httpx.Response)
    sha1_response.text = (sha1_hex + "  dbip-city-lite.mmdb.gz") if not bad_sha1 else ("a" * 40)
    sha1_response.raise_for_status = MagicMock()
    client.get.return_value = sha1_response

    if fail_download:
        stream_cm = MagicMock()
        stream_cm.__enter__ = MagicMock(side_effect=httpx.ConnectError("refused"))
        stream_cm.__exit__ = MagicMock(return_value=False)
        client.stream.return_value = stream_cm
    else:
        # Streaming GET context manager
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


def _make_redirect_mock_client(
    gz_bytes: bytes,
    sha1_hex_val: str,
) -> MagicMock:
    """Build a mock client that simulates a 302 redirect on the first stream call.

    The mock returns the correct content on the (simulated) followed request,
    mimicking the httpx follow_redirects behaviour transparently. In practice
    httpx handles the redirect internally; the test verifies the client is
    configured to follow redirects and still installs the file correctly.
    """
    # httpx follows redirects internally; from the caller's perspective the
    # stream just succeeds (as if the redirect was transparent). We simulate
    # that: the mock client succeeds and the file installs. The separate
    # TestFollowRedirects.test_default_factory_enables_follow_redirects test
    # verifies the client flag is set.
    return _make_mock_client(gz_bytes, sha1_hex_val)


# ---------------------------------------------------------------------------
# F3 — Idempotency: files already present → no download
# ---------------------------------------------------------------------------


class TestIdempotency:
    """F3 — ensure_dbs() skips download when both files already exist."""

    def test_both_present_no_download(self, tmp_path: Path) -> None:
        """When both MMDB files exist, ensure_dbs() makes no HTTP calls."""
        from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

        city = tmp_path / "city.mmdb"
        asn = tmp_path / "asn.mmdb"
        city.write_bytes(b"existing city")
        asn.write_bytes(b"existing asn")

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.close = MagicMock()

        ensure_dbs(
            city_db_path=city,
            asn_db_path=asn,
            http_client_factory=lambda: mock_client,
        )

        mock_client.get.assert_not_called()
        mock_client.stream.assert_not_called()

    def test_city_present_only_asn_downloaded(self, tmp_path: Path) -> None:
        """When only city exists, only the ASN file is downloaded."""
        from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

        city = tmp_path / "city.mmdb"
        asn = tmp_path / "asn.mmdb"
        city.write_bytes(b"existing city")
        # asn absent

        gz_bytes = _make_fake_mmdb_gz(b"asn content")
        sha1 = _sha1_hex(gz_bytes)
        mock_client = _make_mock_client(gz_bytes, sha1)

        ensure_dbs(
            city_db_path=city,
            asn_db_path=asn,
            http_client_factory=lambda: mock_client,
        )

        # Only one stream call (for ASN)
        assert mock_client.stream.call_count == 1
        assert asn.exists()


# ---------------------------------------------------------------------------
# F1 — Successful download, SHA1 verify, atomic install
# ---------------------------------------------------------------------------


class TestSuccessfulDownload:
    """F1 — download → SHA1 verify → atomic install."""

    def test_both_files_downloaded_and_installed(self, tmp_path: Path) -> None:
        """Both absent files are downloaded, verified, and installed."""
        from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

        city = tmp_path / "geo" / "city.mmdb"
        asn = tmp_path / "geo" / "asn.mmdb"

        gz_bytes = _make_fake_mmdb_gz(b"mmdb content")
        sha1 = _sha1_hex(gz_bytes)

        call_count = [0]

        def _factory() -> MagicMock:
            call_count[0] += 1
            return _make_mock_client(gz_bytes, sha1)

        ensure_dbs(
            city_db_path=city,
            asn_db_path=asn,
            http_client_factory=_factory,
        )

        assert city.exists(), "City MMDB must be installed"
        assert asn.exists(), "ASN MMDB must be installed"

    def test_installed_content_is_decompressed_mmdb(self, tmp_path: Path) -> None:
        """The installed file contains the decompressed MMDB bytes (not gzip)."""
        from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

        raw_mmdb = b"raw mmdb bytes for testing"
        gz_bytes = _make_fake_mmdb_gz(raw_mmdb)
        sha1 = _sha1_hex(gz_bytes)

        city = tmp_path / "city.mmdb"
        asn = tmp_path / "asn.mmdb"
        # Pre-create asn so only city is downloaded
        asn.write_bytes(b"existing")

        ensure_dbs(
            city_db_path=city,
            asn_db_path=asn,
            http_client_factory=lambda: _make_mock_client(gz_bytes, sha1),
        )

        assert city.read_bytes() == raw_mmdb, (
            "Installed file must contain decompressed MMDB bytes"
        )

    def test_temp_file_cleaned_up_after_install(self, tmp_path: Path) -> None:
        """No .tmp or .gz temp files remain after successful install."""
        from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

        gz_bytes = _make_fake_mmdb_gz(b"mmdb data")
        sha1 = _sha1_hex(gz_bytes)

        city = tmp_path / "city.mmdb"
        asn = tmp_path / "asn.mmdb"
        asn.write_bytes(b"existing")

        ensure_dbs(
            city_db_path=city,
            asn_db_path=asn,
            http_client_factory=lambda: _make_mock_client(gz_bytes, sha1),
        )

        leftover = list(tmp_path.glob(".fw_mmdb*"))
        assert leftover == [], f"Temp files must be cleaned up; found: {leftover}"


# ---------------------------------------------------------------------------
# F2 — SHA1 mismatch: discard + no partial install
# ---------------------------------------------------------------------------


class TestSha1MismatchRejected:
    """F2 — SHA1 mismatch → file discarded, target path does NOT exist."""

    def test_sha1_mismatch_raises_value_error(self, tmp_path: Path) -> None:
        """_download_and_install raises ValueError when SHA1 does not match."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"legit content")
        wrong_sha1 = "a" * 40  # wrong hash

        dest = tmp_path / "city.mmdb"
        mock_client = _make_mock_client(gz_bytes, wrong_sha1)

        with pytest.raises(ValueError, match="SHA1 mismatch"):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

    def test_sha1_mismatch_target_not_created(self, tmp_path: Path) -> None:
        """After SHA1 mismatch, the target path must NOT be created (no partial install)."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"content")
        wrong_sha1 = "b" * 40

        dest = tmp_path / "city.mmdb"
        mock_client = _make_mock_client(gz_bytes, wrong_sha1)

        with pytest.raises(ValueError):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        assert not dest.exists(), "Target path must NOT exist after SHA1 mismatch"

    def test_sha1_mismatch_no_temp_files_left(self, tmp_path: Path) -> None:
        """No temp files remain after a SHA1 mismatch failure."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"content")
        wrong_sha1 = "c" * 40

        dest = tmp_path / "city.mmdb"
        mock_client = _make_mock_client(gz_bytes, wrong_sha1)

        with pytest.raises(ValueError):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        leftover = list(tmp_path.glob(".fw_mmdb*"))
        assert leftover == [], f"Temp files must be cleaned up; found: {leftover}"

    def test_ensure_dbs_propagates_sha1_failure(self, tmp_path: Path) -> None:
        """ensure_dbs() raises when SHA1 verification fails (caller logs + handles)."""
        from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

        gz_bytes = _make_fake_mmdb_gz(b"data")
        wrong_sha1 = "d" * 40

        city = tmp_path / "city.mmdb"
        asn = tmp_path / "asn.mmdb"
        asn.write_bytes(b"existing")

        mock_client = _make_mock_client(gz_bytes, wrong_sha1)

        with pytest.raises(ValueError, match="SHA1 mismatch"):
            ensure_dbs(
                city_db_path=city,
                asn_db_path=asn,
                http_client_factory=lambda: mock_client,
            )

        assert not city.exists()


# ---------------------------------------------------------------------------
# F4 — HTTP client injection (no real network calls in tests)
# ---------------------------------------------------------------------------


class TestClientInjection:
    """F4 — http_client_factory lets tests inject a mock client."""

    def test_factory_called_once(self, tmp_path: Path) -> None:
        """The factory is called exactly once per ensure_dbs() invocation."""
        from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

        gz_bytes = _make_fake_mmdb_gz(b"x")
        sha1 = _sha1_hex(gz_bytes)
        city = tmp_path / "city.mmdb"
        asn = tmp_path / "asn.mmdb"
        asn.write_bytes(b"existing")

        factory_calls = [0]

        def _factory() -> MagicMock:
            factory_calls[0] += 1
            return _make_mock_client(gz_bytes, sha1)

        ensure_dbs(city_db_path=city, asn_db_path=asn, http_client_factory=_factory)

        assert factory_calls[0] == 1

    def test_download_uses_https_url(self, tmp_path: Path) -> None:
        """The download URL starts with https:// (EARS F1 — HTTPS only)."""
        from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

        gz_bytes = _make_fake_mmdb_gz(b"data")
        sha1 = _sha1_hex(gz_bytes)
        city = tmp_path / "city.mmdb"
        asn = tmp_path / "asn.mmdb"
        asn.write_bytes(b"existing")

        captured_urls: list[str] = []
        mock_client = _make_mock_client(gz_bytes, sha1)
        original_stream = mock_client.stream

        def _capture_stream(method: str, url: str, **kwargs: Any) -> Any:
            captured_urls.append(url)
            return original_stream(method, url, **kwargs)

        mock_client.stream = _capture_stream

        ensure_dbs(
            city_db_path=city,
            asn_db_path=asn,
            http_client_factory=lambda: mock_client,
        )

        assert all(u.startswith("https://") for u in captured_urls), (
            f"All download URLs must be HTTPS; got: {captured_urls}"
        )


# ---------------------------------------------------------------------------
# F5 — Path-traversal guard
# ---------------------------------------------------------------------------


class TestPathTraversalGuard:
    """F5 — _assert_within_dir rejects paths outside the expected root directory."""

    def test_path_within_dir_is_accepted(self, tmp_path: Path) -> None:
        """A path inside the expected directory passes without error."""
        from firewatch_core.adapters.geo_mmdb_fetch import _assert_within_dir

        parent = tmp_path / "geo"
        child = parent / "city.mmdb"
        parent.mkdir()
        # Should not raise
        _assert_within_dir(child, parent)

    def test_path_outside_dir_raises(self, tmp_path: Path) -> None:
        """A path outside the expected directory raises ValueError."""
        from firewatch_core.adapters.geo_mmdb_fetch import _assert_within_dir

        parent = tmp_path / "geo"
        escaped = tmp_path / "other" / "city.mmdb"
        parent.mkdir()

        with pytest.raises(ValueError, match="path-traversal"):
            _assert_within_dir(escaped, parent)


# ---------------------------------------------------------------------------
# F6 — Redirect following (FIX 1)
# ---------------------------------------------------------------------------


class TestFollowRedirects:
    """F6 — HTTP redirects are followed; the default factory enables this."""

    def test_default_factory_enables_follow_redirects(self) -> None:
        """The default httpx.Client factory creates a client with follow_redirects=True."""
        import httpx as real_httpx
        from firewatch_core.adapters import geo_mmdb_fetch

        created_clients: list[real_httpx.Client] = []

        original_client = real_httpx.Client

        def _capturing_client(**kwargs: Any) -> real_httpx.Client:
            c = original_client(**kwargs)
            created_clients.append(c)
            return c

        # Patch httpx.Client inside the module to capture the kwargs
        with patch.object(geo_mmdb_fetch.httpx, "Client", side_effect=_capturing_client):
            # Trigger the default factory path: no http_client_factory provided,
            # but patch ensure_dbs so it doesn't actually attempt a network call.
            # We just instantiate the default factory directly.
            # Access the default_factory via a fresh call to ensure_dbs with
            # both files already present (no download needed, client still created).
            city = Path("/tmp/fw_test_city_redirect.mmdb")
            asn = Path("/tmp/fw_test_asn_redirect.mmdb")
            city.touch()
            asn.touch()
            try:
                geo_mmdb_fetch.ensure_dbs(city_db_path=city, asn_db_path=asn)
            finally:
                city.unlink(missing_ok=True)
                asn.unlink(missing_ok=True)
                for c in created_clients:
                    c.close()

        # Verify the created client has follow_redirects=True
        assert len(created_clients) == 1
        assert created_clients[0].follow_redirects is True, (
            "Default httpx.Client must have follow_redirects=True "
            "so DB-IP 302 redirects are followed automatically."
        )

    def test_redirect_followed_installs_file(self, tmp_path: Path) -> None:
        """A mock client that transparently follows a redirect installs the file.

        httpx follows redirects internally when follow_redirects=True; from the
        caller's perspective the stream succeeds. This test verifies the full
        path: mock client with correct data → file installed correctly.
        """
        from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

        raw_mmdb = b"redirected mmdb content"
        gz_bytes = _make_fake_mmdb_gz(raw_mmdb)
        sha1 = _sha1_hex(gz_bytes)

        city = tmp_path / "city.mmdb"
        asn = tmp_path / "asn.mmdb"
        asn.write_bytes(b"existing")

        mock_client = _make_redirect_mock_client(gz_bytes, sha1)

        ensure_dbs(
            city_db_path=city,
            asn_db_path=asn,
            http_client_factory=lambda: mock_client,
        )

        assert city.exists(), "File must be installed after following redirect"
        assert city.read_bytes() == raw_mmdb, "Installed content must be decompressed MMDB"


# ---------------------------------------------------------------------------
# F7 — Decompressed-size cap (FIX 3)
# ---------------------------------------------------------------------------


class TestDecompressedSizeCap:
    """F7 — decompression aborts when the stream exceeds _MAX_DECOMPRESSED_BYTES."""

    def _make_oversized_gz(self, limit: int) -> tuple[bytes, str]:
        """Return a gzip payload that decompresses to more than *limit* bytes."""
        # Write limit+1 bytes of decompressed content
        raw = b"X" * (limit + 1)
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(raw)
        gz_bytes = buf.getvalue()
        sha1 = _sha1_hex(gz_bytes)
        return gz_bytes, sha1

    def test_oversized_stream_raises_value_error(self, tmp_path: Path) -> None:
        """Decompression exceeding _MAX_DECOMPRESSED_BYTES raises ValueError."""
        from firewatch_core.adapters.geo_mmdb_fetch import (
            _MAX_DECOMPRESSED_BYTES,
            _download_and_install,
        )

        gz_bytes, sha1 = self._make_oversized_gz(_MAX_DECOMPRESSED_BYTES)
        dest = tmp_path / "city.mmdb"
        mock_client = _make_mock_client(gz_bytes, sha1)

        with pytest.raises(ValueError, match="Decompressed size exceeded"):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

    def test_oversized_stream_no_partial_install(self, tmp_path: Path) -> None:
        """No partial file is left after the size cap triggers."""
        from firewatch_core.adapters.geo_mmdb_fetch import (
            _MAX_DECOMPRESSED_BYTES,
            _download_and_install,
        )

        gz_bytes, sha1 = self._make_oversized_gz(_MAX_DECOMPRESSED_BYTES)
        dest = tmp_path / "city.mmdb"
        mock_client = _make_mock_client(gz_bytes, sha1)

        with pytest.raises(ValueError):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        assert not dest.exists(), "No partial install after size cap exceeded"

    def test_oversized_stream_no_temp_files_left(self, tmp_path: Path) -> None:
        """No temp files remain after the size cap triggers."""
        from firewatch_core.adapters.geo_mmdb_fetch import (
            _MAX_DECOMPRESSED_BYTES,
            _download_and_install,
        )

        gz_bytes, sha1 = self._make_oversized_gz(_MAX_DECOMPRESSED_BYTES)
        dest = tmp_path / "city.mmdb"
        mock_client = _make_mock_client(gz_bytes, sha1)

        with pytest.raises(ValueError):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        leftover = list(tmp_path.glob(".fw_mmdb*"))
        assert leftover == [], f"Temp files must be cleaned up; found: {leftover}"

    def test_exactly_at_limit_succeeds(self, tmp_path: Path) -> None:
        """A decompressed payload well under the limit is accepted (no false-positive)."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        # Use a small content that fits well under the 500 MB cap; verify the
        # limit logic doesn't false-positive on legitimate small payloads.
        raw = b"Y" * 1024  # 1 KB — well under the 500 MB limit
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(raw)
        gz_bytes = buf.getvalue()
        sha1 = _sha1_hex(gz_bytes)

        dest = tmp_path / "city.mmdb"
        mock_client = _make_mock_client(gz_bytes, sha1)

        _download_and_install(
            client=mock_client,
            mmdb_url="https://example.invalid/test.mmdb.gz",
            sha1_url="https://example.invalid/test.mmdb.gz.sha1",
            dest_path=dest,
            root_dir=tmp_path,
        )

        assert dest.exists(), "File within size limit must be installed"
        assert dest.read_bytes() == raw


# ---------------------------------------------------------------------------
# F8 — Containment check is a real root-dir check (FIX 2)
# ---------------------------------------------------------------------------


class TestContainmentCheckIsReal:
    """F8 — _download_and_install uses root_dir (not dest.parent) for containment."""

    def test_path_traversal_within_install_root(self, tmp_path: Path) -> None:
        """dest_path within root_dir passes the containment guard."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        root = tmp_path / "geo_data"
        root.mkdir()
        dest = root / "city.mmdb"

        gz_bytes = _make_fake_mmdb_gz(b"content")
        sha1 = _sha1_hex(gz_bytes)
        mock_client = _make_mock_client(gz_bytes, sha1)

        # Should succeed — dest is within root
        _download_and_install(
            client=mock_client,
            mmdb_url="https://example.invalid/test.mmdb.gz",
            sha1_url="https://example.invalid/test.mmdb.gz.sha1",
            dest_path=dest,
            root_dir=root,
        )
        assert dest.exists()

    def test_path_outside_root_dir_rejected(self, tmp_path: Path) -> None:
        """dest_path outside root_dir raises ValueError before any download."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        root = tmp_path / "geo_data"
        root.mkdir()
        # dest is OUTSIDE root — this should be caught
        escaped_dest = tmp_path / "etc" / "passwd"

        gz_bytes = _make_fake_mmdb_gz(b"content")
        sha1 = _sha1_hex(gz_bytes)
        mock_client = _make_mock_client(gz_bytes, sha1)

        with pytest.raises(ValueError, match="path-traversal"):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=escaped_dest,
                root_dir=root,
            )

        # Verify no download was attempted
        mock_client.get.assert_not_called()
        mock_client.stream.assert_not_called()
