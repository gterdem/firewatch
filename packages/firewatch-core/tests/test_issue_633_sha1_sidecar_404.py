"""Tests for issue #633 — geo_mmdb_fetch: best-effort checksum when .sha1 sidecar is 404.

EARS criteria covered:

  F9  WHEN the .gz MMDB is available (200) AND the .sha1 sidecar returns 404,
      the system SHALL log a WARNING and proceed with the download (HTTPS +
      size cap only), installing the MMDB file atomically.

  F10 WHEN the .sha1 sidecar IS fetchable AND the downloaded .gz checksum
      MISMATCHES, the file SHALL be discarded with no partial install (unchanged
      behaviour — regression guard).

  F11 WHEN both the .gz and .sha1 are available and the checksum matches, the
      install SUCCEEDS with no WARNING about missing sidecar (happy-path
      regression guard).

  F12 WHEN the .sha1 sidecar returns a non-404 HTTP error (e.g. 500), the
      install SHALL abort (raising) — only 404 / unavailability is treated as
      "sidecar absent"; other HTTP errors are not silenced.

Tests never make real network calls — all HTTP is mocked via http_client_factory.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest


# ---------------------------------------------------------------------------
# Helpers (mirroring test_issue_382_mmdb_fetch.py helpers for isolation)
# ---------------------------------------------------------------------------


def _make_fake_mmdb_gz(content: bytes = b"fake mmdb content") -> bytes:
    """Return gzip-compressed bytes simulating a DB-IP MMDB download."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(content)
    return buf.getvalue()


def _sha1_hex(data: bytes) -> str:
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def _make_404_sha1_response() -> MagicMock:
    """Return a mock httpx.Response that simulates a 404 for the .sha1 sidecar."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 404
    resp.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=MagicMock(status_code=404),
        )
    )
    return resp


def _make_500_sha1_response() -> MagicMock:
    """Return a mock httpx.Response that simulates a 500 for the .sha1 sidecar."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 500
    resp.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "500 Internal Server Error",
            request=MagicMock(),
            response=MagicMock(status_code=500),
        )
    )
    return resp


def _make_client_with_404_sha1(gz_bytes: bytes) -> MagicMock:
    """Build a mock httpx.Client where .gz serves 200 but .sha1 returns 404."""
    client = MagicMock(spec=httpx.Client)
    client.close = MagicMock()

    # .sha1 GET → 404
    client.get.return_value = _make_404_sha1_response()

    # .gz stream → 200 with gz_bytes
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


def _make_client_with_500_sha1(gz_bytes: bytes) -> MagicMock:
    """Build a mock httpx.Client where .sha1 returns 500 (non-404 server error)."""
    client = MagicMock(spec=httpx.Client)
    client.close = MagicMock()

    # .sha1 GET → 500
    client.get.return_value = _make_500_sha1_response()

    # .gz stream → 200 (should not be reached because 500 must abort)
    stream_resp = MagicMock(spec=httpx.Response)
    stream_resp.raise_for_status = MagicMock()

    def _iter_bytes(chunk_size: int = 65536) -> Any:
        yield gz_bytes  # pragma: no branch

    stream_resp.iter_bytes = _iter_bytes

    stream_cm = MagicMock()
    stream_cm.__enter__ = MagicMock(return_value=stream_resp)
    stream_cm.__exit__ = MagicMock(return_value=False)
    client.stream.return_value = stream_cm

    return client


def _make_ok_client(gz_bytes: bytes, sha1: str) -> MagicMock:
    """Build a mock client where both .sha1 and .gz succeed (happy path)."""
    client = MagicMock(spec=httpx.Client)
    client.close = MagicMock()

    sha1_resp = MagicMock(spec=httpx.Response)
    sha1_resp.text = sha1 + "  dbip-city-lite.mmdb.gz"
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


def _make_client_bad_sha1(gz_bytes: bytes) -> MagicMock:
    """Build a mock client where .sha1 is fetchable but the hash is wrong."""
    wrong_sha1 = "a" * 40
    return _make_ok_client(gz_bytes, wrong_sha1)


# ---------------------------------------------------------------------------
# F9 — 404 sidecar: warn and proceed
# ---------------------------------------------------------------------------


class TestSha1Sidecar404ProceedWithWarning:
    """F9 — WHEN the .sha1 sidecar returns 404 the install PROCEEDS with a WARNING."""

    def test_install_succeeds_when_sha1_sidecar_404(self, tmp_path: Path) -> None:
        """File is installed even when the .sha1 sidecar returns 404."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        raw_mmdb = b"real mmdb bytes"
        gz_bytes = _make_fake_mmdb_gz(raw_mmdb)
        dest = tmp_path / "city.mmdb"
        mock_client = _make_client_with_404_sha1(gz_bytes)

        _download_and_install(
            client=mock_client,
            mmdb_url="https://example.invalid/test.mmdb.gz",
            sha1_url="https://example.invalid/test.mmdb.gz.sha1",
            dest_path=dest,
            root_dir=tmp_path,
        )

        assert dest.exists(), "MMDB must be installed when .sha1 sidecar is 404"
        assert dest.read_bytes() == raw_mmdb, "Installed content must be decompressed MMDB"

    def test_warning_logged_when_sha1_sidecar_404(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A WARNING is logged when the .sha1 sidecar returns 404."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"mmdb content")
        dest = tmp_path / "city.mmdb"
        mock_client = _make_client_with_404_sha1(gz_bytes)

        with caplog.at_level(logging.WARNING, logger="firewatch.geo_mmdb_fetch"):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("sha1" in m.lower() or "checksum" in m.lower() for m in warning_msgs), (
            f"Expected a WARNING about missing SHA1 sidecar; got log messages: {warning_msgs}"
        )

    def test_no_temp_files_left_after_404_sidecar_install(self, tmp_path: Path) -> None:
        """No .fw_mmdb* temp files remain after a successful 404-sidecar install."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"data")
        dest = tmp_path / "city.mmdb"
        mock_client = _make_client_with_404_sha1(gz_bytes)

        _download_and_install(
            client=mock_client,
            mmdb_url="https://example.invalid/test.mmdb.gz",
            sha1_url="https://example.invalid/test.mmdb.gz.sha1",
            dest_path=dest,
            root_dir=tmp_path,
        )

        leftover = list(tmp_path.glob(".fw_mmdb*"))
        assert leftover == [], f"Temp files must be cleaned up; found: {leftover}"

    def test_ensure_dbs_succeeds_when_sha1_sidecar_404(self, tmp_path: Path) -> None:
        """ensure_dbs() installs both files when both .sha1 sidecars return 404."""
        from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

        city = tmp_path / "city.mmdb"
        asn = tmp_path / "asn.mmdb"
        gz_bytes = _make_fake_mmdb_gz(b"mmdb payload")

        def _factory() -> MagicMock:
            return _make_client_with_404_sha1(gz_bytes)

        ensure_dbs(city_db_path=city, asn_db_path=asn, http_client_factory=_factory)

        assert city.exists(), "City MMDB must be installed despite 404 sidecar"
        assert asn.exists(), "ASN MMDB must be installed despite 404 sidecar"


# ---------------------------------------------------------------------------
# F10 — Sidecar present + checksum mismatch → reject (regression guard)
# ---------------------------------------------------------------------------


class TestSha1MismatchStillRejected:
    """F10 — When the sidecar IS present but the hash is wrong, the install aborts."""

    def test_mismatch_raises_when_sidecar_present(self, tmp_path: Path) -> None:
        """SHA1 mismatch is still rejected when the .sha1 sidecar is present."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"legitimate content")
        dest = tmp_path / "city.mmdb"
        mock_client = _make_client_bad_sha1(gz_bytes)

        with pytest.raises(ValueError, match="SHA1 mismatch"):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

    def test_mismatch_target_not_created(self, tmp_path: Path) -> None:
        """Target path does NOT exist after a SHA1 mismatch (no partial install)."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"content")
        dest = tmp_path / "city.mmdb"
        mock_client = _make_client_bad_sha1(gz_bytes)

        with pytest.raises(ValueError):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        assert not dest.exists(), "Target must NOT exist after SHA1 mismatch"


# ---------------------------------------------------------------------------
# F11 — Happy-path regression guard: sidecar present, hash matches → SUCCESS
# ---------------------------------------------------------------------------


class TestHappyPathRegressionGuard:
    """F11 — When .sha1 is present and matches, install succeeds with no sidecar warning."""

    def test_happy_path_install_succeeds(self, tmp_path: Path) -> None:
        """Full happy path: .sha1 present and matching → file installed."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        raw_mmdb = b"verified mmdb bytes"
        gz_bytes = _make_fake_mmdb_gz(raw_mmdb)
        sha1 = _sha1_hex(gz_bytes)
        dest = tmp_path / "city.mmdb"
        mock_client = _make_ok_client(gz_bytes, sha1)

        _download_and_install(
            client=mock_client,
            mmdb_url="https://example.invalid/test.mmdb.gz",
            sha1_url="https://example.invalid/test.mmdb.gz.sha1",
            dest_path=dest,
            root_dir=tmp_path,
        )

        assert dest.exists()
        assert dest.read_bytes() == raw_mmdb

    def test_happy_path_no_sidecar_warning_logged(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No 'sidecar absent' WARNING is emitted when the .sha1 is present."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"data")
        sha1 = _sha1_hex(gz_bytes)
        dest = tmp_path / "city.mmdb"
        mock_client = _make_ok_client(gz_bytes, sha1)

        with caplog.at_level(logging.WARNING, logger="firewatch.geo_mmdb_fetch"):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        sidecar_warnings = [
            r.message
            for r in caplog.records
            if r.levelno == logging.WARNING
            and ("sidecar" in r.message.lower() or "unavailable" in r.message.lower())
        ]
        assert sidecar_warnings == [], (
            f"No sidecar-absent warning expected on happy path; got: {sidecar_warnings}"
        )


# ---------------------------------------------------------------------------
# F12 — Non-404 HTTP error on .sha1 → abort (not silenced)
# ---------------------------------------------------------------------------


class TestNon404Sha1ErrorAborts:
    """F12 — Only 404 is treated as 'sidecar absent'; other HTTP errors still abort."""

    def test_500_on_sha1_sidecar_aborts_install(self, tmp_path: Path) -> None:
        """A 500 error on the .sha1 sidecar raises (not silenced as 'absent')."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"content")
        dest = tmp_path / "city.mmdb"
        mock_client = _make_client_with_500_sha1(gz_bytes)

        with pytest.raises(httpx.HTTPStatusError):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

    def test_500_on_sha1_sidecar_no_partial_install(self, tmp_path: Path) -> None:
        """A 500 error on the .sha1 sidecar leaves no partial file."""
        from firewatch_core.adapters.geo_mmdb_fetch import _download_and_install

        gz_bytes = _make_fake_mmdb_gz(b"content")
        dest = tmp_path / "city.mmdb"
        mock_client = _make_client_with_500_sha1(gz_bytes)

        with pytest.raises(httpx.HTTPStatusError):
            _download_and_install(
                client=mock_client,
                mmdb_url="https://example.invalid/test.mmdb.gz",
                sha1_url="https://example.invalid/test.mmdb.gz.sha1",
                dest_path=dest,
                root_dir=tmp_path,
            )

        assert not dest.exists(), "No partial install after non-404 .sha1 HTTP error"
