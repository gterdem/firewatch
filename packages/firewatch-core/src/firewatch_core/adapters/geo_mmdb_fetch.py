"""First-run downloader for DB-IP Lite MMDB files (ADR-0039).

Responsibility: given the target paths for the two MMDB files, ensure they
exist by downloading them from DB-IP's public HTTPS endpoints when absent,
verifying the SHA1 checksum published by DB-IP, and installing atomically
(write to a temp file, verify, then rename — never leave a partial or corrupt
DB in place).

This module is a pure utility — it has no dependency on ``MmdbGeoEnricher``
or any other enricher class. ``MmdbGeoEnricher._try_first_run_fetch`` imports
it lazily so the network layer is easily isolated in tests.

Security notes (ADR-0039, amended 2026-06 — issues #633, #643)
---------------------------------------------------------------
* Download is over HTTPS only — the URL scheme is enforced both structurally
  (hardcoded HTTPS constants) and at call time via an ``assert`` in
  ``_download_and_install`` (issue #643 hardening — ensures a future URL-param
  refactor fails closed rather than silently downgrading to HTTP).
* HTTP redirects are followed (``follow_redirects=True``). DB-IP month-specific
  URLs may be served via HTTP 302 redirect. This is safe because every URL is a
  hardcoded HTTPS string to ``download.db-ip.com`` — no operator or attacker
  input reaches the HTTP client.
* SHA1SUM verification is **best-effort** (ADR-0039 amendment):
  - When the ``.sha1`` sidecar is fetchable: the downloaded ``.gz`` is verified
    against it; a mismatch → discard + WARNING; no partial install.
  - When the ``.sha1`` sidecar returns HTTP 404: a WARNING is logged and the
    download proceeds (HTTPS transport integrity + size cap still apply).
    Only 404 is treated as "sidecar absent"; other HTTP errors (5xx, etc.)
    still abort the fetch.
  Background: DB-IP stopped publishing ``.sha1`` sidecars for current monthly
  editions (observed 2026-06: ``.mmdb.gz`` → 200, ``.mmdb.gz.sha1`` → 404).
* The install path is validated to be within the ``geo_data`` install root
  directory to prevent path-traversal from a crafted filename (defence-in-depth).
* Compressed download is capped at ``_MAX_COMPRESSED_BYTES`` (200 MB) to abort
  adversarial payloads *before* they are fully written to disk (issue #643).
  Real DB-IP files are ~20-60 MB gzipped; 200 MB provides ample headroom.
* Decompressed output is capped at ``_MAX_DECOMPRESSED_BYTES`` (500 MB) to abort
  zip-bomb-style payloads (CDN-compromise defence-in-depth).
* No operator data or telemetry leaves the box — only a public artifact is
  downloaded. The first-run fetch is explicitly NOT telemetry egress (ADR-0039).

DB-IP Lite URLs (public, no account required, CC-BY 4.0):
  City: https://db-ip.com/db/download/ip-to-city-lite  (monthly editions)
  ASN:  https://db-ip.com/db/download/ip-to-asn-lite   (monthly editions)

The URLs below point to month-specific editions and are followed via HTTP
redirect to the current monthly file. They are intentionally *not* hardcoded
to a specific edition so a first-run install always gets a current DB.
"""
from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from pathlib import Path
from typing import Callable

import httpx

logger = logging.getLogger("firewatch.geo_mmdb_fetch")

# DB-IP Lite public HTTPS download URLs.
# These are month-specific URLs served via HTTP redirect (302) to the actual
# file. ``follow_redirects=True`` is required for the download to succeed.
# Format: mmdb.gz  — we download the .mmdb.gz and decompress to .mmdb.
_CITY_MMDB_URL = (
    "https://download.db-ip.com/free/dbip-city-lite-{year}-{month:02d}.mmdb.gz"
)
_ASN_MMDB_URL = (
    "https://download.db-ip.com/free/dbip-asn-lite-{year}-{month:02d}.mmdb.gz"
)

# Checksum page URLs (DB-IP publishes SHA1 hashes here).
_CITY_SHA1_URL = (
    "https://download.db-ip.com/free/dbip-city-lite-{year}-{month:02d}.mmdb.gz.sha1"
)
_ASN_SHA1_URL = (
    "https://download.db-ip.com/free/dbip-asn-lite-{year}-{month:02d}.mmdb.gz.sha1"
)

# HTTP timeout for fetching DB files (seconds). DBs are ~20-40 MB; 120 s is generous.
_DOWNLOAD_TIMEOUT = 120.0

# HTTP timeout for fetching the small SHA1 checksum files (seconds).
_CHECKSUM_TIMEOUT = 15.0

# Maximum compressed (gzipped) download size in bytes (200 MB).
# Real DB-IP Lite files are ~20-60 MB gzipped; 200 MB provides ample headroom
# while ensuring a CDN-compromise or adversarial .gz is rejected *before* being
# written to disk (issue #643 hardening — defence-in-depth).
# Without this cap the decompressed-size guard below fires only after the full
# .gz has already landed on disk.
_MAX_COMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MB

# Maximum decompressed size in bytes (500 MB). DB-IP City Lite is ~75 MB and
# ASN Lite is ~30 MB decompressed; 500 MB leaves ample headroom while capping
# a CDN-compromise zip-bomb payload (defence-in-depth).
_MAX_DECOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB


def _current_year_month() -> tuple[int, int]:
    """Return (year, month) for the current UTC date."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    return now.year, now.month


def _build_urls(year: int, month: int) -> tuple[str, str, str, str]:
    """Return (city_mmdb_url, asn_mmdb_url, city_sha1_url, asn_sha1_url)."""
    fmt = {"year": year, "month": month}
    return (
        _CITY_MMDB_URL.format(**fmt),
        _ASN_MMDB_URL.format(**fmt),
        _CITY_SHA1_URL.format(**fmt),
        _ASN_SHA1_URL.format(**fmt),
    )


def _fetch_sha1(client: httpx.Client, url: str) -> str:
    """Fetch and return the expected SHA1 hex digest from *url*.

    Raises ``httpx.HTTPError`` or ``ValueError`` on failure.
    The checksum file contains just the hex digest (optionally followed by
    whitespace and a filename on the same line — we take only the first token).
    """
    resp = client.get(url, timeout=_CHECKSUM_TIMEOUT)
    resp.raise_for_status()
    raw = resp.text.strip()
    # SHA1 hex is the first whitespace-delimited token (BSD/GNU checksum format)
    token = raw.split()[0] if raw else ""
    if len(token) != 40 or not all(c in "0123456789abcdefABCDEF" for c in token):
        raise ValueError(
            f"Unexpected SHA1 checksum content from {url!r}: {raw!r}"
        )
    return token.lower()


def _sha1_of_file(path: Path) -> str:
    """Compute and return the SHA1 hex digest of a file.

    SHA1 is used here because it matches what DB-IP publishes on their
    checksum page. HTTPS provides transport integrity; SHA1 is used solely
    for file-identity verification against the published value, not as a
    cryptographic security primitive (acknowledged acceptable per ADR-0039).
    usedforsecurity=False signals this intent and suppresses OpenSSL-strict
    deprecation warnings.
    """
    h = hashlib.sha1(usedforsecurity=False)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _assert_within_dir(final_path: Path, root_dir: Path) -> None:
    """Raise ValueError if *final_path* is not under *root_dir*.

    Defence-in-depth path-traversal guard: asserts that *final_path* resolves
    within the intended ``geo_data`` install root. Callers must pass the actual
    root, not ``final_path.parent``, so the check is meaningful.
    """
    try:
        final_path.resolve().relative_to(root_dir.resolve())
    except ValueError:
        raise ValueError(
            f"Install path {final_path} is outside expected directory "
            f"{root_dir} — refusing install (path-traversal guard)."
        )


def _download_and_install(
    client: httpx.Client,
    mmdb_url: str,
    sha1_url: str,
    dest_path: Path,
    root_dir: Path,
) -> None:
    """Download, verify checksum, and atomically install one MMDB file.

    Steps:
    0. Require *mmdb_url* and *sha1_url* to start with 'https://' (runtime
       HTTPS guard — issue #643; raises ValueError, never a bare assert).
    1. Assert *dest_path* is within *root_dir* (path-traversal guard).
    2. Fetch the expected SHA1 from *sha1_url*.
    3. Stream the MMDB (gzip-compressed) from *mmdb_url* into a temp file,
       capping compressed bytes at ``_MAX_COMPRESSED_BYTES`` (issue #643).
    4. Verify SHA1 of the *compressed* download against the published checksum.
    5. Decompress to a second temp file, capping at ``_MAX_DECOMPRESSED_BYTES``.
    6. On match: atomically rename the decompressed file to *dest_path*.
    7. On mismatch or oversize: discard the temp files; raise ValueError
       (no partial install).

    The temp files live in the same directory as *dest_path* so ``os.replace``
    is atomic on POSIX (same filesystem).

    Parameters
    ----------
    client:
        An ``httpx.Client`` configured with ``follow_redirects=True``.
    mmdb_url:
        HTTPS URL for the gzip-compressed MMDB file.
    sha1_url:
        HTTPS URL for the SHA1 checksum of the compressed file.
    dest_path:
        Final install path for the decompressed MMDB.
    root_dir:
        Geo-data install root; *dest_path* must resolve within this directory.
    """
    import gzip

    # Runtime HTTPS guard (issue #643): the URL constants are hardcoded HTTPS,
    # but an explicit check here ensures a future URL-param refactor fails closed.
    # ADR-0039: download is over HTTPS only — enforced both structurally and
    # at call time. NB: a bare `assert` would be stripped under `python -O`
    # (PYTHONOPTIMIZE), silently disabling the guard — use an explicit raise
    # for security/data-integrity checks on untrusted input (docs/lessons.md).
    for label, url in (("mmdb_url", mmdb_url), ("sha1_url", sha1_url)):
        if not url.startswith("https://"):
            raise ValueError(
                f"{label} must start with 'https://'; got {url!r} — "
                "HTTPS is required (ADR-0039 / issue #643)."
            )

    # Path-traversal guard against the actual geo_data root
    _assert_within_dir(dest_path, root_dir)

    # Ensure destination directory exists
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # Fetch expected checksum first (fast; abort early if checksum page is down).
    # Best-effort: if the sidecar returns 404, log a WARNING and proceed without
    # checksum verification (ADR-0039 amendment, issue #633 — DB-IP stopped
    # publishing .sha1 sidecars for current monthly editions).
    # Any other HTTP error still aborts the fetch (e.g. 5xx transient failures).
    expected_sha1: str | None = None
    try:
        expected_sha1 = _fetch_sha1(client, sha1_url)
        logger.debug(
            "geo_mmdb_fetch: expected SHA1 for %s: %s", dest_path.name, expected_sha1
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            logger.warning(
                "geo_mmdb_fetch: SHA1 sidecar unavailable for %s (HTTP 404 from %r); "
                "proceeding without checksum verification — HTTPS transport integrity "
                "and size cap still apply (ADR-0039 amendment, issue #633).",
                dest_path.name,
                sha1_url,
            )
        else:
            raise

    # Download the compressed MMDB to a temp file
    gz_fd, gz_tmp = tempfile.mkstemp(
        dir=dest_path.parent, prefix=".fw_mmdb_dl_", suffix=".mmdb.gz"
    )
    mmdb_fd, mmdb_tmp = tempfile.mkstemp(
        dir=dest_path.parent, prefix=".fw_mmdb_", suffix=".mmdb"
    )
    try:
        # Stream compressed content to gz_tmp, enforcing the compressed-size cap
        # (issue #643 hardening). Without this cap a CDN-compromise adversarial
        # .gz could be written in full before the decompressed-size guard fires.
        # Real DB-IP files are ~20-60 MB gzipped; _MAX_COMPRESSED_BYTES = 200 MB.
        compressed_total = 0
        with os.fdopen(gz_fd, "wb") as gz_fh:
            gz_fd = -1  # fd now owned by gz_fh
            with client.stream("GET", mmdb_url, timeout=_DOWNLOAD_TIMEOUT) as stream:
                stream.raise_for_status()
                for chunk in stream.iter_bytes(chunk_size=1 << 16):
                    compressed_total += len(chunk)
                    if compressed_total > _MAX_COMPRESSED_BYTES:
                        raise ValueError(
                            f"Compressed download size exceeded {_MAX_COMPRESSED_BYTES} bytes "
                            f"while downloading {mmdb_url!r}. "
                            "Aborting — possible adversarial payload (no partial install)."
                        )
                    gz_fh.write(chunk)

        # Verify SHA1 of the compressed download (only when the sidecar was present)
        if expected_sha1 is not None:
            actual_sha1 = _sha1_of_file(Path(gz_tmp))
            if actual_sha1 != expected_sha1:
                raise ValueError(
                    f"SHA1 mismatch for {mmdb_url!r}: "
                    f"expected {expected_sha1!r}, got {actual_sha1!r}. "
                    "File discarded — no partial install."
                )

        # Decompress to the mmdb temp file, enforcing the size cap
        decompressed_total = 0
        with gzip.open(gz_tmp, "rb") as gz_in, os.fdopen(mmdb_fd, "wb") as mmdb_out:
            mmdb_fd = -1  # fd now owned by mmdb_out
            for chunk in iter(lambda: gz_in.read(1 << 16), b""):
                decompressed_total += len(chunk)
                if decompressed_total > _MAX_DECOMPRESSED_BYTES:
                    raise ValueError(
                        f"Decompressed size exceeded {_MAX_DECOMPRESSED_BYTES} bytes "
                        f"while decompressing {mmdb_url!r}. "
                        "Aborting — possible zip-bomb payload (no partial install)."
                    )
                mmdb_out.write(chunk)

        # Atomic install: rename decompressed temp → final dest
        os.replace(mmdb_tmp, dest_path)
        mmdb_tmp = ""  # mark as consumed so finally block skips cleanup
        sha1_note = "SHA1 verified" if expected_sha1 is not None else "no SHA1 sidecar"
        logger.info(
            "geo_mmdb_fetch: installed %s (%s)", dest_path.name, sha1_note
        )

    except Exception:
        # Clean up temp files on any failure
        if gz_fd >= 0:
            try:
                os.close(gz_fd)
            except OSError:
                pass
        if mmdb_fd >= 0:
            try:
                os.close(mmdb_fd)
            except OSError:
                pass
        raise

    finally:
        for tmp in (gz_tmp, mmdb_tmp):
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass


def ensure_dbs(
    city_db_path: Path,
    asn_db_path: Path,
    http_client_factory: Callable[[], httpx.Client] | None = None,
) -> None:
    """Ensure both DB-IP Lite MMDB files are present, downloading if absent.

    Downloads only the files that are missing (idempotent for present files).
    Raises on failure so the caller (``MmdbGeoEnricher._try_first_run_fetch``)
    can log a warning and proceed gracefully.

    Parameters
    ----------
    city_db_path:
        Destination path for the City Lite MMDB.
    asn_db_path:
        Destination path for the ASN Lite MMDB.
    http_client_factory:
        Optional factory returning an ``httpx.Client``. Injected in tests to
        avoid real network calls. Defaults to a factory that creates an
        ``httpx.Client`` with ``follow_redirects=True`` (required because
        DB-IP month-specific URLs are served via HTTP 302 redirect).
    """
    year, month = _current_year_month()
    city_url, asn_url, city_sha1_url, asn_sha1_url = _build_urls(year, month)

    # Both DB files must live within the same root directory; use city_db_path's
    # parent as the geo_data root for the path-traversal containment check.
    root_dir = city_db_path.parent

    def _default_factory() -> httpx.Client:
        return httpx.Client(follow_redirects=True)

    factory = http_client_factory or _default_factory
    client = factory()

    try:
        if not city_db_path.exists():
            logger.info(
                "geo_mmdb_fetch: City DB not found at %s — downloading...",
                city_db_path,
            )
            _download_and_install(client, city_url, city_sha1_url, city_db_path, root_dir)

        if not asn_db_path.exists():
            logger.info(
                "geo_mmdb_fetch: ASN DB not found at %s — downloading...",
                asn_db_path,
            )
            _download_and_install(client, asn_url, asn_sha1_url, asn_db_path, root_dir)
    finally:
        client.close()
