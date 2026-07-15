"""Typed, catchable errors for the local-machine log readers (ADR-0065 §3).

Both readers raise one of these — never a bare subprocess/OS traceback — when the
local machine cannot supply logs at all (missing binary, permission denied,
non-systemd host, unreadable file). Each message carries operator-facing
remediation text so a consuming plugin's ``health_check()`` / diagnostics path
can surface it verbatim (mirrors ``firewatch_suricata.collector.SSHConnectionError``).

Mid-stream, transient hiccups (a single malformed line, one bad record) are
logged and skipped — they do NOT raise. These errors are reserved for
"the reader cannot run at all" conditions, raised before any record has been
yielded from the current stream.
"""
from __future__ import annotations


class LocalReaderError(Exception):
    """Base class for local-log reader errors carrying remediation text."""


class JournaldUnavailableError(LocalReaderError):
    """``journalctl`` is absent, the journal is unreadable, or the host has no systemd.

    Raised by ``JournaldReader`` before/while establishing a stream — never after
    records have already been yielded from a productive run (a later transient
    failure is logged and the generator simply ends, per the "never raise out of
    the loop" hard rule once streaming is underway).
    """


class FileTailUnavailableError(LocalReaderError):
    """The tailed file cannot be opened, or a resume cursor is malformed.

    Raised by ``FileTailReader`` at start-of-read — never mid-poll (a later
    transient read hiccup, e.g. the file briefly disappearing during rotation,
    is retried on the next poll instead).
    """
