"""Syslog/CEF listener substrate -- thin re-export of firewatch_syslog.listener.

The transport layer (UDP datagram handling, TCP line framing, backpressure,
MAX_BATCH_SIZE, idle-timeout, max-connections) is provided by the shared
firewatch_syslog package. This module re-exports the public surface so that:

  1. firewatch_syslog_cef.listener.run_udp_listener / run_tcp_listener /
     MAX_BATCH_SIZE are accessible without importing firewatch_syslog directly
     in the tests (the test's substrate assertion only requires these symbols
     to be reachable from firewatch_syslog_cef.listener).

  2. SyslogCefSource.start() calls the shared functions directly -- no code
     duplication. Adding a new transport or backpressure strategy in
     firewatch_syslog automatically benefits this plugin.

  3. pfSense (#605) and future push plugins can follow the same pattern.

ADR-0023 / ADR-0030: Transport lifecycle and backpressure rules are
implemented once in firewatch_syslog and inherited here.
"""
from firewatch_syslog.listener import (  # re-export shared substrate
    MAX_BATCH_SIZE,
    EmitCallback,
    SyslogListener,
    _decode_line,
    _make_raw,
    run_tcp_listener,
    run_udp_listener,
)

__all__ = [
    "MAX_BATCH_SIZE",
    "EmitCallback",
    "SyslogListener",
    "_decode_line",
    "_make_raw",
    "run_tcp_listener",
    "run_udp_listener",
]
