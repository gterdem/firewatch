"""FireWatch Linux auth & intrusion signals source plugin.

Local-only (M1, issue #3): journald ``authpriv``/auth-relevant identifiers first
(ADR-0065), plain file-tail of ``/var/log/auth.log``-style files as the fallback
for non-systemd hosts. Push mode (fleet forwarding) is out of scope — M2.1.
"""
