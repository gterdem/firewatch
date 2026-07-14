# ADR-0065: Local-First Endpoint Collection & Solo/Hub Topology — journald-First SDK Readers, Cursor-Based Resume

**Date:** July 2026
**Status:** Accepted (formalizes maintainer decisions settled 2026-07-14; complements ADR-0021 — does not reopen it)

**Decision:** Four related decisions, recorded together because they form one contract for the
endpoint-source milestones (M1 `clamav`/`linux_auth`, M2 hub push):

1. **The local-first collection principle.** Every *endpoint* source plugin (one that reads a
   machine's own logs — as opposed to a network/cloud source like Suricata or Azure WAF) MUST be
   able to collect from the machine FireWatch runs on, by default, with **zero network
   configuration**. A single-machine ("Solo") install is self-sufficient out of the box.
   Remote transports (push via standard shippers, SSH-pull) are **additive** modes, never the
   only mode. This forbids: shipping an endpoint source that requires a forwarder, listener
   port, or credential to monitor the local machine; and (per ADR-0021, unchanged) any
   FireWatch-installed daemon on monitored machines.

2. **Topology naming: Solo / Hub.** Two deployment topologies — **Solo** (FireWatch protects
   the machine it runs on; local collection) and **Hub** (an always-on box collects from a
   fleet via push/pull). Topology is orthogonal to the AI-depth profiles
   (rules-only / lean / default, ADR-0042). **One plugin serves both topologies with one
   `normalize()`:** local reading covers Solo; the hub transport reuses the same mapping.
   "FireWatch-Lite" is retired as a name; "home" is docs prose, never a UI mode; there is no
   second dashboard. Solo grows into Hub with zero re-architecture — the data model is already
   multi-instance on `(source_type, source_id)` (ADR-0016, ADR-0031).
   *Boundary deliberately kept open:* M2 anticipates dual-flavor plugins (a plugin implementing
   both `PullSource` and `PushSource`, instance flavor selecting the entrypoint — contract v1.4,
   own short ADR at pickup). The local readers therefore MUST NOT be entangled with plugin
   flavor: they are plain iterators yielding `(record, cursor)` that any entrypoint can drive.

3. **journald-first substrate, cursor-based resume.** The SDK provides a shared **journald
   reader** as the primary local-log interface, with a plain **file-tail reader** as the
   non-systemd fallback. journald is the one log interface present and consistent across the
   mainstream distros (Arch, Ubuntu, Fedora, Debian) — no per-distro path tables; Arch-family
   systems have no classic `/var/log/auth.log` at all. The reader shells out to
   `journalctl -o json` (zero native dependencies) rather than binding libsystemd.
   Resume is **cursor-based, not timestamp-based**: systemd defines the entry cursor as "an
   opaque text string that uniquely describes the position of an entry in the journal and is
   portable across machines, platforms and journal files"
   ([systemd.journal-fields(7), `__CURSOR`](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html)),
   surfaced in every `-o json` record (Journal JSON Format address fields,
   [systemd.io/JOURNAL_EXPORT_FORMATS](https://systemd.io/JOURNAL_EXPORT_FORMATS/)), and
   `journalctl --after-cursor=` / `--cursor-file=` is the documented mechanism to "continually
   read the journal by sequentially calling journalctl"
   ([journalctl(1)](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)).
   `--after-cursor` is exclusive of the cursor's own entry, so resume neither duplicates nor
   skips. **Deliberate deviation from the documented pattern:** we persist the cursor via
   `ctx.kv` (the plugin's ScopedKV view), *not* `--cursor-file` — ADR-0025 makes `ctx.kv` the
   only plugin persistence handle; a loose cursor file would be per-instance state outside the
   store, invisible to backup and to the one-class Postgres swap (ADR-0007). The readers
   themselves persist nothing: callers pass the last cursor in and store the new one.

4. **Placement: `firewatch-sdk` only.** The readers live in the SDK
   (`firewatch_sdk/localhost/`), consumed by `clamav`, `linux_auth`, and future endpoint
   plugins. The SDK imports neither core nor plugins (the dependency rule); core never imports
   the readers. They are **SDK utilities, not contract surface** — no PLUGIN_CONTRACT version
   bump; the `PullSource.collect()` watermark and `ctx.kv` semantics (ADR-0025/0027) are
   unchanged.

**Alternatives considered:**
- **Per-plugin log reading** (each endpoint plugin implements its own journald/file handling) —
  rejected: N copies of the multi-distro, rotation, and cursor logic; the ClamAV and auth
  plugins would immediately diverge on the exact bugs this centralizes.
- **File-tail as the primary interface** (`/var/log/auth.log`, `/var/log/clamav/…`) — rejected
  as primary: paths and formats differ per distro and Arch-family installs have no syslog files
  by default; kept as the fallback for non-systemd hosts and file-only daemons.
- **python-systemd C bindings** — rejected for now: a native build dependency (libsystemd
  headers) on every install and container image, against a subprocess that is already on every
  systemd machine. Revisit only if profiling shows the subprocess boundary matters.
- **Timestamp-based resume** (`--since`, or the store watermark alone) — rejected:
  `__REALTIME_TIMESTAMP` is `CLOCK_REALTIME` wall-clock (systemd.journal-fields(7)) — it is
  neither unique (multiple entries per microsecond) nor monotonic (NTP steps, clock changes),
  so a timestamp resume duplicates or drops entries at exactly the moments a security tool
  must not. The cursor exists to solve this; use it.
- **Readers in `firewatch-core`** — rejected: plugins never import core; it would put shared
  plugin machinery on the wrong side of the dependency rule.
- **A separate "FireWatch-Lite" app / fork for home endpoints** — rejected: endpoint security
  is source plugins + onboarding on the existing rails; a fork implies a lesser product when
  the differentiator is that detection is identical everywhere.
- **A FireWatch endpoint agent** — rejected in ADR-0021 and not reopened here; standard
  shippers (rsyslog default, Vector recommended) remain the remote transport tier. The only
  capability this forgoes is EDR-style sub-second endpoint interdiction, which no stated goal
  needs; reopening that boundary is one deliberate ADR conversation.

**Reasoning:** Single-machine users are a first-class audience, not a degraded enterprise case.
The verified market gap (2026): every open-source SIEM with antivirus integration
(Wazuh-class) demands an agent per endpoint plus a heavyweight manager stack — minimum
4 CPU / 8 GB / 50 GB and weeks of tuning ([Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html));
no polished, lightweight, local-first option exists. FireWatch's answer must therefore work on
the machine it's installed on with zero configuration ceremony — that is the Solo install, and
it is also the on-ramp: the same plugins, data model, and dashboard scale to Hub because
multi-instance identity was built in from ADR-0016. Reading journald once, in the SDK, is what
makes "multi-distro" a property every endpoint plugin inherits instead of re-earns.

**Consequences:**
- M1.1 (`localhost` readers: `journald.py`, `filetail.py`) implements this ADR; M1.2/M1.3
  (`clamav`, `linux_auth`) consume the readers; M2's push mode adds the hub flavor against the
  same `normalize()` and files its own dual-flavor contract ADR at pickup.
- Every endpoint-source issue states which collection modes are in scope; local mode is always
  the first shipped.
- Containerized Solo installs cannot see the host journal without documented bind-mounts and
  permissions — the Solo deployment docs must cover both bare-metal and container paths
  (tracked in M1.5).
- Docs/wizard language uses Solo/Hub for topology and rules-only/lean/default for AI depth;
  no "Lite", no "home mode".
