# firewatch-clamav

FireWatch source plugin that turns [ClamAV](https://www.clamav.net/) malware detections on
this machine into FireWatch `SecurityEvent`s — so a malware hit (e.g. an EICAR test file)
appears on the dashboard, scored and escalated like any other threat.

Registered as `clamav` under the `firewatch.sources` entry point (zero `firewatch-core`
edits — see `PLUGIN_CONTRACT.md`). Depends on `firewatch-sdk` only.

## Important — ClamAV detects *when it scans*

**Read this before you rely on FireWatch to catch malware instantly.** ClamAV is not an
always-watching antivirus by default — it detects malware **only when something runs a
scan**. A plain `clamd` install with a manual `clamscan` only reports what you told it to
scan, and only at the moment you ran it.

For *instant*, drop-a-file-and-see-it-on-the-dashboard detection (the EICAR walkthrough
this plugin is built to support), you need **on-access scanning**:
[`clamonacc`](https://docs.clamav.net/manual/OnAccess.html), ClamAV's `fanotify`-based
on-access daemon, watching the directories you care about.

Configuring/installing ClamAV itself (including `clamonacc`) is **out of scope for this
plugin** — FireWatch never ships or manages an agent on the monitored machine
([ADR-0021](../../../docs/adr/0021-suricata-ingestion-shipper-push-path.md)). The
step-by-step setup guide lands with the onboarding wizard (M2.6); until then, see
[docs.clamav.net](https://docs.clamav.net/) for `clamd.conf` / `clamonacc` setup.

## Collection modes (local only — issue #2; push/SSH-pull are out of scope)

Local-first, journald-first (ADR-0065 §1/§3): this plugin collects from the machine
FireWatch runs on with zero network configuration.

- **`journald`** (default) — reads ClamAV's detections from the systemd journal. Works out
  of the box on any mainstream systemd distro (Arch, Ubuntu, Fedora, Debian) with zero path
  configuration, provided ClamAV logs to syslog (`clamd.conf`'s `LogSyslog true`, which is
  also what `clamonacc` uses by default).
- **`file`** — tails ClamAV's plain-text log file directly (`log_path`, default
  `/var/log/clamav/clamav.log`). The fallback for non-systemd hosts, or any setup that
  isn't logging through syslog.

## What gets reported

A ClamAV `<path>: <signature> FOUND` detection line becomes a `SecurityEvent` with:

- `category="malware"`, `severity="high"` (ADR-0067 D4 / ADR-0069 — malware present on
  disk is a genuine, load-bearing assertion that escalates through the severity gate).
- `rule_name` / `rule_id` — the ClamAV signature name (e.g. `Win.Test.EICAR_HDB-1`).
- `payload_snippet` / `file_name` — the infected file's path / basename.
- `action` — `ALERT` for a plain detection; `BLOCK` when ClamAV was configured to
  remove/quarantine the file and that outcome appears in the log stream (never fabricated
  — a plain detection is never reported as `BLOCK`).

MITRE ATT&CK / CAPEC fields are deliberately left unset: a ClamAV signature name carries
no such metadata to derive from (unlike Suricata's ET Open `mitre_*` tags), and
PLUGIN_CONTRACT.md's discipline is to map only what's derivable, never fabricate.

## Testing with EICAR

Download the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) (a
harmless string every antivirus engine recognizes as "malware" by convention) to a
directory ClamAV scans, and either run `clamscan` on it manually or let `clamonacc`
on-access scanning pick it up. Either way, a `FOUND` line reaches this plugin's configured
mode (journald or file) and a `malware` / `high`-severity event appears on the dashboard.
