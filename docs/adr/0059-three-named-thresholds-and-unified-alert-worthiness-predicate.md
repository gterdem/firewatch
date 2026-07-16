# ADR-0059: Three Named, Purpose-Specific Thresholds — and a Shared Alert-Worthiness Predicate Across Banner and Notifications

**Date:** June 2026
**Status:** Accepted

**Implements / extends:** ADR-0058 (action-aware deterministic escalation axis — **stays Accepted**;
this ADR builds on its D2 escalation verdict and does not reopen it). Reshapes the scope of issue #650
and motivates the IA-divide issue #661.
**Relates to / honours:** ADR-0036 (score & confidence presentation — band-and-axis stay separable,
never collapsed), ADR-0033 (`onAction` SIEM-now/SOAR-later seam — the greyed auto-block tier),
ADR-0015 (tiered-autonomy ceiling), ADR-0019 (rjsf config convention — and the deliberate deviation
recorded below), ADR-0006 (SecretStr masking for `webhook_url`), ADR-0043 (the `/ai` page is the
**AI-engine** accountability surface — alerting does not belong to it).

---

## Context

ADR-0058 D2 made the dashboard triage banner worthy on **`escalation.tier ≤ 2` OR
`threat_level ∈ {CRITICAL, HIGH}`** — but it **hard-coded** the score-band half of that rule at
CRITICAL/HIGH. Investigating that revealed a deeper problem: FireWatch has *several distinct gating
decisions* that were either hard-coded, mislabelled, or quietly conflated under one name
(`alert_threshold`). All facts below are code-confirmed against `origin/main`.

1. **Three genuinely different decisions, only one of them named honestly.** The product makes three
   independent gating choices, and they had been muddled together:
   - **"Push this to my chat channel?"** — gated by `alert_threshold`
     (`packages/firewatch-sdk/.../config.py:94`, default `CRITICAL`), consumed only by the webhook
     notifier (`packages/firewatch-core/.../adapters/webhook_notifier.py`,
     `_meets_threshold(threat.threat_level, runtime.alert_threshold)`). This is a *notification* gate.
   - **"Do I trust this AI verdict enough to let it move a score?"** — gated by
     `CONFIDENCE_BOOST_THRESHOLD` (`packages/firewatch-core/.../scoring.py:47`, default `0.7`). A
     *model-trust* gate. It is a module-level constant, **not** a config field and **not** exposed in
     any UI today. Historically this concept was loosely referred to as an "alert threshold," which
     was the core confusion: it has nothing to do with alerting — it is about *trusting the model*.
   - **"Does this actor enter the triage banner by severity?"** — hard-coded `{CRITICAL, HIGH}` inside
     `deriveTriageActors` (`frontend/src/routes/DashboardRoute.tsx`). A *triage-surfacing* gate, with
     **no operator control** at all.

2. **The notification path is escalation-blind.** A tier-1 *allowed-through* SQLi that scores MEDIUM
   banners on the dashboard (ADR-0058 D2) but is **never** sent to the operator's webhook, because the
   notifier gates on severity band only. That is exactly the threat ADR-0058 was written to surface,
   re-buried on the notification path.

3. **The one operator knob lived in the wrong card.** `alert_threshold` is a *global* alerting control
   (it gates all alerts — rule-based and AI alike) but its form lived under the **"Local AI"** engine
   panel (`frontend/src/components/LocalAiPanel.tsx`, "Alerting" section group; a stale local-only
   duplicate also sits in `OllamaPanel.tsx`). This contradicts ADR-0043 (the AI surface is scoped to
   AI-engine accountability).

The naming muddle was the root cause. The fix is **not** to unify the three decisions behind one
shared threshold — they are different questions with different right answers. The fix is to give each
its **own name, own default, own home**, and to share only the *mechanism* (a single predicate) where
two surfaces must agree.

## Decision

### D1 — Three separately-named, purpose-specific thresholds (NOT one shared threshold)

FireWatch exposes three distinct controls. Each has its own name, default, and card. They are never
collapsed into a single value.

| Control (UI label) | Question it answers | Backend source | Default | Card |
|---|---|---|---|---|
| **Notification threshold** | "Push to Discord / Slack / webhook?" | `RuntimeConfig.alert_threshold` (field name unchanged for compat) | **CRITICAL** | Notifications card (#661) |
| **AI confidence threshold** | "Trust this AI verdict enough to move a score?" | `CONFIDENCE_BOOST_THRESHOLD` (`scoring.py`) | **0.7** | AI Engine card (`/ai`) |
| **Triage threshold** | "Enter the triage banner by *severity*?" | net-new operator control feeding `deriveTriageActors`' band half | **HIGH** | Escalation Policy card (#650) |

- **Notification threshold.** The renamed-in-UI `alert_threshold`. The **underlying SDK field name
  stays `alert_threshold`** to avoid a contract break / migration; **every UI label and any new label
  reads "Notification threshold."** UI subtitle: *"Send to Discord / Slack / webhook at or above this
  severity."* Default stays **CRITICAL** — quiet chat by design.
- **AI confidence threshold.** The `CONFIDENCE_BOOST_THRESHOLD` gate, reframed honestly:
  *"Minimum confidence before an AI verdict raises a score."* Default **0.7**. **It is not exposed in
  any UI today** — exposing it (as an editable dial on the AI Engine card) is **net-new** and is
  scoped in #650's confidence-dial item / the AI Engine card. Whether it stays a constant or becomes a
  config-store value is an implementation detail for that work; this ADR fixes its *name, default, and
  home*.
- **Triage threshold.** A net-new operator control for the band half of the banner predicate. Default
  **HIGH**, which **preserves today's banner band exactly** (the hard-coded `{CRITICAL, HIGH}` set =
  "band ≥ HIGH"). UI subtitle must state: *"The action-aware escalation tier always surfaces in the
  banner regardless of this threshold"* — so a low-score allowed-through / alert-only threat still
  banners even when the triage threshold is raised.

**Why three, not one (the dissolved D4).** An earlier draft asked whether to *unify* into one shared
`is_alert_worthy` threshold and what its single default should be. Maintainer dissolved that question:
unifying would force "trust the model" (0.7), "push to chat" (CRITICAL), and "show in banner" (HIGH)
to share a value, which is meaningless — they are different units (confidence vs severity) and
different decisions. Separation removes the shared-default question entirely; each control keeps its
own correct default.

### D2 — One *predicate*, shared by the two surfaces that must agree on alert-worthiness

The thresholds are separate, but where two surfaces evaluate the **same** notion of "alert-worthy by
severity-band OR escalation-tier," they must use **one shared implementation** so they cannot drift
again. Define a pure helper:

```
is_alert_worthy(threat, threshold) :=
    band_meets(threat.threat_level, threshold)            # severity-band axis (ADR-0036)
    OR threat.escalation.auto_escalate_tier               # action-aware axis (ADR-0058 D2; tier ≤ 2)
```

This is a **shared mechanism**, not a shared *threshold*: each caller passes its own band threshold.

- **The banner** calls `is_alert_worthy(threat, triage_threshold)` — its band half reads the new
  **Triage threshold** (D1) instead of the hard-coded `{CRITICAL, HIGH}`. The escalation-tier half is
  unchanged.
- **The notifier** calls `is_alert_worthy(threat, notification_threshold)` for its band half (the
  renamed `alert_threshold`), gaining the action-aware axis it lacks today **subject to D3's toggle**.

The two axes are **OR-combined and never collapsed into a single number** (ADR-0036). Per-detection
`severity` + `auto_escalate` (the ADR-0058 D1 `ESCALATION_POLICY` registry) feed the tier axis; they
are not re-summed into the band.

### D3 — Notification escalation-awareness: opt-in toggle, default OFF (notifications stay quiet)

With the thresholds separated, a design residue must be resolved explicitly: the banner is
escalation-aware (tier surfaces regardless of band) but notifications are severity-only — so a tier-1
allowed-through threat with a low score **banners but does not notify**. Should the notification path
*also* fire on auto-escalate tiers?

**Decision: add an optional toggle "Also notify on auto-escalating detections", defaulting OFF.
Notifications are severity-only unless the operator opts in.**

- **Default OFF** preserves the deliberate "quiet chat" intent of the CRITICAL notification default.
  Auto-escalation fires on `tier ≤ 2` (every allowed-through and every alert/log-only detection); with
  the toggle ON-by-default, a CRITICAL notification floor would still flood chat with low-score
  allowed-through events — defeating the purpose of a high notification threshold.
- **The toggle exists** so the gap is closed *honestly and controllably*, not silently. The original
  "banners-but-never-notifies" behaviour was a hidden inconsistency with no operator control; the
  resolution is an explicit, operator-owned switch — not a forced behaviour in either direction. An
  operator who wants the action-aware signal in chat turns it on; the dashboard banner remains the
  always-on surface for the action-aware axis.
- **Mechanically:** with the toggle OFF the notifier passes only the band axis
  (`band_meets(threat_level, notification_threshold)`); with it ON the notifier uses the full
  `is_alert_worthy(threat, notification_threshold)` predicate (band OR tier). New SDK field:
  `notify_on_auto_escalate: bool = False` on `RuntimeConfig` (additive, backward-compatible). It lives
  in the Notifications card (#661) next to the Notification threshold.

This is the only **new** config field this ADR introduces; the three thresholds themselves add no new
backend fields beyond the Triage threshold's operator control (see Blast radius).

### D4 — Notifications config is divided OUT of the AI-engine card (IA divide, #661)

The Notification threshold (`alert_threshold`), `webhook_url` (+ its `webhook_url_set` honest signal,
ADR-0006), `alert_on_sync`, and the new `notify_on_auto_escalate` toggle move out of the "Local AI"
panel into their own **Notifications card** (#661). The stale `OllamaPanel.tsx` alerting duplicate is
removed. **Backend config fields do not move** — they remain on `RuntimeConfig`; this is an **IA/UI
regrouping**, not a schema migration. (ADR-0043: the AI page owns AI accountability, not global
alerting.)

### D5 — The Escalation Policy card is GLOBAL and schema-driven; deviation from rjsf recorded

Per the modular-UI rule the card is **global** (install/uninstall a source never adds/removes it) and
is **not** a per-source page. "Schema-driven" here means **driven by the typed `RuntimeConfig` +
`ESCALATION_POLICY` shape**, not necessarily hand-built rjsf:

- **Deviation from ADR-0019 recorded.** ADR-0019 adopted rjsf for **per-source `config_schema()`**
  forms. The **runtime** config surfaces (`LocalAiPanel`, `ApiKeyPanel`) are deliberately *hand-built*
  React today — there is no runtime-config JSON-Schema endpoint, and the policy card needs rich,
  non-form widgets (live 24h hit-counts, the greyed enforcement staircase, the dual-axis explainer)
  that rjsf does not express well. The card therefore follows the **established hand-built
  runtime-config pattern**. If a future ADR adds a runtime-config schema endpoint, the card can
  migrate; that is out of scope here.

### D6 — Read-only exposure of the escalation policy + live hit-counts

The Escalation Policy card shows the `ESCALATION_POLICY` registry (per-detection `severity` +
`auto_escalate`) and a live 24h hit-count per rule. `ESCALATION_POLICY` is **registered at import and
finalized** (`escalation/policy.py` — `register()` raises after `finalize()`), so it is **read-only at
runtime**: the card *displays* the declared policy; it does not mutate the registry. Hit-counts are
**derived** from persisted `ThreatScore.detections` over a 24h window (no new detection table) — net-new
read-API work, scoped in #650.

## Module shape (sketch — for the implementers)

- **Backend (firewatch-core / firewatch-api), small:**
  - `escalation/` (existing) gains a pure helper, e.g. `escalation/worthiness.py` —
    `is_alert_worthy(threat, threshold) -> bool` (the D2 predicate, no I/O), so the **banner-feed
    serializer and the notifier share one implementation** and cannot drift again.
  - `webhook_notifier.check_and_alert` gates on the band axis by default and on the full
    `is_alert_worthy(...)` predicate when `notify_on_auto_escalate` is set (D3).
  - SDK: additive `notify_on_auto_escalate: bool = False` on `RuntimeConfig` (D3).
  - A read endpoint (e.g. `routes/config.py` / `routes/threats.py`) returns the escalation policy
    registry view + 24h per-rule hit-counts (aggregated from persisted `ThreatScore.detections`).
- **Frontend — two cards, by concern:**
  - **Notifications card (#661):** `NotificationThresholdField` (label "Notification threshold") ·
    `WebhookField` (+ `alert_on_sync`) · `NotifyOnAutoEscalateToggle` (D3). Removed from
    `LocalAiPanel.tsx`; stale `OllamaPanel.tsx` copy deleted.
  - **Escalation Policy card (#650):** `components/alerting/AlertingPolicyPanel.tsx` (shell)
    decomposed by concern — `TriageThresholdField` (label "Triage threshold", subtitle noting the tier
    always surfaces) · `EscalationPolicyTable` (severity + auto_escalate + 24h hit-count rows) ·
    `DualAxisExplainer` · `EnforcementStaircase` (WARN / require-approval active; auto-block greyed
    "coming with SOAR").
  - **AI Engine card (`/ai`):** `AiConfidenceThresholdField` (label "AI confidence threshold",
    subtitle "Minimum confidence before an AI verdict raises a score") — net-new exposure of
    `CONFIDENCE_BOOST_THRESHOLD`.
  - `deriveTriageActors` reads the Triage threshold for its band half (replaces hard-coded
    `{CRITICAL, HIGH}`).

## Standard alignment & deviations

- **Per-concern notification routing.** Mirrors how SIEM/SOAR products keep *severity-based
  notification routing* distinct from *board/triage surfacing* and from *detection confidence* —
  Elastic detection-rule **actions** route on rule severity, separate from the model/risk signals;
  Splunk alert **trigger conditions** + **actions** likewise separate "what fires a notification" from
  "what an analyst sees." FireWatch's three named thresholds make each decision explicit and
  operator-owned rather than conflating them under one mislabelled knob.
- **Two axes, not one number.** Consistent with **OCSF 1.8.0** carrying `severity_id` *and* a separate
  finding/`disposition_id` signal, and with **Elastic** carrying `risk_score` *and* `severity` as
  distinct fields — band and disposition are orthogonal. ADR-0036 already mandates band/axis
  separability; this ADR enforces it on the banner and (opt-in) notification paths.
- **NIST SP 800-61r2.** Escalation/notification is Detection-&-Analysis; enforcement (the greyed
  auto-block tier) is Containment — the SIEM-now/SOAR-later boundary (ADR-0033/0015) is preserved.
- **rjsf deviation recorded** in D5 (runtime config is hand-built; rjsf is per-source only, ADR-0019).
- **ADR-0006** — `webhook_url` stays `SecretStr`; the card uses the `webhook_url_set` honest signal,
  never echoing the secret.

## Blast radius

- **SDK** — one additive field: `notify_on_auto_escalate: bool = False` (D3). `alert_threshold` /
  `webhook_url` / `alert_on_sync` unchanged; no rename, no contract break. The Triage threshold's
  persistence (config field vs derived) is an implementation choice for #650; if it becomes a
  `RuntimeConfig` field it is additive with default HIGH.
- **Core** — additive `is_alert_worthy` helper; `webhook_notifier` gate becomes band-axis +
  (opt-in) tier-axis. `CONFIDENCE_BOOST_THRESHOLD` reframed/relabelled; exposing it editable is #650.
- **API** — additive read endpoint for the policy view + 24h hit-counts.
- **Frontend** — Notifications card gains the divided-out controls + the opt-in toggle; AI Engine card
  gains the AI confidence threshold; Escalation Policy card gains the Triage threshold;
  `deriveTriageActors` reads the Triage threshold; stale `OllamaPanel` alerting copy removed.
- **Golden oracle** — **untouched.** Scores do not move; this is a surfacing / notification-gating /
  naming / IA change, orthogonal to ADR-0058 D5's (separate) re-bless.

## Alternatives considered

- **Unify into one shared `is_alert_worthy` threshold (the original draft framing).** Rejected by
  Maintainer and re-evaluated here — the three decisions are different units (confidence 0–1 vs severity
  band) and different questions; one shared value is meaningless and forces a fake default. Separation
  dissolves the shared-default question. This ADR keeps the shared *predicate* (D2) where two surfaces
  genuinely agree, but not a shared *threshold*.
- **Keep calling the confidence gate an "alert threshold."** Rejected — it is a model-trust gate, not
  an alerting gate; the conflation was the root confusion.
- **Leave the banner band hard-coded.** Rejected — operators cannot tune triage sensitivity, and the
  band cannot diverge from the notification threshold safely.
- **Make notifications escalation-aware by default (toggle ON / forced).** Rejected as the default —
  with a CRITICAL notification floor, firing on every `tier ≤ 2` detection floods chat and defeats the
  quiet default. Provided as an **opt-in** instead (D3).
- **Keep notifications severity-only forever (no toggle).** Rejected — recreates the silent
  "dangerous-but-low-score never reaches me" gap with no operator recourse. The opt-in toggle resolves
  it honestly.
- **Add a separate `banner_threshold` *and* re-use it for notifications.** Rejected — that is the
  unify-the-threshold path again; the Triage threshold and Notification threshold answer different
  questions and keep different defaults (HIGH vs CRITICAL).
- **Amend ADR-0058 in place.** Rejected — ADR-0058 is Accepted and the supersede-don't-edit rule
  applies; this is a *new* decision (three named thresholds + shared predicate + opt-in notification
  escalation + IA divide) that references 0058 rather than editing it.

## Reasoning

ADR-0058 gave us the honest second axis and put it on the banner. The remaining problem was **naming
and ownership**: three different gating decisions hid behind one mislabelled knob in the wrong card,
the notifier ignored the action-aware axis, and the banner band was un-tunable. Three separately-named
thresholds — Notification (push to chat, CRITICAL), AI confidence (trust the model, 0.7), Triage
(banner by severity, HIGH) — give operators three honest mental models instead of one muddled one.
A single `is_alert_worthy` predicate keeps the two surfaces that must agree from drifting, while the
opt-in `notify_on_auto_escalate` toggle resolves the banner-vs-notification residue explicitly and
keeps chat quiet by default. Zero score movement, no contract break beyond one additive boolean.

## Consequences

- Reshapes #650 (Escalation Policy card: Triage threshold + policy table + hit-counts + confidence
  framing + enforcement staircase) and #661 (Notifications card: Notification threshold + webhook +
  `alert_on_sync` + the opt-in auto-escalate toggle), both in milestone #19.
- The "AI confidence threshold" becomes a net-new editable surface on the AI Engine card.
- The old D4 open question (single shared default) is **dissolved** by separation — no Maintainer decision
  pending on defaults.
- The `ai-engine-invariants` skill still governs any touch of the AI path; this ADR touches the
  notification gate, the confidence label/exposure, and IA — not score math.

## Amendment 1 (2026-07-15, A1.2 revised 2026-07-16): escalation-aware notifications ON by default; notification model stays on/off + threat level, per-state preferences deferred; OS push deferred

**Status:** Accepted — direct Maintainer decision (2026-07-15, verbatim intent recorded below).
House rule honoured: D3's text above is never edited; this amendment supersedes its *default*
(and only its default). Implementing issue: **#74**. Coupled with ADR-0070 Revision 1 (the
intensity states this default serves).

### The decision (Maintainer, verbatim intent)

- **HIGH ALERT** (an actor in the escalation tiers — ADR-0070 R2/R3, and Tier 1): *"notification
  should be done; by default, it can be discord/slack hook (or email in the future)."*
- **INFORM** (observed-stratum activity): *"no notification by default — but it should be
  customizable. If someone wants to get slack/discord notification on INFORM, they should be
  able to."*
- **OS/desktop push:** *"can be implemented in the future, not now."*

### A1.1 — `notify_on_auto_escalate` defaults to `True`

The D3 toggle's default flips OFF → ON: when a webhook is configured, the notifier uses the
full `is_alert_worthy(threat, notification_threshold)` predicate (band OR tier ≤ 2) without
opt-in. Existing persisted configs keep their stored value — only the default for absent
values changes (no migration). The band half (`alert_threshold`, default CRITICAL) is
unchanged.

**Why the original default no longer holds (the premise moved, not the reasoning).** D3 chose
OFF because *"auto-escalation fires on `tier ≤ 2` (every allowed-through and every alert/log-only
detection)"* — true when written, and notifying that population would have flooded chat. The
ADR-0067 assertion gate (merged in #42) changed the distribution the default was calibrated
against: Tier 2 now requires a qualifying assertion, so **the set of actors eligible to notify
equals the triage-queue population by construction**. The queue's flood controls (ADR-0067's
gate, ADR-0070's queue bar, ADR-0068's tripwire) are now the notification path's flood controls
too — one set of numbers, one oracle. A HIGH ALERT that reaches only a browser tab at 3am warns
no one; post-gate, the quiet-chat property is preserved by the gate, not by the toggle.

**Correction (2026-07-16 ruling, this batch): stock vs. flow — the gate bounds the SET, not the
CADENCE.** An earlier draft of the paragraph above said "notification volume equals triage-queue
volume"; that conflates a stock with a flow. The queue is a *population* (which actors qualify
right now); notification firing is a *rate* (how often the notifier is invoked for them) — and
today the rate is unbounded by anything the gate controls. Mechanics, verified in code:
`webhook_notifier.check_and_alert` is **stateless** — gate, then post; no dedup, no cooldown, no
memory of having notified (`webhook_notifier.py`, whole file). Its caller,
`pipeline.background_analyze_and_alert`, is scheduled **per ingested event** on `POST /logs`
(`ingest.py:232`) and per distinct source IP per batch on `POST /logs/batch` (`ingest.py:308`).
Consequence: an actor that *stays* in the queue re-notifies on every ingest-triggered analysis —
the Maintainer's 50/min brute force, pushed one event at a time, is **~50 webhook posts per
minute for the duration of the attack**. Note this is not a defect A1.1 creates: the band path
already repeat-fires today under the same statelessness (a CRITICAL-band actor re-notifies on
every analysis via `band_meets`); flipping the default extends the exposure to the tier axis
and to a population that, post-ADR-0070, is *designed* to be in the queue for hours.

**Firing cadence is therefore #74's transition semantics, in scope with the flip — for both
axes:** the notifier fires when an actor's alert-worthiness state *transitions* (enters a tier /
first crosses the band threshold / worsens), never on re-evaluation of an unchanged state.
**Must-NOT: an actor continuously in the queue (or continuously above the band threshold) MUST
NOT re-notify on every ingest-triggered analysis under default config.** The default flip does
not land without this; ON-by-default with a per-event cadence would be the chat flood D3's
original OFF was protecting against, rebuilt out of the notifier's own statelessness.

**Falsifier:** if a real ambient night produces more than the ADR-0068 D2-2 tripwire (10) of
notifications under default config, the defect is in the **queue bar** (ADR-0070 D5's
constants), not in this default — fix the bar, do not flip the default back. Flipping the
default back would hide a flooding queue behind a silent channel.
**Precondition (2026-07-16):** this falsifier is well-defined only once #74's transition
semantics exist. Without them, counting notifications counts *ingest events* (stock-vs-flow
correction above), and an ambient night could trip the wire through notifier cadence while the
queue bar is perfectly calibrated — indicting the wrong component. Run the falsifier against
transition-deduplicated notifications only.

### A1.2 — Notification model for now: on/off + operator-selected threat level; per-state preferences deferred as a whole (revised 2026-07-16)

**Ruling (Maintainer, 2026-07-16, verbatim):**

> "Notification can be something turned on and turned off. Also users should be able to select
> on what level of threat they may want to be notified. Right now, lets keep it that way. We
> will work on notification system in detail later."

**The interim model (what main has today — verified in code, 2026-07-16):**

- **Level:** `alert_threshold` (`firewatch_sdk/config.py:94-97`, default `CRITICAL`) is the
  operator-selected threat level, consumed by the notifier's band gate
  (`webhook_notifier.py:220-223`). This knob already exists and is the ruling's "select on
  what level of threat."
- **On/off:** there is **no explicit enable/disable field** — verified: `RuntimeConfig`
  (`config.py:94-124`) has no `notifications_enabled`. "Off" today means `webhook_url` is
  unset (`config.py:111-114`, default `None`; the notifier returns without posting when the
  URL is absent — `webhook_notifier.py:226-228`). The on/off is *implicit in the URL's
  presence*. Recorded plainly as the interim rather than claiming a switch exists; an
  explicit switch, if one is wanted, belongs to the deferred effort below.

**Per-state notification preferences are deferred as a whole.** An earlier draft of this
section recorded only a narrow future requirement (INFORM → webhook opt-in, "filed when the
\#53 pressure surface exists"). The 2026-07-16 ruling supersedes that framing: the ADR-0070 D3
operator vocabulary (CRITICAL / HIGH ALERT / INFORM) has **no per-state notification surface**
today — CRITICAL and HIGH ALERT are both `tier <= 2` and collapse into the single
`notify_on_auto_escalate` bool — and making the three states independently subscribable is
deferred **whole** to a dedicated notification-system design effort ("we will work on
notification system in detail later"). No design implied here; no issue filed now (the A1.3
D-shape). **Stated interim:** until that effort, INFORM is visible on the dashboard / pressure
strip, and the only notification controls are the two above.

**Correction (2026-07-16, this batch): the previous "INFORM never notifies under default
config" was overstated — the tier axis never fires for INFORM, but the band axis stays live.**
Mechanics, verified on main:

- *Tier axis:* an observed actor (`tier=None`) casts no tier vote in `is_alert_worthy`
  (`escalation/worthiness.py:111-117`), and today's default notifier gate is band-only anyway
  (`webhook_notifier.py:220-223` with `notify_on_auto_escalate=False`). INFORM never notifies
  **via the tier axis**, under any config. That half of the claim holds.
- *Band axis:* an observed actor **can** reach CRITICAL today. `tier=None` requires zero
  BLOCK/DROP events (`escalation/decider.py:198-205`), which forecloses `brute_force`,
  `persistence`, **and the AI boost** (`build_samples` groups only BLOCK/DROP events —
  `scoring.py:140-143`; `analyze_ip` invokes the AI only when samples are non-empty —
  `pipeline.py:686-688`). But `port_scan` (+25) counts all events' ports
  (`scoring.py:106-109`), and SQLi/XSS signatures scan **all** events at disposition weight
  0.75 (ALERT/LOG) or 1.0 (ALLOW) (`scoring.py:66-72, 113-125`): an unqualified
  payload-bearing population reaches 81 (ALERT/LOG) or 100 (ALLOW-only with no detections) —
  ≥ 76 = CRITICAL (`scoring.py:253-254`) → `band_meets` fires → it notifies under default
  config. Concrete in-tree instance: Suricata severity-3 signatures normalize to `medium`
  (`suricata/normalize.py:43-48,163`) — an unqualified ALERT under the D1 gate
  (`qualify.py:42, 84-95`) — so SQLi+XSS snippets across ≥5 destination ports produce an
  observed actor at score 81.
- **The corrected property this amendment records:** an observed-stratum actor notifies
  *only* through the band axis at ≥ `alert_threshold` — i.e., only through the operator's
  chosen threat level. That is not a defect to fix: the band net is ADR-0067 D5's deliberate
  catch-all, and the level gate is exactly the ruling's model. The non-payload observed
  population — the flood the product-strategist's constraint targets — tops out at band 35
  today (ADR-0067's D5 correction box: `port_scan` 25 + `multi_source` 10) and cannot reach
  the CRITICAL default at any volume. Post-#53, ADR-0070 D2's R1 (+15) flows under the +30
  `detection_boost` cap, lifting that non-payload ceiling to ~55 (HIGH) — still below the
  CRITICAL default; the payload-bearing reachability above exists today, before R1, and R1
  does not change it. Firing *cadence* for this path is governed by A1.1's transition
  semantics (both axes), unchanged by this section.
- **Falsifier:** an observed actor notifying under default config with score < 76, or via
  the tier arm at any score, is a defect against this section.

### A1.3 — OS/desktop push: deferred, recorded

Explicitly out of scope now, by Maintainer decision. No design implied here; a future issue
when prioritized. Webhook (Discord/Slack) is the notification transport for M1; email is a
future transport ("or email in the future").

### Amendment 1 retire list (grep-derived: `grep -rln "notify_on_auto_escalate" packages/ frontend/ docs/`)

| Artifact | Disposition |
|---|---|
| D3's "defaulting OFF … Notifications stay quiet" ruling (this file, above) | Stands unedited (house rule); **default superseded by A1.1** — the toggle, mechanism, and predicate are unchanged |
| `firewatch_sdk/config.py` `notify_on_auto_escalate: bool = False` | **Replace-with `True` in #74** |
| `webhook_notifier.py` default gate path | Behaviour follows the field default — **verified in #74's tests** (must-NOT, as corrected by A1.2: observed-stratum actors never notify **via the tier axis**; the band axis stays live at ≥ `alert_threshold`) |
| `webhook_notifier.check_and_alert` stateless per-invocation firing (no dedup/cooldown — verified 2026-07-16, whole file) | **Replaced in #74 with transition semantics** (fire on state transition, both axes — see the A1.1 stock-vs-flow correction). Until #74 lands, the per-event cadence is the *pre-existing* band-path behaviour; the default flip MUST land in the same change as the transition semantics, never before |
| Issue #74 body, original criterion "exactly one notification per new alert cycle (existing notifier dedup semantics unchanged)" | **Replaced in the 2026-07-16 batch** — there are no existing dedup semantics (the premise was false); rewritten to explicit transition-semantics criteria with the must-NOT above |
| Issue #74 body, must-NOT "an observed-stratum actor … SHALL NOT trigger a notification under default config" + Out-of-scope "per-state notification preferences … filed when the #53 pressure surface exists" | **Stands until Maintainer sequences the #74 reword** — both carry A1.2's superseded framing: the must-NOT must be scoped to the tier axis (the band axis is live per the A1.2 correction), and the out-of-scope pointer must repoint to the deferred notification-system effort (2026-07-16 ruling), not #53 |
| `frontend/src/components/notifications/NotifyOnAutoEscalateToggle.tsx` help copy ("Default OFF keeps chat quiet by design per ADR-0059 D3") | **Replace-with A1 citation in #74** — the copy currently *defends the superseded default by citing this ADR*; leaving it is the mis-citation drift pattern |
| `frontend/src/api/types.ts`, `NotificationsPanel.tsx`, test files (`SettingsRoute.test.tsx`, `AlertingPolicyPanel.test.tsx`, `NotificationsPanel.test.tsx`) | **Updated in #74** where they assert the OFF default; UI mechanics unchanged |
| `docs/escalation-and-triage-model.md` notification text | **Updated in #74** |
| `docs/internal/board-draft-2026-07.md` | Internal/archive-bound; no action (never cited publicly) |
| D3's Alternatives row "Make notifications escalation-aware by default (toggle ON / forced) — rejected as the default" | Stands as history; its stated premise (pre-gate tier ≤ 2 population) is the thing that changed — see A1.1 |

## References

- **Elastic detection-rule actions / risk_score + severity** —
  https://www.elastic.co/guide/en/security/current/rules-ui-create.html
- **Splunk alert trigger conditions + actions** —
  https://docs.splunk.com/Documentation/Splunk/latest/Alert/Aboutalerts
- **OCSF severity_id / disposition_id** — https://schema.ocsf.io/ (1.8.0)
- **NIST SP 800-61r2** — incident-response lifecycle (Detection-&-Analysis vs Containment boundary).
- **Internal:** ADR-0058 (escalation axis — extended), ADR-0036 (presentation contract),
  ADR-0033/0015 (SIEM-now/SOAR-later), ADR-0019 (per-source rjsf — deviation recorded),
  ADR-0043 (AI-engine surface identity), ADR-0006 (SecretStr masking).
