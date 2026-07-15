# FireWatch Escalation and Triage Model

**How FireWatch decides which attackers a SOC analyst must act on.**

---

## Quick version (30-second read)

FireWatch uses **deterministic rules** — no large language model (LLM) in the decision path — to
classify every attacker into one of four tiers based on what the perimeter actually *did* with the
traffic. A single SQL injection attempt that slipped through the firewall surfaces immediately in the
triage banner, even if its raw numeric score is low. An LLM is never the trigger; it narrates the
story *after* the rule already fired.

The dashboard leads with a triage banner: **"N actors need a BLOCK decision."** Each actor on that
banner is one the rules have already escalated. The analyst's job is to review, investigate, and
record a block decision — manually in today's SIEM-first posture. Automated enforcement (SOAR-style
auto-block) is a deliberate later phase, gated behind operator consent.

---

## Contents

1. [The core idea — rules first, AI second](#1-the-core-idea)
2. [The 4-tier action model](#2-the-4-tier-action-model)
3. [block_status — what it tells an analyst](#3-block_status)
4. [The Triage banner — what you see and what to do](#4-the-triage-banner)
5. [SIEM now, SOAR later](#5-siem-now-soar-later)
6. [The three named thresholds](#6-the-three-named-thresholds)
7. [Why you don't need to tune this](#7-why-you-dont-need-to-tune-this)
8. [Further reading](#8-further-reading)

---

## 1. The core idea

> "Rules escalate instantly. AI narrates the post-alert story."
> — [ADR-0058](adr/0058-action-aware-deterministic-escalation-axis.md)

### Why not an LLM per log?

Running an LLM over every raw log at WAF/IDS volumes is slow, expensive, and a prompt-injection
surface. More importantly, it is not necessary: FireWatch's correlation rules already detect SQL
injection (SQLi), cross-site scripting (XSS), port scans, and brute force attempts instantly, for
free, at ingest — no model needed for the detection step.

The AI's genuine value is *synthesis*, not detection: "given everything this actor has done in the
last hour, did the attack succeed and what should the analyst look at next?" That question is asked
per-actor, once, after the rules have already fired — not per-log, thousands of times per minute.
This is the "sampling, not per-log" posture documented in
[ADR-0003](adr/0003-ai-approach-sampling-not-per-log.md) and it is the approach credible
security-information and event-management (SIEM) platforms use in practice.

### The action axis

Every security event in FireWatch carries an `action` field populated honestly by the source
normalizer:

| `action` value | What it means |
|---|---|
| `ALLOW` | The request matched a rule and **passed through** the firewall. The attack may have succeeded. |
| `BLOCK` / `DROP` | The firewall terminated the connection. The request did not reach the application. |
| `ALERT` | An intrusion detection system (IDS) or WAF in detection (not blocking) mode fired. Disposition is **not asserted** — neither blocked nor allowed is confirmed. |
| `LOG` | Non-blocking informational detection (e.g. SSH login audit). Disposition not asserted. |

This field already existed and was already populated correctly across every source plugin. The
escalation model reads it and turns it into urgency — no schema change was needed.

---

## 2. The 4-tier action model

The `decide(events, detections)` function in
`packages/firewatch-core/src/firewatch_core/escalation/decider.py` maps each actor's events and
detections to a single escalation verdict deterministically — no I/O, no LLM. The verdict is
attached to the actor's `ThreatScore` as an `escalation` sub-object.

| Tier | Actions that trigger it | Dashboard label (issue #6 — maintainer-approved) | Plain-language meaning | `block_status` | Banner-worthy? |
|---|---|---|---|---|---|
| **1** | `ALLOW` + a high-fidelity detection | **Got through — possible breach** | A correlation rule fired *and* the request got past your defenses. The attack may have reached your system — highest priority. | `allowed` | Yes — loudest |
| **2** | `ALERT` or `LOG` (with or without a detection) | **Unconfirmed — may have got through** | Something suspicious was flagged, but nothing confirms whether it was actually stopped. Treat it as unresolved. | `unknown` | Yes |
| **3** | `BLOCK` / `DROP`, persistent (3 or more events) | **Blocked — kept trying** | Your defenses stopped every attempt, but this attacker keeps coming back. Consider a longer-term IP block. | `blocked` | No — informational |
| **4** | `BLOCK` / `DROP`, one-off | **Blocked — didn't keep trying** | Your defenses stopped every attempt, and this one didn't keep coming back. No action needed. | `blocked` | No — informational |

Tiers 3 and 4 differ on exactly one fact — persistence — so their labels differ on exactly that
word. Reading both rows together teaches the whole lower half of the ladder without a tooltip.
Both labels are count-agnostic: Tier 4 never says "one" or "single," because the persistence
threshold (`_PERSISTENCE_THRESHOLD` in `decider.py`, currently 3) means a Tier-4 actor can have
1 *or* 2 blocked events — "single attempt" would already be false at 2.

The wording in the "Dashboard label" column is defined in exactly one place in code —
`frontend/src/lib/escalationCopy.ts` — so a future rewording is a one-file edit, not a hunt across
components. The underlying tier number, `disposition` key, and `block_status` key never change
(ADR-0058): only the human-readable label layered on top does.

**Only Tier 1 and Tier 2 actors enter the triage banner.** The banner is the escalation surface;
Tiers 3 and 4 are visible in the threat table for situational awareness but do not demand immediate
analyst action.

### Why disposition beats score

Before this model, a single allowed-through SQLi scored +40 and landed in the MEDIUM band (26–50),
which kept it off the banner. A blocked flood of hundreds of requests accumulated +1 per event and
dominated the board — the noisiest, least urgent events were the loudest. The action axis fixes this
inversion: a single Tier-1 event banners immediately, regardless of its numeric score, because *what
the perimeter did* carries more urgency signal than *how many events accumulated*.

The numeric score and the escalation tier are **two separate axes**. They are never collapsed into a
single number. This follows the OCSF (Open Cybersecurity Schema Framework) 1.8.0 model, which
carries `severity_id` and `disposition_id` as distinct fields (see
[ADR-0058](adr/0058-action-aware-deterministic-escalation-axis.md) §Standard alignment).

---

## 3. block_status

Each escalation verdict carries a `block_status` field that answers the most immediate analyst
question: **did the perimeter stop this?**

| Value | Dashboard label | Meaning |
|---|---|---|
| `allowed` | **Got through** | The request passed through. Corresponds to `ALLOW` events. |
| `blocked` | **Blocked** | The perimeter terminated the connection (`BLOCK` or `DROP`). |
| `unknown` | **Unconfirmed** | An IDS or WAF detection-mode alert fired, but no terminating verdict was asserted. The request may or may not have been stopped. This is the honest answer for `ALERT` / `LOG` events. |
| `partial` | e.g. "9 blocked · 298 unconfirmed" | The actor's events span more than one terminal disposition class (ADR-0058 Amendment 1) — some confirmed blocked, some unconfirmed. The dashboard formats a counts-derived label instead of a single word. |

---

## 4. The Triage banner

The dashboard banner leads with: **"N actors need a BLOCK decision."**

### What triggers it

An actor enters the banner when:

```
escalation.tier ≤ 2   (Tier 1 or Tier 2 — action-aware axis)
OR
threat_level ≥ triage_threshold   (severity-band axis, default HIGH)
AND
actor has not been dismissed
```

The two axes are OR-combined. A low-scoring Tier-1 actor (single allowed-through SQLi, score 40 →
MEDIUM) banners even if the triage threshold is HIGH — because the action axis is unconditional.
Raising the triage threshold tightens the severity-band half only; it never suppresses Tier 1 or
Tier 2 actors.

Actors within the banner are sorted by tier first (Tier 1 before Tier 2), then by score descending,
so the loudest signals lead.

### What each chip shows

Each actor chip on the banner displays:

- The **IP address** — clicking it opens the entity slide-over with the full event history (no
  separate "Drill down" button needed).
- A **tier badge** (T1, T2, ...) colour-coded by urgency (red for Tier 1, amber for Tier 2).
- A **disposition label** — one of the four human-readable strings from the tier table above.
- A **popover** on the disposition label with the full `justification` string. The justification is
  a `[RULE]`-tagged sentence produced by the deterministic decider — never by an LLM at this stage.
  Example: `[RULE] sql_injection matched, and the request got through — this may have reached your
  system.`
- A **dismiss** button to acknowledge the actor and remove it from the banner.

### What the analyst should do

FireWatch is currently a SIEM (Security Information and Event Management) tool. The banner does not
take any automatic action. When an actor appears:

1. Click the IP to open the event slide-over and review the evidence — the full event list,
   matched correlation rules, score breakdown, and (when AI is enabled) the AI narrative.
2. Decide whether to block the IP at the firewall, WAF, or upstream.
3. Record that decision (block / watch / false-positive) and dismiss the actor from the banner.

The empty/all-clear banner state shows the **4-tier escalation legend** so analysts are oriented to
the model even when the queue is empty.

---

## 5. SIEM now, SOAR later

Security orchestration, automation, and response (SOAR) capabilities — specifically, automated
enforcement of block decisions — are a deliberate next phase, not yet shipped.

Today's boundary:
- **SIEM (now):** FireWatch detects, scores, escalates, and presents. The analyst decides and acts.
- **SOAR (later, issue #NNN / milestone #NNN):** The `onAction` seam
  ([ADR-0033](adr/0033-ui-action-seam-siem-now-soar-later.md)) already exists in the UI layer.
  When the enforcement tier is activated, a "block" decision will propagate to the upstream
  firewall, WAF, or edge device automatically, under the tiered-autonomy guardrails defined in
  [ADR-0015](adr/0015-tiered-autonomy-for-active-response.md). The greyed-out auto-block option
  visible in the Escalation Policy settings card shows this seam — it is intentionally disabled
  until the operator enables it.

This boundary follows NIST SP 800-61r2: escalation and triage sit in the Detection and Analysis
phase; automated enforcement sits in the Containment phase and requires explicit operator consent.

---

## 6. The three named thresholds

Three separate gating decisions control what reaches the analyst. They were previously conflated
under a single mislabelled knob; [ADR-0059](adr/0059-three-named-thresholds-and-unified-alert-worthiness-predicate.md)
separated them. Each has its own name, own default, and lives in its own settings card.

### Notification threshold

**Question it answers:** "Push this actor to my webhook (Discord, Slack, etc.)?"

The underlying SDK field is `alert_threshold` (name preserved for compatibility; the UI label reads
"Notification threshold"). Default: **CRITICAL** — chat is quiet by design. An optional
"Also notify on auto-escalating detections" toggle (`notify_on_auto_escalate`, default **off**)
extends this to Tier 1/Tier 2 actors regardless of their severity band. The toggle is off by
default because a CRITICAL notification floor combined with the unconditional tier axis would flood
chat with every low-score allowed-through event.

Lives in: the **Notifications** settings card.

### AI confidence threshold

**Question it answers:** "Do I trust this AI verdict enough to let it raise the actor's score?"

The backend constant is `CONFIDENCE_BOOST_THRESHOLD = 0.7` in `scoring.py`. When the AI returns a
verdict with confidence above 0.7, it contributes a +20 (CRITICAL AI verdict) or +10 (HIGH AI
verdict) score boost. Below 0.7, the AI verdict is recorded but does not move the score. This is a
model-trust gate, not an alerting gate. It has no relation to whether a notification is sent.

Lives in: the **AI Engine** settings card.

### Triage threshold

**Question it answers:** "Enter the triage banner by severity band?"

A `triage_threshold` field on `RuntimeConfig`, default **HIGH**. This controls only the
severity-band half of the banner predicate. The escalation-tier half (Tier 1 / Tier 2) is
unconditional and always surfaces in the banner regardless of this setting. Raising this threshold
to CRITICAL makes the banner stricter for score-based actors; it does not suppress action-aware
escalations.

Lives in: the **Escalation Policy** settings card.

---

## 7. Why you don't need to tune this

The three named thresholds above ([§6](#6-the-three-named-thresholds)) all gate the **severity-band**
half of the banner predicate — they decide which score-based actors reach chat, the banner, or a
score boost. None of them can silence a Tier 1 or Tier 2 actor.

That is deliberate, not an oversight. ADR-0059 D2 defines banner-worthiness as:

```
is_alert_worthy(threat, threshold) :=
    band_meets(threat.threat_level, threshold)   # tunable — the severity-band axis
    OR
    threat.escalation.tier <= 2                  # NOT tunable — the action-aware axis
```

The two axes are OR-combined, and the second one has **no threshold, no toggle, no config field**.
A single allowed-through SQL injection attempt is Tier 1 regardless of its numeric score, regardless
of the Triage threshold, the Notification threshold, or the AI confidence threshold — it always
surfaces in the banner. There is no way to configure FireWatch into a state where a confirmed
high-fidelity attack that got through, or an unconfirmed alert, is kept out of the banner.

**This is the point, not a limitation.** Every other knob in FireWatch answers "how loud should the
*noise* be" (which severity band reaches chat, which band enters the banner, how much you trust the
AI). None of them answer "should a real breach be visible" — that answer is always yes, and it isn't
a setting. For a home user or a small team with no dedicated SOC, this means the four escalation-tier
labels ([§2](#2-the-4-tier-action-model)) require **zero tuning out of the box**: install a source,
and the two highest-priority tiers surface automatically, with no threshold to discover, misconfigure,
or accidentally silence.

---

## 8. Further reading

| Document | What it covers |
|---|---|
| [ADR-0058](adr/0058-action-aware-deterministic-escalation-axis.md) | The full decision record for the 4-tier action model, including the original scoring blind spots it fixes and alternatives rejected |
| [ADR-0059](adr/0059-three-named-thresholds-and-unified-alert-worthiness-predicate.md) | The three named thresholds and the shared `is_alert_worthy` predicate |
| [ADR-0003](adr/0003-ai-approach-sampling-not-per-log.md) | Why the AI is per-actor sampling, not per-log |
| [ADR-0033](adr/0033-ui-action-seam-siem-now-soar-later.md) | The SIEM-now / SOAR-later action seam |
| [ADR-0015](adr/0015-tiered-autonomy-for-active-response.md) | Tiered autonomy and the auto-block ceiling |
| [ADR-0035](adr/0035-analytic-provenance-tagging.md) | RULE / AI provenance tagging on justification strings |
| [ROADMAP.md](ROADMAP.md) | Milestone sequencing — when SOAR enforcement ships relative to the current SIEM posture |
