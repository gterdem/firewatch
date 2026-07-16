# ADR-0071: The Auth-Outcome Contract Vocabulary — `SecurityEvent.outcome`, Outcome-Keyed Correlation, and the Demotion of `category` from Routing Surface

**Date:** 2026-07-16
**Status:** Accepted (2026-07-16) — **Revision 1** read and approved by the Maintainer
(verbatim: "I read the ADR changes and I approve them"). Every file:line claim was re-verified
against merged main (PR #73 = `a935f33`); the draft's anti-registry reason (1) was falsified by
an adversarial review and is retracted (see Provenance); D5 rescoped to what is actually left on
main and reconciled with issue #76. **The direction — D1/D3, the field — is unchanged**; this
is a truth-and-evidence revision, not a reversal. D5 (the OCSF class correction) was separately
Maintainer-settled by direct ruling (2026-07-16) and ships independently as #76.
Implementing issues: #76 (M1) · #77 (M3, the field) · #78 (M3, rule generalization).

**Corrects (conformance, not design):** the OCSF class assignments in `firewatch_syslog` and
`firewatch_syslog_cef` (fallback path) — wrong against the OCSF 1.8.0 schema ADR-0040 pins
(D5; the conformance issue is **#76**, Maintainer-filed, M1). *Revision 1:* the draft also
listed `firewatch_linux_auth` — its rows shipped **correct** in merged `a935f33`
(`normalize.py:128-155`: 3002/3, 3001/3, 0/0) and it is no longer in scope.
**Couples with:** ADR-0070 Revision 1 (its D3/D9 reachability caveats and the fade-on-success
inversion name the defect this ADR fixes; the interim selector union PR #73 merged into
`detector.py` is retired by this ADR's D3).
**Relates to / honours:** ADR-0012 (action semantics — untouched; `outcome` is a new axis, not
a re-cut of `action`), ADR-0069 (the precedent: a field that routes needs published semantics —
this ADR applies the same lesson to the *other* field core rules key on), ADR-0040 (OCSF export
pinned to 1.8.0 — D5 is conformance to it), ADR-0020 (lightweight OCSF alignment),
ADR-0048/0055 (the additive-field growth pattern this ADR reuses), ADR-0016 (`source_type` is
the correlation key for *diversity*, not for rule reachability).
**Skill gate:** anyone touching `detector.py` loads `ai-engine-invariants` first;
`canonical-schema` and `firewatch-plugin-author` are updated by this ADR's docs work.

**Evidence convention (Revision 1):** every file:line below was re-verified 2026-07-16 against
main at `a935f33` by running the command, not by recall; null results were validated with a
positive control in the same file (e.g. the grep that finds no `source_type == "syslog"` in
`detector.py` finds `source_type == "suricata"` at line 156).

---

## Context

### The defect: a contract a plugin can satisfy literally and still not be protected by

FireWatch's loudest detection — `brute_force_then_login`, registered `severity="critical"` +
`auto_escalate=True` (the escalation registry's only critical rule), the "probable compromise"
verdict — was, until PR #73 merged, unreachable from any source that did not emit the syslog
plugin's exact category strings. (Tier note, so this ADR does not re-seed a corrected
conflation: on a pure host-auth actor the rule queues as a **Tier-2** verdict via the ADR-0067
D1(a) gate — Tier 1 requires a literal ALLOW event in the actor's window, which the SSH/auth
categories never carry: syslog and linux_auth emit no ALLOW anywhere (grep, zero hits, both
normalize modules), and syslog_cef hard-codes `ALERT`/`LOG` on its SSH/fallback path
(`firewatch_syslog_cef/normalize.py:249,260,267,277`) while its generic CEF path *can* emit
ALLOW for firewall events via the vendor action registry
(`firewatch_syslog_cef/registry.py:55-57`), reaching Tier 1 per-actor, never per-rule. The
rule's loudness is its registration, not a tier number. See ADR-0070 D3's tier-attribution
correction and worked partition examples, 2026-07-16.)

**Where main actually stands (re-verified at `a935f33`):**

- PR #73's **interim selector union is merged**: `detector.py:140-141` defines
  `_SSH_BRUTE_FORCE_CATEGORIES = {"SSH Brute Force", "SSH Login Failure"}` and
  `_SSH_LOGIN_SUCCESS_CATEGORIES = {"SSH Login", "SSH Login Success"}`, under an in-code
  INTERIM marker (`detector.py:129-139`) that names this ADR as its retirer.
- `_brute_force_then_login` selects both legs through those frozensets
  (`detector.py:189,193`). The strings union syslog's private labels
  (`firewatch_syslog/normalize.py:79,82,102,106`; duplicated in syslog_cef's fallback,
  `firewatch_syslog_cef/normalize.py:251,262`) with linux_auth's
  (`firewatch_linux_auth/parsers.py:38-39`).
- `_ids_then_brute_force` keys its **corroboration leg** on `source_type == "suricata"`
  (`detector.py:156`); its auth leg keys on the category union alone (`detector.py:157`).
  **Revision 1 correction:** the draft claimed an additional `source_type == "syslog"` filter
  on the auth leg (then-lines 110,113). That filter **no longer exists** — PR #73 deleted it.
  A plugin adopting the known category strings reaches both rules' auth legs on today's main
  with zero further core edits. This falsified the draft's load-bearing anti-registry
  argument; see Alternatives and Provenance.

**linux_auth proved the gap mechanically** (PR #73, merged `a935f33`): as drafted, a
contract-conformant plugin — entry point, `normalize()` with correct action/severity/MITRE
mapping, tests — whose auth events carry `"SSH Login Failure"` / `"SSH Login Success"` could
reach zero of the CRITICAL rule's events. Every gate was green. The merged PR closed the
reachability hole — **by editing core**, which is the defect restated, not resolved:
conformance alone did not buy protection; a hand-maintained synonym list in
`firewatch_core.detector` did, and every future auth-capable source needs the same core edit
until this ADR lands.

**Why this ADR exists, framed precisely: this is core fixing its own defect — not a new source
forcing core edits.** Non-negotiable #1 ("adding a source must require ZERO edits to
firewatch-core") is currently true-but-hollow: the plugin loads, collects, normalizes, scores —
and joins the detection the product's CRITICAL vocabulary depends on only because someone grew
a file-local frozenset in core on its behalf. The zero-core-edits promise is only meaningful if
the contract carries enough vocabulary for core's rules to *reach* every conformant source.
Today it does not, because of a root cause one line long:

> PLUGIN_CONTRACT.md (`normalize()` responsibilities, lines 160-164) mandates `category` among
> the fields a plugin "MUST set" — **and defines no vocabulary for it** (verified: that list is
> the file's only mention of `category`). It is the only field core detection logic keys on
> that has nothing behind it: `action` has ADR-0012, `severity` has ADR-0069, `source_type`
> has its own contract section. `category` is freeform, and core rules treat it as if it were
> canonical.

### Why the defect is load-bearing, not cosmetic (the fade-on-success inversion)

ADR-0070's intensity model *fades on cessation* — and an attacker who succeeds **stops
attempting**. λ̂ decays, R2/R3 stop deriving, and the intensity axis reads *calmer at the exact
moment the situation got worse*. The success-correlation rule is the only thing standing
between "compromise" and "fades to calm" (ADR-0070, distribution table, corrected 2026-07-16).
A source whose success events are invisible to that rule therefore fails in the worst shape
available: attack visible while it is failing, silence when it works.

### What `outcome` is, and why the contract cannot express it (this is not ADR-0070's rejected field)

ADR-0070 rejected "a new SDK `attempt`/`hostile` field set by normalizers" — correctly, because
*hostility* is derivable from axes every event already carries (`action` + `severity`; the D1
predicate is exactly that derivation). **Outcome has no durable derivation from the contract's
published axes.** A successful SSH login is `action=LOG, severity=info` (ADR-0012 Flag A —
non-blocking, informational) — by action and severity alone it is indistinguishable from every
other benign log line. *(Revision 1 nuance: once D3 admits `ocsf_class` as a routing input, a
`class 3002 + action` derivation happens to be correct for the exact post-D5 M1 population —
but only by coincidence of that population's small size; it breaks silently on the first
informational-but-not-a-success Authentication event. See Alternatives, where it is recorded
and rejected. The draft's flat "impossible" was overstated.)* The only place "this
authentication *succeeded*" exists today is inside each plugin's private category string —
which is precisely why the coupling arose: the rule needed the fact, and the freeform label was
the only carrier. The rejection and this proposal do not overlap: one field was refused because
the information was already there; this field is proposed because the contract has no honest
carrier for it.

### Standards (fetched live 2026-07-16, quoted verbatim)

**ECS `event.outcome`** (elastic/ecs `schemas/event.yml`, fetched 2026-07-16,
https://github.com/elastic/ecs/blob/main/schemas/event.yml):

> "`event.outcome` simply denotes whether the event represents a success or a failure from the
> perspective of the entity that produced the event."
>
> Allowed values — `failure`: "Indicates that this event describes a failed result." ·
> `success`: "Indicates that this event describes a successful result." ·
> `unknown`: "Indicates that this event describes only an attempt for which the result is
> unknown from the perspective of the event producer. […] The unknown value should not be used
> when an outcome doesn't make logical sense for the event. In such cases `event.outcome`
> should not be populated."
>
> "Further note that not all events will have an associated outcome. For example, this field is
> generally not populated for metric events, events with `event.type:info`, or any events for
> which an outcome does not make logical sense."

**OCSF 1.8.0 Authentication class** (https://schema.ocsf.io/api/1.8.0/classes/authentication,
fetched 2026-07-16):

> class_uid **3002**, caption **"Authentication"**, category `iam` (category_uid **3**,
> "Identity & Access Management"): "Authentication events report authentication session
> activities, including user attempts to log on or log off, **regardless of success**, as well
> as other key stages within the authentication process."
>
> `status_id` enum: `0` Unknown — "The status is unknown." · `1` **Success** · `2` **Failure** ·
> `99` Other — "The status is not mapped."

**OCSF 1.8.0 categories** (https://schema.ocsf.io/api/1.8.0/categories, fetched 2026-07-16):
`1` System Activity · `2` Findings · `3` Identity & Access Management · `4` Network Activity ·
`5` Discovery · `6` Application Activity · `7` Remediation · `8` Unmanned Systems. Classes
verified from https://schema.ocsf.io/api/1.8.0/classes (same fetch): **4001 = Network
Activity** (category 4), **6002 = Application Lifecycle** (category 6), **1001 = File System
Activity** (category 1), **0 = Base Event** ("As a generic event that does not belong to any
event category", category_uid 0 "Uncategorized").

The two vocabularies agree: ECS's `success`/`failure`/`unknown`-or-absent is exactly OCSF
Authentication's `status_id` 1/2/0-or-unset. FireWatch can adopt the ECS spelling internally
and emit the OCSF integers at the export boundary with zero loss.

### The OCSF class defect (found while verifying the above; Maintainer-ruled, see D5)

`firewatch_syslog/normalize.py:26-28,71-73,133-134` claims *"class_uid 4001 = Authentication
Activity (category_uid 4 = Identity & Access Mgmt)"* — **wrong on both halves** against the
schema just quoted: 4001 is Network Activity (category 4 = Network Activity); Authentication is
3002 (category 3). Every syslog auth event exports with a network class. The same file claims
*"class_uid 6002 = File System Activity"* — also wrong: 6002 is Application Lifecycle; File
System Activity is 1001 — and neither describes a generic syslog line. syslog_cef's fallback
path inherits both errors (`firewatch_syslog_cef/normalize.py:35,251-297` — where the generic
row additionally emits `ocsf_class=6002` with a hard-coded `ocsf_category=4` at line 297, a
class/category pair no OCSF version has ever defined). Suricata's use of 4001 is **correct** —
its flow events are network activity; the defect is confined to the syslog-family auth events.
*Revision 1:* linux_auth is **no longer affected** — its merged rows
(`firewatch_linux_auth/normalize.py:128-155`) carry 3002/3 for auth, 3001/3 for account
change, and 0/0 for the unclassified fallback, with the OCSF citations in its module
docstring. Corroborating detail: our own export fallback treats 4001 as the *network* default
(`firewatch-api/ocsf/serializer.py:54-58` — "Falls back to OCSF Network Activity (4001/4)",
re-verified), so the codebase already knew what 4001 means everywhere except the files that
mislabeled it.

## Decision

### D1 — `SecurityEvent.outcome`: a three-value, ECS-anchored outcome axis

`SecurityEvent` gains one **additive, defaulted** field:

```python
OutcomeLiteral = Literal["success", "failure", "unknown"]
outcome: OutcomeLiteral | None = None
```

Semantics are ECS `event.outcome`'s, adopted verbatim (quoted above): `success`/`failure` from
the perspective of the producing source; `unknown` **only** for a genuine attempt whose result
the source cannot see; **`None` (not populated) when an outcome makes no logical sense** — the
ECS distinction between "unknown result" and "no outcome" is part of the contract, not a
nicety. Population discipline mirrors the contract's existing rule: set it where the source
honestly knows it; **never fabricate** (no defaulting auth-looking lines to `failure`). It is
orthogonal to `action` (ADR-0012 — what the control did) and to `severity` (ADR-0069 — what a
human should do): a successful login is `LOG`/`info`/`outcome=success`; a failed one is
`ALERT`/`low`/`outcome=failure`.

M1 population, stated (the distribution check): syslog "SSH Brute Force" → `failure`,
"SSH Login" → `success`, "Sudo Failure" → `failure`; syslog_cef fallback rows identically;
linux_auth failure/success/sudo/pam rows likewise. Suricata, Azure WAF, AWS NFW, ClamAV set
nothing in M1 (`None` — no outcome in their event shapes today; Azure WAF may later derive it
for auth-shaped CRS events, not scoped here). The generalized rules of D3 therefore see exactly
the population the merged interim union (`detector.py:140-141`) sees — this ADR changes
contract shape, not event volume; no distribution movement to re-adjudicate.

Store: one additive nullable column, the NB-pattern idempotent migration (same as
ADR-0048/0055 fields).

### D2 — Export: `outcome` → OCSF `status_id` at the boundary

At the OCSF export surface (ADR-0040), events whose class carries `status_id` emit
`success → 1`, `failure → 2`, `unknown → 0`, `None` → attribute omitted — the lossless mapping
the verbatim enums above license. No new export machinery; one serializer mapping.

### D3 — Correlation rules key on published vocabularies; the category unions and `source_type` literal retire

The two coupled rules are generalized to selectors built **only from fields with published
semantics behind them**:

- **Failed auth attempt** := `ocsf_class == 3002 and outcome == "failure"`.
- **Auth success** := `ocsf_class == 3002 and outcome == "success"`.
- `_brute_force_then_login` keeps its thresholds and window verbatim (≥3 failures, success
  within 30 min); only the selectors change (today: the frozenset union,
  `detector.py:189,193`).
- `_ids_then_brute_force` keeps its shape (≥1 corroborating alert coinciding with ≥3 failed
  auth attempts within 10 min) but its corroboration side becomes **cross-source, not
  named-source**: ≥1 `ALERT` event from a *different* `source_type` than the auth events —
  the rule's actual meaning ("an independent sensor corroborates the auth-log picture"),
  which the `== "suricata"` literal (`detector.py:156`) was a proxy for. No plugin name
  appears in core. *(Note: this corroboration-leg edit is required under every alternative
  considered, including the registry — it is not a cost unique to the field. See
  Alternatives.)*

Discipline made explicit (ADR-0069's lesson, generalized): **core detection logic routes only
on fields with a published vocabulary** — `action` (ADR-0012), `severity` (ADR-0069, Sigma),
`outcome` (this ADR, ECS), `ocsf_class` (OCSF 1.8.0, pinned by ADR-0040), `source_type`
*for diversity counting only* (ADR-0016). Keying on `ocsf_class` promotes it to a routing
input, which is deliberate and safe for the same reason severity became one: its semantics are
a published schema, not a per-plugin invention. **Landing order consequence:** D3 requires D5's
class correction (issue #76) first — a rule keyed on `3002` must not land while syslog still
emits `4001` for auth events.

Rule *names*, thresholds, deltas, severities, and the escalation registry entries are
unchanged — this is a selector change, invisible to the golden oracle
(`tests/golden/fixtures/expected_scores.json` pins `"detection_rule_names": []` in all five
occurrences; sha re-verified this revision:
`fe4787643955c920e934e3789c79f741cd8c8cde6b2adbc6540b66ff3743f31f`, ADR-0070 D4).

### D4 — PLUGIN_CONTRACT: `outcome` joins the contract; `category` gets honest semantics (v1.5)

PLUGIN_CONTRACT.md changes (contract version v1.5, sequenced after ADR-0069's v1.4 — issue
#70):

1. **`normalize()` responsibilities** gain: set `outcome` where the source honestly knows the
   result (ECS definitions quoted in the contract); never fabricate; `None` when no outcome
   makes sense.
2. **A new "category semantics" subsection** — the root-cause fix. `category` is defined as a
   **stable, human-readable, per-source classification label**: it drives presentation,
   filtering, and per-source grouping; values MUST be stable within a source (renames are
   breaking for saved filters); authors are NOT required — or expected — to coordinate
   category strings across sources. **Core MUST NOT key detection logic on `category`** (true
   once D3 lands; until then the contract notes the named exceptions — the interim union and
   the burst/intense pair — and their retirement). This removes the *implied* cross-source
   contract that was never written, rather than writing one (see Alternatives — the registry).
3. Changelog entry with the ECS/OCSF anchors, per house pattern.

### D5 — The OCSF class correction: settled, already filed as issue #76, lands now

**Maintainer ruling (2026-07-16, verbatim): "No one is consuming the FireWatch logs right now.
It needs to be correct."** The correction is therefore a **decision of record, not an open
trade-off**: zero known consumers exist pre-launch, so the breaking change to exported data is
free today and expensive after the announcement — it lands now.

*Revision 1 rescope:* the conformance issue **already exists — #76** (Maintainer-filed
2026-07-16, M1, `bug`/`P1`/`source`), and its scope matches reality on main: linux_auth's rows
shipped correct inside merged `a935f33` and are **out**; the serializer falsy-zero fix is
**inside #76**, not a separate issue (linux_auth's own in-code landmine note,
`normalize.py:157-168`, already points to #76 for it). What remains (all against the verbatim
schema facts in Context; file:line per #76, re-verified this revision):

| Artifact | Wrong today | Correct (OCSF 1.8.0) |
|---|---|---|
| `firewatch_syslog/normalize.py` auth rows (SSH Brute Force / SSH Login / Sudo Failure, lines 79-89) + comments at 26-28, 71-73, 133-134 | `4001/4` labeled "Authentication Activity / Identity & Access Mgmt" | **`3002/3`** (Authentication / IAM) |
| `firewatch_syslog/normalize.py` "Syslog Event" generic row | `6002/6` labeled "File System Activity" | **`0/0`** (Base Event / Uncategorized — the honest class for an unclassified line; 6002 is Application Lifecycle, 1001 is File System Activity, neither applies) |
| `firewatch_syslog_cef/normalize.py` fallback path (docstring at 35; auth rows at 251-273; generic row at 274-280 with its hard-coded `ocsf_category=4` at 297) | `4001/4` auth; `6002` + category `4` generic (a pair no OCSF version defines) | **`3002/3`** auth; **`0/0`** generic |
| `firewatch-api/ocsf/serializer.py:57-58` | `event.ocsf_class or 4001` — **falsy-zero hazard**: a legitimate class_uid `0` (Base Event) would be silently rewritten to 4001 (linux_auth's merged 0/0 fallback row hits this today on export) | `is not None` checks, so class 0 survives to the wire |

The CEF *network* path (4001 for CEF network flows, `normalize.py:66-68`) and Suricata are
**correct and untouched** — they are the must-NOT half of the correction's tests, along with
linux_auth's already-correct rows. Because this is conformance to an accepted ADR (0040), not
new design, #76 does **not** wait on this ADR's acceptance.

### D6 — Scope boundaries

- **Auth outcome only.** `outcome` is populated for auth-shaped events in M1. Wider outcome
  population (HTTP auth, Windows logon when #24 lands, sudo/su beyond what exists) follows the
  same vocabulary with no new decision.
- **No category registry.** Deliberately not building a canonical cross-source category
  vocabulary (Alternatives). If a future correlation genuinely needs a cross-source concept
  that neither `outcome` nor the OCSF class expresses, that is a new contract-vocabulary ADR.
- **`scoring.py` untouched.** Its sqli/xss selectors key on `payload_snippet` regexes
  (`scoring.py:113-124`), not category — `category` appears there only as a report-dict key
  (`scoring.py:138,151,173,189`); re-verified this revision. No scoring movement anywhere in
  this ADR.
- **Category renames stay deferred** (ADR-0069's deferral stands) — but D3 removes the reason
  they were risky: once no rule keys on the strings, "SSH Brute Force"-the-misnomer becomes a
  presentation-only rename, doable in any UI batch.

## The retire list (greps re-run this revision against `a935f33`: `grep -rn '"SSH Brute Force"\|"SSH Login"\|"SSH Login Failure"\|"SSH Login Success"' packages/ --include="*.py"`; `grep -rn 'source_type == "syslog"\|source_type == "suricata"' packages/ --include="*.py"`; `grep -rn "4001\|6002" packages/sources/syslog* --include="*.py"`)

| Artifact | Disposition |
|---|---|
| `detector.py:140-141` interim category unions (`_SSH_BRUTE_FORCE_CATEGORIES` / `_SSH_LOGIN_SUCCESS_CATEGORIES`, INTERIM marker at 129-139) + their use in `_brute_force_then_login` (`:189,193`) and `_ids_then_brute_force`'s auth leg (`:157`) | **Replace-with outcome-keyed selectors in D3's implementing issue** — the marker names this ADR as retirer |
| `detector.py:156` `source_type == "suricata"` corroboration literal | **Replace-with cross-source corroboration selector, same issue** |
| `detector.py:266-278` `_ssh_login_failure_events` helper (+ burst at 281, intense at 319) keying on `category == "SSH Login Failure"` (`:275`) | **Stand until #53/#54** (ADR-0070 retire list — those rules retire whole, taking their category coupling with them; D3 does not need to touch them) |
| Category-string *producers* — `firewatch_syslog/normalize.py:79,82,102,106`, `firewatch_syslog_cef/normalize.py:251,262`, `firewatch_linux_auth/parsers.py:38-39` | **Stand permanently as per-source labels** (D4's category semantics — they stop being routing surface, they remain presentation values; boundary: stable within their source) |
| Core/detector tests pinning the coupled selectors (`firewatch-core/tests/test_detector.py` — incl. the union-reachability tests PR #73 added; `test_issue_647_severity_policy.py:209-221`; api `tests/test_issue_650_escalation_policy_route.py:108-182`) | **Updated in D3's issue** — fixtures keep the strings (they are real plugin output); assertions that *selection* happens via category move to outcome/class |
| Plugin tests asserting their own category values (`syslog/tests/test_plugin.py:365,371`, `linux_auth/tests/test_normalize.py:42,64,74`) | **Stand permanently** — they pin per-source labels (D4 semantics), not routing |
| OCSF class values + comments (table in D5) | **Replace-with corrected values in issue #76** (linux_auth's rows: already done, merged `a935f33`) |
| PLUGIN_CONTRACT.md `category` listed with no semantics (`normalize()` responsibilities, lines 160-164) | **Replace-with the D4 subsection in the contract issue (v1.5)** |
| ADR-0070 D3/D9 reachability caveats + PR #73 Consequences bullet (2026-07-16 corrections) | **Stand as history**; their "owner of the real fix: ADR-0071" pointers resolve here. *Revision 1 note:* ADR-0070's citations of `detector.py:110-113,141-145` and the `source_type == "syslog"` filter described the pre-`a935f33` tree — **since corrected in ADR-0070 itself (same batch, 2026-07-16)**; its caveats now cite the merged union at `detector.py:140-141` |

## Alternatives considered

- **A documented canonical-category registry in PLUGIN_CONTRACT.md** (the serious contender —
  presented fairly, and more strongly than the draft did). Define well-known category strings
  ("SSH Brute Force", "SSH Login", …) that any plugin may adopt to join the correlations — the
  same shape as the contract's `provides` facet registry (PLUGIN_CONTRACT.md:156), no SDK
  field, no store column, no migration. **Honest pros, corrected in Revision 1:** the merged
  interim frozensets (`detector.py:140-141`) *are* a two-entry in-core registry, and they
  demonstrably work — linux_auth reaches both rules on today's main through them. Formalizing
  the strings in the contract would require **no rule edit at all on the auth legs**; the one
  remaining rule edit — the corroboration leg's `== "suricata"` literal → cross-source — is
  required **identically under both options** (D3 makes exactly that edit). The registry's
  total diff is therefore genuinely smaller than the field's: one contract subsection versus
  SDK field + column/migration + export mapping + population discipline + three normalizer
  edits. *The draft's reason (1) — that the registry "provably cannot" fix
  `_ids_then_brute_force` because a `source_type == "syslog"` filter runs before category is
  compared — was **false against merged main** (that filter was deleted by PR #73) and is
  retracted; see Provenance. The draft's reason (4) — that the registry "couples plugin
  authors to each other" — is withdrawn as rhetorical: a registry in PLUGIN_CONTRACT.md
  couples authors to the contract, exactly as the field does.* Why the field is still
  recommended, on the reasons that survive scrutiny:
  **(1) Type enforcement versus string discipline (the load-bearing reason).** A registry
  string is enforced by nothing: a plugin that emits `"SSH Login Sucess"` passes ruff, pyright,
  pytest, and the golden oracle — and silently drops out of the CRITICAL rule. That is the
  linux_auth defect class recurring per-string forever, invisible by construction. A typed
  `Literal["success", "failure", "unknown"]` fails **loudly**: pyright rejects the typo at
  build time, pydantic rejects it at ingestion. The field converts a per-author string
  discipline into a machine-checked contract.
  **(2) Success/failure is not an auth-category fact but a cross-domain axis** (web logins,
  sudo, Windows logons when #24 lands, future sources) — a registry would re-enumerate it per
  category forever, growing both the contract's string list and every rule's selector per
  domain; one three-value field states it once. And the standards' own answer is unambiguous:
  ECS maintains *both* an `event.category` allowed-values registry *and* `event.outcome` as a
  field — success/failure is carried by the field, never by the category vocabulary.
  **(3) It makes a *presentation* string load-bearing** — though less absolutely than the
  draft claimed: under a registry, registered strings become contract-versioned identifiers,
  so renames are deliberate v1.x changes rather than forbidden (Sigma's logsource taxonomy and
  ECS's `event.category` values are exactly this pattern, in production). The surviving core:
  one field carrying display duty and routing duty at once is a standing conflation ADR-0069
  already paid for (it could not rename the "SSH Brute Force" misnomer because the detector
  keyed on it); D4's presentation-only demotion is the cleaner cut.
  Recommendation: the field, on (1)+(2). The Maintainer decides.
- **Derive outcome at the detector from `ocsf_class` + `action` — no new field** (*added in
  Revision 1; rejected — recorded because someone will propose it as the zero-cost fix*). Once
  D3 admits `ocsf_class` as a routing key, `3002 and action == "ALERT"` (failed auth) /
  `3002 and action == "LOG"` (auth success) is **correct for the exact post-D5 M1 population**
  — verified: linux_auth's 3002 rows are ALERT=failures and LOG=SSH-Login-Success only, its
  LOG-but-not-a-login rows sit in classes 3001/0 (`normalize.py:128-155`); syslog maps
  login→LOG and brute-force/sudo→ALERT. Zero schema change, zero migration. Rejected because
  it is correct **only by coincidence of that small population**: it breaks silently on the
  first informational-but-not-a-success Authentication event — a Windows 4634 logoff when #24
  lands, a PAM session-open/close line if linux_auth's fallback row is ever classified as
  3002 — and it makes `action` (ADR-0012: what the control did) a proxy for an axis it was
  never defined to carry. The failure mode is the linux_auth defect again: nothing fails, the
  success leg just quietly over- or under-matches.
- **Derive outcome from `action`+`severity` alone (no class key).** Not possible even
  coincidentally: a successful login is `LOG`/`info`, indistinguishable on those axes from any
  benign line (Context). *(Revision 1: the draft stated a flat "impossible" for all
  derivation; that was overstated — see the class+action bullet above for the qualified
  version.)*
- **Reuse the existing category strings in new sources** (strategist option (a)). *Revision 1
  reframe:* no longer "dead on arrival" — merged main effectively does this, inverted (core
  unions the plugins' spellings, `detector.py:140-141`), and it works. Recorded as the live
  stopgap that D3 retires; rejected as the durable contract for the registry bullet's reasons
  (1)-(3) — it is the registry, minus even the documentation.
- **Adopt OCSF Authentication `activity_id` (Logon/Logoff/Ticket/…) instead of a boolean-ish
  outcome.** Over-scoped: the rules need success/failure; the activity taxonomy adds Kerberos
  machinery no M1 source produces. `activity_id` remains derivable at the export boundary
  later without contract change.
- **Key the rules on `attack_technique == "T1110"` for the failure side.** Half a fix: catches
  failures (plugins map brute force → T1110 per ADR-0014) but successes carry no technique —
  the success selector still needs `outcome`, and then the failure side may as well use the
  same axis. Also conflates "what ATT&CK calls it" with "what happened".
- **Keep the OCSF correction inside this ADR's timeline.** Rejected by decomposition (and made
  moot by the Maintainer's ruling): the class fix is conformance to ADR-0040 — a correctness
  bug with settled semantics — and must not inherit a vocabulary decision's review cycle. D5
  records the ruling; issue #76 ships independently.

## Provenance — how the draft's load-bearing argument failed, and how it propagated

This batch records its own corrections in the open (the ADR-0070 D3 and ADR-0067 A1.3
pattern); this one belongs in the record because three readers inherited it.

The draft's strongest-stated sentence — Alternatives reason (1), "the registry alone provably
cannot fix `_ids_then_brute_force` — its `source_type == "syslog"` filter runs *before*
category is compared" — was verified against a pre-PR-#73 tree (`detector.py:110,113`) and was
already false when it reached review: PR #73 (merged as `a935f33`) had deleted that filter and
replaced the category couplings with the interim union. The stale premise then propagated
exactly the way this repo's evidence discipline predicts: the coordinator relayed reason (1)
to the Maintainer as fact **twice** without re-running the grep, and the product-strategist
retracted its own registry-shaped proposal citing `detector.py:156` as confirmation of the
pre-filter — a line that reads `source_type == "suricata"`, not what was claimed. Of the
readers who handled the claim, only the reviewer explicitly instructed to *attack* the
recommendation ran the refuting command (grep for the `"syslog"` literal, with the
`"suricata"` literal as the positive control proving the search could find what does exist).

Two mechanical lessons, now applied in this document: a file:line citation is a claim about a
moving target — it verifies nothing after the tree moves, and it *looks* verified, which is
worse; and a recommendation's most confident sentence is the one to re-run, not the one to
relay. Revision 1 therefore re-ran every citation against `a935f33` and states the evidence
convention in the header. The recommendation survived on different grounds than the draft
argued — reasons (1) and (4) fell; type enforcement and the cross-domain axis stand — which is
the difference between a conclusion that happened to be right and one that is right for
checkable reasons.

## Reasoning

The contract's promise is that conformance buys protection. linux_auth showed the promise
failing at the exact point it matters most: the CRITICAL rule, which the intensity model's
fade-on-success inversion makes load-bearing rather than decorative — and the merged fix had
to be a core edit, which is the promise failing a second way. The root cause is not that
someone hard-coded a string — it is that the contract mandated a field with no vocabulary, so
the first rule that needed a cross-source fact had nowhere else to find it. The fix follows
ADR-0069's proven shape: give the routing input published semantics (ECS's outcome definition,
OCSF's status enum — two standards that agree letter-for-letter), key core on that, and demote
the freeform field to what it honestly is. One additive field, two rules edited, one contract
subsection — and the zero-core-edits promise becomes true in the only sense that counts: the
*next* auth-capable source joins the CRITICAL path by setting three values it already knows,
checked by the type system rather than by anyone's spelling.

## Consequences

- **Implementing issues:** the D5 conformance fix is **issue #76** (already filed,
  Maintainer-authored, M1); still to file: the D1/D2/D4 contract slice (SDK field + export
  mapping + PLUGIN_CONTRACT v1.5, M3) and the D3 rule generalization (M3, depends on both #76
  and the contract slice).
- **Export data changes shape** (D5, settled): syslog-family auth events move class
  4001→3002, category 4→3; generic syslog lines move to Base Event 0/0; the serializer's
  falsy-zero fallback stops rewriting class 0 (all in #76). Pre-launch this is free by ruling;
  recorded so the post-launch reader knows it was deliberate, dated, and cited.
- `tests/golden/`: `fixtures/expected_scores.json` untouched (D3 changes selectors, not scores
  or rule names; sha re-verified this revision). The syslog-family *normalize* pins move under
  issue #76 — a conformance correction with the schema quoted verbatim as the justification
  (the ADR-0058 D5b discipline: the new values are right on their own terms — the published
  schema says what 3002 is — not merely "the old ones were wrong"). `outcome` pins are
  additive new assertions, not a re-bless.
- The merged interim union (`detector.py:129-141`) has its named retirer (D3); ADR-0070's
  retire-list row already points here.
- ADR-0069's deferred category renames become presentation-only after D3 (D6) — unblocked,
  not scheduled.
- PLUGIN_CONTRACT v1.5 sequenced after v1.4 (#70) so the changelog stays linear.
- **Batch conformance (Revision 1):** ADR-0070's D3/D9 caveats and PR #73 bullets inherited
  the stale pre-`a935f33` citations (`detector.py:110-113,141-145`, the `source_type ==
  "syslog"` filter, PR #73 framed as unmerged/pending) — **corrected in ADR-0070 in this same
  batch (2026-07-16)**, on the Maintainer-relayed go that followed this revision's report. No
  other batch document quotes the draft's reason (1); ADR-0067/0059 came back clean on the
  same grep.

## References

- **ECS `event.outcome`** — https://github.com/elastic/ecs/blob/main/schemas/event.yml —
  definitions quoted verbatim in Context (fetched 2026-07-16).
- **OCSF 1.8.0 Authentication (3002)** — https://schema.ocsf.io/api/1.8.0/classes/authentication
  — class description and `status_id` enum quoted verbatim (fetched 2026-07-16).
- **OCSF 1.8.0 categories / classes** — https://schema.ocsf.io/api/1.8.0/categories,
  https://schema.ocsf.io/api/1.8.0/classes — category list and the 4001/6002/1001/0 facts
  (fetched 2026-07-16).
- **MITRE ATT&CK T1110** — https://attack.mitre.org/techniques/T1110/ (the failure side's
  existing technique mapping; why technique-keying was rejected).
- **Internal:** ADR-0070 Revision 1 (+2026-07-16 corrections), ADR-0069, ADR-0040, ADR-0020,
  ADR-0016, ADR-0012, ADR-0048/0055; PLUGIN_CONTRACT.md; `detector.py` (at `a935f33` — the
  merged PR #73), `firewatch_syslog/normalize.py`, `firewatch_syslog_cef/normalize.py`,
  `firewatch_linux_auth/normalize.py` + `parsers.py`, `firewatch-api/ocsf/serializer.py`;
  issues #3, #53, #54, #70, **#76**.
