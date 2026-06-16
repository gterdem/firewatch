# AI Engine — Page Guide

**Audience:** Junior Security Operations Center (SOC) analyst — you know security basics and
are new to FireWatch.

**Series note:** This is the second guide in the per-page series. Every page guide follows the
same five-section template used here. The first guide covers the Dashboard.

---

<!-- SCREENSHOT PLACEHOLDER: replace this comment with a full-width screenshot of the
     AI Engine page once the public repo is set up and screenshots can be committed. -->

---

## 1. What this page is for

The AI Engine page answers one question: **"Do I trust what the AI concluded, and why did it
conclude that?"**

Every AI (Artificial Intelligence) verdict FireWatch records is shown here in full — what the
local model was given to read, what it said back, whether that moved the score, and whether
you agreed with the call. The page is FireWatch's auditable AI surface. You are not expected
to act on it the way you act on the Dashboard triage queue. You are expected to understand
what the AI did, spot patterns where it is wrong, and record your disagreement so the system
has an honest track record.

Two structural guarantees matter before you start reading any number on this page:

- **The AI is additive only.** It can raise a threat actor's risk score; it can never lower
  it or override it. If the AI runs and decides the actor is low risk, the score stays wherever
  the detection rules put it. The floor is always the rule score.
- **Nothing left your machine.** All inference runs on a local LLM (Large Language Model) —
  a model your operator installed and configured on the same host as FireWatch. No data is
  sent to a cloud service. The page subtitle states this explicitly: "Every verdict, what the
  model saw, and proof nothing left this box."

---

## 2. What you are looking at

Panels appear on the page in this order, top to bottom:

| # | Panel name | One-line purpose |
|---|------------|-----------------|
| 1 | **Page heading and subtitle** | States the page identity ("AI Engine") and the operating promise ("Every verdict, what the model saw, and proof nothing left this box."). |
| 2 | **Provenance chip legend** | A one-time dismissible banner explaining what the RULE, AI, and AI+RULE chips mean; disappears after you dismiss it for the session. |
| 3 | **Threat summary** | A rule-templated prose block (marked with a RULE chip) showing how many actors were scored, how many have AI verdicts, how many are rules-only, and which CRITICAL/HIGH actors are the highest priority to review. |
| 4 | **AI coverage** | A sortable, searchable, paginated table (10 rows per page) listing every scored actor with AI-specific columns: verdict, confidence, score, AI status, and how long ago the AI last analysed them. |
| 5 | **AI verdicts** | A list of verdict cards — one card per stored AI analysis — each showing the IP, provenance chip, confidence band, engine score, model identity, the model's threat verdict, and whether the AI moved the score. Each card also contains the Agree/Disagree feedback controls and the "What the model saw" prompt drawer. |
| 6 | **Model trust** | A drift report panel showing whether your local AI model is producing the same verdicts it did when you last saved a baseline — the "did my model get worse?" check. |

---

## 3. How to read it

### Provenance chips

Small chips appear on every panel and card. They tell you who or what produced a number:

| Chip | Meaning |
|------|---------|
| **RULE** | Produced entirely by FireWatch's deterministic detection rules. No AI involved. |
| **AI** | Produced by the local AI model. The verdict (threat level, confidence) is AI-authored. |
| **AI+RULE** | Both the rule engine and the AI model contributed. The score was boosted because the AI verdict was high-severity and the model was confident enough. |

The Threat summary panel is always marked RULE even though it appears on the AI Engine page —
because the text is generated from rule-derived counts, not written by the model. FireWatch
never claims AI authorship for content the rules produced.

### The Threat summary panel

This panel is a factual status block, not an AI output. It tells you:

- How many actors are scored in total.
- Whether the AI engine is active or offline.
- How many actors have an AI verdict versus how many are rules-only.
- Which CRITICAL or HIGH actors (up to three) are worth reviewing first.

When the AI engine is offline the panel shows an informational notice and all actors revert
to rules-only scoring. This is expected and safe — the rule engine is always the floor.

### The AI coverage table

This table is not a copy of the Dashboard threat actor table. It shows AI-specific columns only:

| Column | What it means |
|--------|--------------|
| **IP** | The source IP address of the threat actor. Click any IP to open the entity detail slide-over. |
| **Verdict** | The severity call for this actor, plus a provenance chip showing whether the rules, AI, or both produced it. |
| **Confidence** | How sure the local model was about its verdict — expressed as a word band (High, Medium, Low) rather than a raw number. Only meaningful for actors the AI has analysed. A dash means the AI has not run on this actor yet. |
| **Score** | The current engine risk score (0–100). CRITICAL is 76–100; HIGH is 51–75; MEDIUM is 26–50; LOW is 0–25. |
| **AI status** | "Rules-only" is the normal state for most actors — the AI runs on demand, not automatically. "AI-analyzed" means the AI has run a deep analysis for this actor. |
| **Analysis age** | How long ago the AI last analysed this actor. A dash means no analysis has been run yet. |

Click any sortable column header (Confidence, Score, Analysis age) to sort. Use the search
box to filter by IP address. Pagination controls below the table let you move through pages
of 10 rows each. The "See all on the Dashboard" link at the bottom returns you to the
full threat actor table.

If you opened this page with a `?filter=below-threshold` link from elsewhere in FireWatch,
the table shows only actors whose score is exactly 0. A banner above the table explains that
these actors scored below the detection threshold and were excluded from the Dashboard threat
actor table.

### Verdict cards

Each verdict card is a complete audit record of one AI analysis. Reading a card top to bottom:

**Row 1 — Identity:** The actor's IP (clickable), the provenance chip (always AI or AI+RULE on
a verdict card because the card is AI-authored by definition), the confidence band, and the
engine risk score badge. Note that the score badge shows the *engine* band derived from the
numeric score — for example "Risk 42 · MEDIUM" — not the AI's own threat level. These are
two separate artifacts.

**Row 2 — Model identity and age:** Which local model produced this verdict and how long ago.
The model name is the identifier of the model running on your machine (for example
`llama3.1:8b`). The age tells you how fresh the analysis is.

**Row 3 — AI verdict:** What the model actually called this actor's threat level, plus the
analysis kind (concise or detailed) and the AI status for this record.

**Row 4 — Score-effect line:** A plain-English sentence explaining whether the AI changed the
score and why. There are three possible outcomes:

- *"The AI was confident enough to raise the score (boost applied)."* — The boost fired.
  The score you see is higher than it would have been from rules alone.
- *"The AI read this as [level]-risk, so it left the rule-based score alone."* — The model
  called this actor LOW or MEDIUM risk. The boost gate requires a HIGH or CRITICAL verdict,
  so the score stayed at its rule value regardless of confidence.
- *"The AI leaned [level]-risk but wasn't confident enough ([band], [value]) to raise the
  rule-based score."* — The model called this HIGH or CRITICAL but its confidence was below
  the required threshold. In this case a small bar appears showing the model's confidence
  against the threshold line, so you can see exactly how close it came.

**Agree / Disagree controls:** Below the score-effect line you can record whether you agree
with the AI's verdict. Clicking Agree submits immediately. Clicking Disagree opens an
optional text field where you can note why you disagree (up to 500 characters). The caption
below the buttons states the consequence plainly: your grade is recorded to track the
agreement rate — it does not change the score and does not retrain the model.

**"What the model saw" drawer:** A disclosure button that expands inline to show the full
analysis detail: the prompt that was sent to the model (split into an Instructions section,
an Attack samples section, and an Output schema section), the raw model response, and the
validated JSON fields that FireWatch actually consumed. This is how you verify that the model
saw what you would expect it to see, and that its raw output was well-formed.

**Re-run analysis button:** Lets you trigger a fresh analysis for this actor from the card.
A pipeline stage ticker appears below the button while the analysis runs, stepping through
each stage (fetch, build prompt, call model, validate output). When the run completes the
card list refreshes automatically.

**Open case:** Creates a case file for this analysis and opens it in the case slide-over.
Useful when you want to track an investigation or hand it off.

### The Agreement stat headline

At the top of the AI verdicts panel, above the verdict cards, a headline shows the overall
agreement rate: how often analysts who reviewed verdicts agreed with the AI's call. This
stat is marked RULE (it is deterministic arithmetic over your recorded grades, not
AI-derived). When fewer than 10 verdicts have been graded, the stat shows raw counts
("You agreed with 3 of 4 verdicts you reviewed") rather than a percentage, because a
small sample does not support a meaningful rate.

### The Model trust panel

This panel answers "did my AI model change how it judges attacks?" It runs a fixed set of
synthetic baseline scenarios through your current model and compares the results to a saved
baseline. The top-line number is a **Model Consistency Score** — the percentage of scenarios
where your current model gave the same verdict as when you last saved the baseline.

The panel has four states:

- **No baseline saved yet:** Shows instructions to run `firewatch ai-baseline --save` from
  the command line. No analysis button is provided in the UI — saving a baseline is an
  intentional operator action, not a one-click action.
- **Baseline saved, no comparison run:** Shows the baseline metadata (model name, number of
  scenarios, when it was saved) and instructions to run `firewatch ai-baseline --compare`
  after switching models.
- **Drift report available:** Shows the consistency score, the model names compared, when the
  comparison ran, and a list of up to 10 scenarios where the verdict changed. Each changed
  scenario shows the before-and-after verdict side by side.
- **Model-swap banner:** If the model currently configured in Settings is different from the
  model recorded in your saved baseline, a banner appears alerting you to run a comparison.

The comparison runs against *synthetic baseline scenarios*, not against production traffic.
It tells you whether the model's judgment changed, not whether the model is correct.

---

## 4. What you would do here

### Workflow A — "I want to understand why an actor got a high score"

1. Find the actor in the **AI coverage** table. Sort by Score (click the Score column header)
   to bring the highest-scoring actors to the top.
2. Click the actor's IP to open the entity slide-over and review the full event history.
3. In the **AI verdicts** panel below, find the verdict card for that actor. Read the
   score-effect line to see whether the AI raised the score or left it at the rule baseline.
4. Click **"What the model saw"** to open the prompt drawer. Read the Attack samples section
   to see the exact event data the model received. Check the Raw model response section to
   see what the model wrote before validation. Check the Validated JSON section to see what
   FireWatch actually used.
5. If you agree that the verdict looks correct, click **Agree**. If you think the model
   mis-read the activity, click **Disagree** and add a short note describing the discrepancy.

### Workflow B — "I want to check whether the AI is consistently calling attacks correctly"

1. Look at the **Agreement stat** headline above the verdict cards. If the rate is low (for
   example, "You agreed with 4 of 10 verdicts you reviewed"), it is worth reviewing the
   disagreed cards to look for a pattern.
2. Scroll through the verdict cards. Cards where you previously clicked Disagree will show
   your stored grade and any reason you entered. Look for a common thread — for example, the
   model consistently over-calling LOW-severity scanning traffic as HIGH.
3. If you notice a pattern, note it in a case file using the **Open case** button on the
   relevant card, or record it in your shift notes for the operator to review.

### Workflow C — "The operator upgraded the local model; I want to verify nothing regressed"

1. Ask the operator whether they ran `firewatch ai-baseline --compare` after the upgrade.
2. Open the **Model trust** panel at the bottom of the page. If a drift report is available,
   check the Model Consistency Score. A score below 100% means some scenarios changed.
3. Expand the changed-scenario list to see which attacks the new model now classifies
   differently. Escalations (the new model calls an attack more severe than the baseline)
   are shown in red; de-escalations (the new model is less severe) are shown in green.
4. If any escalations look unexpected — for example, the new model is flagging low-noise
   scanning traffic as CRITICAL when the baseline called it LOW — flag this to the operator
   before relying on AI verdicts from the new model.

---

## 5. Terms used here

<!-- GLOSSARY CANDIDATES -->

- **SOC (Security Operations Center)** — a team responsible for monitoring, detecting, and
  responding to security events.

- **AI (Artificial Intelligence)** — in FireWatch, refers specifically to a local language
  model that reads threat actor evidence and produces a verdict. The model runs on your own
  hardware; no data is sent to a cloud service.

- **LLM (Large Language Model)** — the type of AI model FireWatch uses to analyse threat
  actors. A large neural network trained to read and generate text. FireWatch uses any
  OpenAI-compatible local model (for example, one served by Ollama or vLLM).

- **Verdict** — the AI model's assessment of a threat actor: a threat level (CRITICAL, HIGH,
  MEDIUM, or LOW), a confidence value, and optionally prose explaining the assessment. A
  verdict is stored in the ledger when you request a deep analysis for an actor.

- **Confidence** — how certain the local model was about its verdict, expressed as a decimal
  between 0 and 1 (for example, 0.82). FireWatch displays this as a word band: High (at or
  above the boost threshold), Medium, or Low. Only HIGH or CRITICAL verdicts with high
  confidence can raise the engine score.

- **Provenance** — who or what produced a data point. FireWatch marks every panel and number
  with a chip: RULE (detection rules only), AI (local model), or AI+RULE (both contributed).

- **Score derivation** — whether the final risk score was produced by the rule engine alone
  (RULE) or boosted by the AI's confidence signal (AI+RULE). Tagged on every analysis record.

- **Model drift** — the change in a model's verdicts between two points in time, typically
  before and after a model upgrade. FireWatch measures drift by re-running a fixed set of
  synthetic scenarios and comparing the results to a saved baseline.

- **Baseline (AI baseline)** — a saved snapshot of how your current local model judged a
  fixed set of 25 synthetic attack scenarios. Created by running `firewatch ai-baseline --save`
  from the command line. Used as the reference when you later run `--compare` to detect drift.

- **Model Consistency Score** — the percentage of baseline scenarios where your current model
  gave the same verdict as the saved baseline. 100% means no drift; anything below 100% means
  at least one scenario changed.

- **Zero-egress** — a deployment posture in which no data leaves the local machine. All AI
  inference happens on-device using a locally-installed model. FireWatch enforces this by
  refusing to connect to non-local AI endpoints at startup.

- **Additive-only (AI)** — the structural rule that the AI can only raise a risk score, never
  lower or replace it. The rule engine score is the floor. If the AI runs and disagrees, the
  score does not drop.

- **Prompt drawer** — the "What the model saw" expandable section inside each verdict card.
  Shows the exact text sent to the model and the model's raw response, split into sections
  (Instructions, Attack samples, Output schema, Raw model response, Validated JSON).

- **Pipeline stage ticker** — the inline progress display that appears when you click
  "Re-run analysis" on a verdict card. Steps through the stages of the analysis pipeline
  (fetch, build prompt, call model, validate output) in real time.

- **Agreement rate** — the percentage of AI verdicts that you (or your team) have reviewed
  and marked Agree. Computed from analyst-recorded grades; never derived from the AI itself.
  Shown in the Agreement stat headline inside the AI verdicts panel.

- **Synthetic baseline scenarios** — the fixed set of 25 attack descriptions used by
  `firewatch ai-baseline` to measure model drift. These are not production events; they are
  representative examples used to test whether the model's judgment is consistent over time.
