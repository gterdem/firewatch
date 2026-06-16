# ADR-0049: Constrained NL→FilterSpec query grammar (store-schema-bounded)

**Date:** 2026-06-13
**Status:** Accepted

## Context
R2 ("Ask the network") lets an analyst type plain English and get a filtered/
aggregated view, using the LOCAL glass-box LLM (zero egress) — the launch
differentiator no cloud SIEM matches. Maintainer locked Q1: the NL vocabulary is
constrained to FireWatch's own filter+aggregation vocabulary, GENERATED FROM THE
STORE SCHEMA, not the raw SecurityEvent model.

## Decision
Define a bounded NL→`FilterSpec` (+ optional aggregation intent) generation:
1. **Vocabulary source = the store-queryable column set** (the columns that
   `get_paginated`/aggregates can actually filter on), enumerated at runtime from
   the store, NOT the full SecurityEvent field list. A field that exists on the
   model but is not yet persisted/queryable (the historical `destination_ip` trap)
   is NEVER advertised to the model. After ADR-0048's migration lands, the new
   queryable columns join the vocabulary automatically.
2. **Strict validator** rejects any field/value the vocabulary doesn't contain; an
   out-of-vocabulary or low-confidence parse **degrades to a plain `q` free-text
   search** — never a fabricated/hallucinated filter.
3. **Glass-box output:** the generated FilterSpec is rendered as editable chips
   (analyst sees and can tweak exactly what ran) and carries an AI provenance chip
   (R5). The LLM emits a structured FilterSpec candidate; core validates it against
   the vocabulary before any query executes.
4. **No free SQL.** The model never emits SQL; it emits a constrained FilterSpec/
   aggregation enum. This bounds the injection + hallucination surface.

## Consequences
- Reuses the existing local-LLM client and the `parseIpParam`/`KNOWN_ACTIONS`
  guard discipline (LogsRoute.tsx).
- The vocabulary is data-driven, so ADR-0048's new columns become queryable in NL
  with no prompt rewrite (just re-enumeration).
- SOAR seam noted only: "…and block them" would route the resulting IP set through
  onAction later — NOT built in ML.

## Alternatives considered
- **Free-form analytic NL→SQL** — rejected by Maintainer (Q1): bigger hallucination
  surface, weaker glass-box guarantee.
- **Vocabulary from the SecurityEvent model** — rejected: would advertise fields the
  store can't execute (the destination_ip trap), producing un-runnable filters.
