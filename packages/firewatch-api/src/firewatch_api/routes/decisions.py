"""Triage-decisions routes — POST/GET /decisions, DELETE /decisions/{id}
(ADR-0072 D3, issue #47 Part 1/backend).

Routes
------
POST /decisions
    Record a triage decision (`expected` / `dismissed` / `false_positive`).
    The SERVER computes ``decided_tier``/``decided_score`` by running the
    actor through the pipeline (ADR-0072 D2) — the client never self-reports
    them. Returns 201 + the full record. 422 when ``verb='false_positive'``
    XOR ``rule_name`` is present.

GET /decisions
    Cursor-paginated list (ADR-0029 D2 envelope), newest-first. ``actor``
    scopes to one actor's full history (active + revoked).

DELETE /decisions/{id}
    Soft-revoke (sets ``revoked_at``) — the audit row survives (append-only,
    ADR-0072 D2). 404 on an unknown id.

Route class: B (writes) / C (reads) — ADR-0026 gating applies when the API
is exposed beyond loopback (loopback posture unchanged in M1, ADR-0072).

Security
--------
- All store access is parameterised SQL (adapter layer); no interpolation.
- ``actor_ip``/``rule_name``/``note`` are bounded and pattern-validated at
  the schema layer (schemas.py) — malformed input is a clean 422, never a 500.
- A ``ValueError`` raised by the store (verb/rule_name mismatch, oversized
  field) is mapped to 422 here — never leaks as an unhandled 500.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from firewatch_api.deps import get_decision_store, get_pipeline
from firewatch_api.schemas import CreateDecisionRequest, DecisionRecord, ListDecisionsResponse
from firewatch_core.adapters.decisions.caps import DEFAULT_LIMIT, MAX_LIMIT

logger = logging.getLogger("firewatch.api.decisions")

router = APIRouter(prefix="/decisions", tags=["decisions"])


def _require_decision_store(store: Any) -> Any:
    if store is None:
        raise HTTPException(
            status_code=503,
            detail="Decision store not available — service starting up.",
        )
    return store


@router.post(
    "",
    status_code=201,
    response_model=DecisionRecord,
    summary="Record a triage decision (expected / dismissed / false_positive)",
)
async def create_decision(
    body: CreateDecisionRequest,
    store: Any = Depends(get_decision_store),
    pipeline: Any = Depends(get_pipeline),
) -> DecisionRecord:
    """Record a decision; the server computes the tier/score snapshot (ADR-0072 D2).

    Returns 503 when the decision store or pipeline is not wired.
    Returns 422 when the verb/rule_name pairing is invalid (schema layer
    already enforces the Literal verb vocabulary; this catches the XOR rule).
    """
    store = _require_decision_store(store)
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not available")

    # ADR-0072 D2 "snapshot authority is the server": run the actor through
    # the SAME pipeline every other read surface uses — never trust a
    # client-reported tier/score (a stale tab must not write a stale
    # re-entry baseline). use_ai=False: a decision snapshot is a fast,
    # deterministic fact, not an AI-augmented judgement (no LLM call here).
    score = await pipeline.analyze_ip(body.actor_ip, use_ai=False)
    decided_tier = score.escalation.tier if score.escalation is not None else None

    try:
        record = await store.create_decision(
            actor_ip=body.actor_ip,
            verb=body.verb,
            rule_name=body.rule_name,
            decided_tier=decided_tier,
            decided_score=score.score,
            note=body.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("POST /decisions: create_decision failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=503, detail="Decision store write failed.") from exc

    return DecisionRecord(**record)


@router.get(
    "",
    response_model=ListDecisionsResponse,
    summary="Cursor-paginated list of triage decisions",
)
async def list_decisions(
    actor: str | None = Query(
        default=None, description="Optional exact-match actor_ip filter.",
    ),
    cursor: str | None = Query(default=None, description="Opaque pagination token."),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    store: Any = Depends(get_decision_store),
) -> ListDecisionsResponse:
    """Return the decision history (ADR-0029 D2 envelope), newest-first.

    Returns the FULL history (active + revoked) — the audit trail feeds the
    case inbox (#16). Returns 503 when the decision store is not wired.
    """
    store = _require_decision_store(store)
    try:
        page = await store.list_decisions(limit=limit, cursor=cursor, actor=actor)
    except Exception as exc:
        logger.error("GET /decisions: list_decisions failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=503, detail="Decision store read failed.") from exc
    return ListDecisionsResponse(
        items=[DecisionRecord(**item) for item in page["items"]],
        next_cursor=page["next_cursor"],
        has_more=page["has_more"],
    )


@router.delete(
    "/{decision_id}",
    status_code=200,
    response_model=None,
    summary="Soft-revoke a triage decision (undo)",
)
async def revoke_decision(
    decision_id: int,
    store: Any = Depends(get_decision_store),
) -> dict[str, Any]:
    """Soft-revoke a decision (sets ``revoked_at``) — the row is never deleted.

    Returns 404 when the decision id does not exist.
    Returns 503 when the decision store is not wired.
    """
    store = _require_decision_store(store)
    try:
        await store.revoke_decision(decision_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Decision not found.")
    except Exception as exc:
        logger.error("DELETE /decisions/%s failed: %s", decision_id, exc, exc_info=True)
        raise HTTPException(status_code=503, detail="Decision store write failed.") from exc
    return {"id": decision_id, "revoked": True}
