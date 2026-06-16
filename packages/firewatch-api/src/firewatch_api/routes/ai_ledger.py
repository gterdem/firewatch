"""AI verdict ledger routes (MK-2 / issue #407, ADR-0044; MK-5 / issue #410, ADR-0045).

Routes
------
GET /ai/analyses
    Cursor-paginated summary list of AI analysis records.
    Filterable by ``ip`` query parameter.
    Summary projection excludes ``prompt_text`` / ``response_text`` (ADR-0029 D3).

GET /ai/analyses/{id}
    Full record including prompt and response text.
    Returns 404 when the record does not exist.
    Returns 503 when the ledger is not yet wired.

POST /ai/analyses/{id}/feedback     [ADR-0045 D2; write route — ADR-0026 class B]
    Upsert analyst feedback (agree/disagree + optional reason) for one analysis.
    Returns 404 on unknown analysis_id; 422 on invalid verdict or oversized reason.
    Idempotent: re-submitting replaces the previous judgment (latest wins).

GET /ai/feedback/summary             [ADR-0045 D2 / D4; read route — ADR-0026 class C]
    Agreement rollup: {graded, agreed, agreement_pct}.
    Computed at read time — no denormalized counters.
    Honest denominator rule: agreement_pct is always accompanied by graded count.

Route class: C (read), B (write POST /feedback — ADR-0026 gating applies when exposed).
Pagination: cursor-based per ADR-0029.

Security
--------
- ``prompt_text`` / ``response_text`` are attacker-influenced strings (OWASP LLM05).
  They are excluded from the list projection and only returned by the detail endpoint.
- All queries use parameterised SQL (no interpolation in the adapter).
- ``limit`` is clamped to a maximum of 200 to prevent inadvertent large reads.
- POST /feedback: ``reason`` is capped at 1 000 chars server-side (enforced in the
  adapter before any DB write); oversized input returns 422.
- Unknown analysis_id returns 404 — the error body does NOT echo attacker-controlled
  content from the analysis record (OWASP API4:2023).
- ``reason`` is operator text (attacker-influenced); returned verbatim; must be
  rendered as a text node in the UI, never interpolated into HTML or prompts
  (ADR-0045 D3 / OWASP LLM01).

Dependency rule: imports firewatch-sdk and firewatch-api internals only.
Never imports legacy/.
"""
from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("firewatch.api.ai_ledger")

router = APIRouter(tags=["ai"])

# Maximum page size the API will honour — prevents large inadvertent reads.
_MAX_LIMIT: int = 200
_DEFAULT_LIMIT: int = 50

# Server-side reason cap (mirrors feedback.REASON_CAP_CHARS — kept in sync;
# the adapter enforces independently as a defence-in-depth second layer).
_REASON_CAP: int = 1_000


# ---------------------------------------------------------------------------
# Request body model — POST /ai/analyses/{id}/feedback
# ---------------------------------------------------------------------------


class _FeedbackBody(BaseModel):
    """Request body for POST /ai/analyses/{id}/feedback (ADR-0045 D2).

    verdict:
        Must be ``"agree"`` or ``"disagree"``.  Any other value returns 422.
    reason:
        Optional operator note.  Capped at 1 000 chars; oversized input returns 422.
        Attacker-influenced: rendered as text-node-only in the UI (MK-6); never
        interpolated into HTML or prompts (ADR-0045 D3 / OWASP LLM01).
    """

    verdict: Literal["agree", "disagree"] = Field(
        ..., description="'agree' or 'disagree'"
    )
    reason: str | None = Field(
        default=None,
        max_length=_REASON_CAP,
        description="Optional operator note (max 1 000 chars)",
    )


def _get_ledger(request: Request) -> Any | None:
    """Resolve the AnalysisLedger from app state.

    Returns None when the ledger is not yet wired (pre-#407 degrade).
    """
    return getattr(request.app.state, "analysis_ledger", None)


# ---------------------------------------------------------------------------
# GET /ai/analyses
# ---------------------------------------------------------------------------


@router.get(
    "/ai/analyses",
    summary="Paginated list of AI analysis records (summary projection)",
    response_model=None,
)
async def list_analyses(
    request: Request,
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    cursor: str | None = Query(default=None),
    ip: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return a cursor-paginated summary list of AI analysis records.

    The summary projection excludes ``prompt_text`` and ``response_text``
    (ADR-0029 D3 / OWASP LLM05 / ADR-0044 §Security).

    Parameters
    ----------
    limit:
        Maximum number of records per page (1–200, default 50).
    cursor:
        Opaque pagination token from a previous response's ``next_cursor``.
        Omit to start from the first (newest) page.
    ip:
        Filter results to records for the given source IP address.

    Response envelope (ADR-0029)::

        {
            "items": [ /* summary rows */ ],
            "next_cursor": "<opaque>" | null,
            "has_more": bool
        }

    Status is 503 when the ledger is not yet available.
    """
    ledger = _get_ledger(request)
    if ledger is None:
        raise HTTPException(
            status_code=503,
            detail="Analysis ledger not available — service starting up.",
        )

    try:
        page = await ledger.list_page(limit=limit, cursor=cursor, ip_filter=ip)
    except Exception as exc:
        logger.error("ai/analyses: list_page failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=503,
            detail="Analysis ledger read failed.",
        ) from exc

    return page


# ---------------------------------------------------------------------------
# GET /ai/analyses/{id}
# ---------------------------------------------------------------------------


@router.get(
    "/ai/analyses/{analysis_id}",
    summary="Full AI analysis record including prompt and response text",
    response_model=None,
)
async def get_analysis(
    request: Request,
    analysis_id: int,
) -> dict[str, Any]:
    """Return the full record for the given analysis ID.

    Includes ``prompt_text`` and ``response_text`` — the detail endpoint is
    the only place these attacker-influenced fields are exposed (OWASP LLM05 /
    ADR-0044 §Security; they must be rendered as text nodes in the UI).

    Returns 404 when the record does not exist.
    Returns 503 when the ledger is not yet wired.
    """
    ledger = _get_ledger(request)
    if ledger is None:
        raise HTTPException(
            status_code=503,
            detail="Analysis ledger not available — service starting up.",
        )

    try:
        record = await ledger.get_by_id(analysis_id)
    except Exception as exc:
        logger.error(
            "ai/analyses/%d: get_by_id failed: %s", analysis_id, exc, exc_info=True
        )
        raise HTTPException(
            status_code=503,
            detail="Analysis ledger read failed.",
        ) from exc

    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis record {analysis_id} not found.",
        )

    return record


# ---------------------------------------------------------------------------
# POST /ai/analyses/{id}/feedback   (MK-5 / ADR-0045 D2 — write route, class B)
# ---------------------------------------------------------------------------


@router.post(
    "/ai/analyses/{analysis_id}/feedback",
    summary="Upsert analyst feedback (agree/disagree) for an analysis record",
    response_model=None,
    status_code=200,
)
async def upsert_feedback(
    request: Request,
    analysis_id: int,
    body: _FeedbackBody,
) -> dict[str, Any]:
    """Upsert analyst feedback for the given analysis record.

    Re-submitting replaces the previous judgment for the same analysis_id
    (latest wins — UNIQUE constraint on analysis_id, INSERT OR REPLACE upsert).

    Returns the stored feedback row::

        {
            "id": <int>,
            "analysis_id": <int>,
            "verdict": "agree" | "disagree",
            "reason": "<text>" | null,
            "created_at": "<ISO 8601>"
        }

    Status codes
    ------------
    200 — success (also used for re-votes — idempotent upsert, not 201/204).
    404 — unknown analysis_id (error body does NOT echo analysis content).
    422 — invalid verdict or reason exceeds 1 000 chars.
    503 — ledger not wired.

    Security (ADR-0026 / ADR-0045):
    - Write route: loopback-open by default; key-gated when the API is exposed
      beyond loopback (ADR-0026 Decision 2–4; no exception carved for this route).
    - ``reason`` is capped at 1 000 chars (Pydantic ``max_length`` + adapter-level
      enforcement in feedback.py — defence-in-depth).
    - 404 error body does NOT include the analysis record content (OWASP API4:2023).
    - ``reason`` is returned verbatim; must be rendered as a text node (MK-6),
      never interpolated into HTML or prompts (ADR-0045 D3 / OWASP LLM01).
    """
    ledger = _get_ledger(request)
    if ledger is None:
        raise HTTPException(
            status_code=503,
            detail="Analysis ledger not available — service starting up.",
        )

    try:
        result = await ledger.upsert_feedback(
            analysis_id=analysis_id,
            verdict=body.verdict,
            reason=body.reason,
        )
    except LookupError:
        # Unknown analysis_id — return 404 without echoing analysis content.
        raise HTTPException(
            status_code=404,
            detail=f"Analysis record {analysis_id} not found.",
        )
    except ValueError as exc:
        # Invalid verdict or oversized reason.
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error(
            "ai/analyses/%d/feedback: upsert failed: %s", analysis_id, exc, exc_info=True
        )
        raise HTTPException(
            status_code=503,
            detail="Feedback store write failed.",
        ) from exc

    return result


# ---------------------------------------------------------------------------
# GET /ai/feedback/summary   (MK-5 / ADR-0045 D2 / D4 — read route, class C)
# ---------------------------------------------------------------------------


@router.get(
    "/ai/feedback/summary",
    summary="Agreement rollup: graded count, agreed count, and agreement percentage",
    response_model=None,
)
async def get_feedback_summary(request: Request) -> dict[str, Any]:
    """Return the analyst agreement rollup computed at read time.

    Response::

        {
            "graded":        <int>,    -- total analyses graded by analysts
            "agreed":        <int>,    -- graded where verdict = "agree"
            "agreement_pct": <float>   -- agreed / graded * 100 (0.0 when graded == 0)
        }

    Honest denominator rule (ADR-0045 D4): ``graded`` is always present so the
    caller can display "84% over 120 graded verdicts" rather than a bare percentage.

    Returns 503 when the ledger is not wired.
    """
    ledger = _get_ledger(request)
    if ledger is None:
        raise HTTPException(
            status_code=503,
            detail="Analysis ledger not available — service starting up.",
        )

    try:
        summary = await ledger.get_feedback_summary()
    except Exception as exc:
        logger.error(
            "ai/feedback/summary: get_feedback_summary failed: %s", exc, exc_info=True
        )
        raise HTTPException(
            status_code=503,
            detail="Feedback summary read failed.",
        ) from exc

    return summary
