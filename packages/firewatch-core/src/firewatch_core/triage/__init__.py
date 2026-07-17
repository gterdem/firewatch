"""firewatch_core.triage — post-verdict triage-decision domain (ADR-0072 D8).

Deliberately NOT under ``escalation/``: this package is what an operator
*decides* about an already-computed verdict (suppress / re-enter), not part
of producing the verdict itself. ``models.py`` carries the frozen, pure data
shapes; ``suppression.py`` is the single pure evaluator (ADR-0072 D4) every
read surface consumes through ``firewatch_api.decision_annotator``.
"""
