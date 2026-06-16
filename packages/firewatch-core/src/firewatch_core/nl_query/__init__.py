"""NL→FilterSpec query subsystem (ADR-0049 / ML-6, issue #434).

Components
----------
vocabulary  — enumerate queryable FilterSpec fields from the store schema at
              runtime; only persisted/filterable columns are advertised (EARS-4).
prompt      — build the structured system+user prompt for the local LLM.
validator   — strict allowlist validation of the LLM-emitted candidate; degrades
              to free-text q= on any out-of-vocabulary field or low-confidence
              result (EARS-1, EARS-2).
engine      — orchestrates vocab→prompt→LLM call→validate; exposes the single
              public entry point ``parse_nl_query``.

Security boundary (ADR-0049 / OWASP LLM)
-----------------------------------------
All LLM output is treated as untrusted input (OWASP LLM01 prompt injection).
The validator applies a strict allowlist before any FilterSpec is used:
  1. Field keys must be in the runtime vocabulary (EARS-4).
  2. Enum fields (action, severity) must contain a known value (EARS-1).
  3. Substring/exact fields are accepted as-is but capped at 200 chars (no SQL
     construction — values flow through SQLite ? placeholders only, same as all
     other FilterSpec fields).
  4. Low-confidence parse or any OOV reference → degrade to q= (EARS-2).
"""
