"""FireWatch API auth subpackage (ADR-0026 Decisions 2-3 + Amendment 1).

Submodules
----------
classes    -- RouteClass enum (A/B/C) + optional declaration decorator (extension point)
posture    -- pure policy: (api_key, route_class) -> gate | no_op
credential -- bearer extraction (RFC 6750) + hmac.compare_digest check (all paths)
dependency -- intentionally thin; explains why Depends is not used (see wiring.py)
middleware -- Starlette BaseHTTPMiddleware enforcing bearer auth on all routes
wiring     -- wire_auth(app): stamps RouteClass + adds AuthMiddleware

Auth enforcement flow
---------------------
create_app -> wire_auth(app):
  1. Classifies every APIRoute (decorator > path-override > method heuristic)
  2. Stamps _fw_route_class on each endpoint function (coverage test uses this)
  3. Registers AuthMiddleware, which on every request:
     a. Reads api_key from app.state.config_store
     b. Calls AuthPosture.should_gate(api_key, route_class=C)  # C = most permissive
     c. If gating: extracts Bearer token; verifies via hmac.compare_digest
     d. Returns 401 (RFC 6750 §3) on failure; proceeds on success

Standards: RFC 9110 sec 11.6.2, RFC 6750, OWASP API1/API2/API5, NIST SP 800-63B.
"""
