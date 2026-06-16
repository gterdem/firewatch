"""firewatch-core analytics sub-package.

Provides read-only aggregate queries over persisted event data.
Currently ships:
  - entity_graph  — IP/ASN/category link-analysis substrate (ML-8, issue #436)
  - dga           — DGA (domain generation algorithm) detection on dns_query (ML-12, issue #440)
  - beaconing     — beaconing + rare-flow detection (ML-10, issue #438)
"""
