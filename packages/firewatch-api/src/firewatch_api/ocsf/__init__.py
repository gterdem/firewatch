"""OCSF 1.8.0 export surface for the FireWatch API (ADR-0040 / MI-5 #386).

Subpackage layout (architect-specified — must not be collapsed):
  mapping.py    — pure constants/tables, no I/O
  serializer.py — pure functions: event_to_ocsf, threat_to_detection_finding
"""
