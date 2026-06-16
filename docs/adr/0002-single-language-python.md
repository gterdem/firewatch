# ADR-002: Single Language — Python

**Date:** April 2026
**Status:** Accepted

**Decision:** Entire backend in Python. No Go, no Rust, no TypeScript backend.

**Reasoning:** Bottlenecks are I/O (SSH, HTTP to Ollama, SQLite) and GPU (Ollama inference), not CPU. Python async handles all of these. Adding a second language doubles build complexity, CI, and contributor barrier for zero performance benefit at this scale.
