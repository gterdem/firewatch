# ADR-011: Faceted Filters Over Category Tabs

**Date:** April 2026
**Status:** Accepted

**Decision:** Network Logs uses dropdown comboboxes (Source, Category, Action, Severity) + free text search instead of horizontal category tabs.

**Reasoning:** 20+ categories from WAF + IDS don't fit in a tab bar. Faceted filters are the industry standard (Splunk, Elastic, Graylog). Server-side filtering scales to millions of rows.
