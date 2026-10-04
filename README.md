# SOC Detection Framework — Application-Layer Threat Detection for API Attacks

MSc Cyber Security with Advanced Practice — Dissertation (Distinction, 70)  
Northumbria University, London Campus | September 2025 – May 2026

Detection rules for the OWASP API Security Top 10, developed against a
containerised deployment of OWASP crAPI with telemetry ingested into Splunk
Free via the HTTP Event Collector.

## Note on revision

The detection rules in this repository were rewritten in September 2026.

The original rules matched event fields that the attack scripts themselves
wrote into Splunk, rather than log output produced by the target application.
A rule searching for the string `BOLA`, for example, matched only because the
attack tooling had placed that string in the event. The reported detection
coverage was therefore circular and did not measure what it claimed to.

The pipeline has since been rebuilt to ingest crAPI's nginx access logs
directly, and every rule has been rewritten against fields the application
actually produces: `clientip`, `uri_path` and `status`. All ten categories
were re-tested. Results are in `/results`.

## Findings

Seven of the ten categories are detectable from reverse-proxy access logs,
using three rule patterns:

| Pattern | Categories | Measure |
|---|---|---|
| Request rate | API2, API4, API6 | `count` per source per minute |
| Cardinality | API1, API8 | `dc(uri_path)` per source per minute |
| Path match | API5, API8, API9 | presence of a request to a given path |

Three are not detectable at this tier:

- **API3** (mass assignment) — injected fields exist only in the request body,
  which nginx does not log. Not visible at either tier as configured.
- **API7** (SSRF) and **API10** (unsafe consumption) — no access log entry is
  produced, but the application container logs the attacker-supplied URL in
  full. Detectable at the application tier, which was not ingested here.

The central finding is that detection coverage depends on which logging tier
is instrumented, not on the sophistication of the rules.

## Limitations

- Thresholds were set by inspection, not from a traffic baseline
- Precision was evaluated for one rule only (API1)
- Single target application; rules require adaptation for other APIs
- Splunk SPL; portability to other platforms untested
- Data collected before 19 September 2026 is excluded due to duplicate
  ingestion during pipeline development

## Structure

- `/detections` — SPL rules, one file per OWASP category
- `/results` — Splunk exports supporting each reported figure

A paper based on this work is in preparation with Dr Umair B. Chaudhry
(Queen Mary University of London; Northumbria University).
