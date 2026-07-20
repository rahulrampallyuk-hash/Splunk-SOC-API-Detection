# SOC Detection Framework — Application-Layer Threat Detection for API-Based Attacks

**MSc Cyber Security with Advanced Practice — Dissertation (Distinction, 70)**
Northumbria University, London Campus | September 2025 – May 2026

---

## 📋 Project Overview

This repository showcases a working **Security Operations Centre (SOC) detection framework** built to detect **application-layer attacks against REST APIs**, developed as my MSc dissertation.

The project takes a deliberately vulnerable API application, generates real attack traffic against it, ingests the resulting logs into a SIEM, and applies custom detection rules to catch each attack — then maps every detection to a recognised industry framework.

**Result: 100% detection coverage across all 10 OWASP API Security Top 10 (2023) categories.**

---

## 🎯 Objective

Modern applications are increasingly API-driven, and the OWASP API Security Top 10 highlights how different API attacks are from traditional web attacks. Many SOC setups are tuned for network- and web-layer threats and miss application-layer API abuse.

This project set out to answer a practical question: **can a lightweight, reproducible SOC pipeline reliably detect the full OWASP API Top 10 using rule-based SIEM detections, and how does that coverage map to a standard framework?**

---

## 🏗️ Architecture

```
[ crAPI (vulnerable API app, Docker) ]
                |
        application & container logs
                |
                v
[ Splunk Free ] <-- HTTP Event Collector (HEC), port 8088
                |
        custom SPL detection rules
                |
                v
     [ Alerts mapped to NIST CSF 2.0 ]
```

**Stack:**
- **Target application:** crAPI (Completely Ridiculous API) — a deliberately vulnerable API, running in Docker (multi-container).
- **SIEM:** Splunk Free, with logs ingested via the HTTP Event Collector (HEC) on port 8088.
- **Detection logic:** custom SPL (Search Processing Language) rules, one detection strategy per OWASP API category.
- **Attack generation:** manual exploitation plus automated scanning with OWASP ZAP.
- **Framework mapping:** all detections aligned to NIST Cybersecurity Framework 2.0 functions.

---

## 🔑 Key Original Finding

During testing I found that **authentication failure logs did not route through the `crapi-web` service as expected — they were emitted by the `crapi-identity` service instead.**

This matters because a SOC analyst building detections against the "obvious" web-facing service would silently miss broken-authentication and brute-force activity entirely. I corrected the detection logic to source authentication events from `crapi-identity`, which restored full visibility.

This is exactly the kind of log-source validation issue that causes real-world detection gaps — and it is a core lesson for anyone tuning SIEM use cases: **verify where your logs actually originate before trusting a detection.**

---

## 📊 Detection Coverage — OWASP API Top 10 (2023)

| # | Category | Detected |
|---|----------|----------|
| API1 | Broken Object Level Authorisation (BOLA) | ✅ |
| API2 | Broken Authentication | ✅ |
| API3 | Broken Object Property Level Authorisation | ✅ |
| API4 | Unrestricted Resource Consumption | ✅ |
| API5 | Broken Function Level Authorisation | ✅ |
| API6 | Unrestricted Access to Sensitive Business Flows | ✅ |
| API7 | Server-Side Request Forgery (SSRF) | ✅ |
| API8 | Security Misconfiguration | ✅ |
| API9 | Improper Inventory Management | ✅ |
| API10 | Unsafe Consumption of APIs | ✅ |

**Detection rate: 10/10 (100%)**

---

## 🧭 Framework Mapping — NIST CSF 2.0

Each detection was mapped to NIST Cybersecurity Framework 2.0 functions (primarily **Detect (DE)**, with links to **Identify** and **Respond**), giving the framework traceability that SOC and GRC teams use to demonstrate control coverage.

---

## 🛠️ Methodology

The project followed a **Design Science Research (DSR)** approach: design an artefact (the detection framework), build it, and evaluate it against measurable criteria (detection coverage across all ten categories, plus framework alignment).

1. Deploy crAPI in Docker as the target environment.
2. Stand up Splunk Free and configure HEC log ingestion.
3. Execute each OWASP API attack (manual + OWASP ZAP).
4. Analyse the resulting logs and author SPL detection rules.
5. Validate detections and map each to NIST CSF 2.0.
6. Evaluate overall coverage and document findings.

---

## 📁 Repository Contents

```
/detections     → SPL detection rules (one per OWASP API category)
/screenshots    → evidence of detections firing in Splunk
/docs           → methodology notes and framework mapping
README.md       → this file
```

*(SPL rule files and screenshots are being added — see commit history.)*

---

## 💡 Skills Demonstrated

- SIEM engineering and log ingestion (Splunk, HEC)
- Detection rule authoring (SPL)
- API security testing (OWASP API Top 10, crAPI, OWASP ZAP)
- Log-source analysis and detection validation
- Framework mapping (NIST CSF 2.0)
- Containerised lab environments (Docker)
- Incident lifecycle thinking: detection → triage → escalation → reporting

---

## 📌 Note

This repository presents the practical detection work from my dissertation. The full academic thesis is not published here. For any questions, feel free to connect:

- **LinkedIn:** [linkedin.com/in/rahulrampally-cyber](https://linkedin.com/in/rahulrampally-cyber)
