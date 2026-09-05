# 🛡️ MailTrace AI - System Architecture & Implementation Flows

This guide outlines the 4 primary execution flows of **MailTrace AI**. You can navigate directly to any line in VS Code using `Ctrl + P` -> `filename:linenumber`.

---

## 🚀 Quick Navigation in VS Code

| Step | Flow Name | File Path | Line | Quick Open (`Ctrl + P`) |
|---|---|---|---|---|
| **1** | **E2E Threat Detection Pipeline** | `server/src/routes/api.ts` | **Line 48** | `api.ts:48` |
| **2** | **Multi-Signal Geolocation Fusion** | `server/src/services/locationEvidenceFusion.ts` | **Line 48** | `locationEvidenceFusion.ts:48` |
| **3** | **Webmail to SOC Ingestion Bridge** | `exchange/server/src/services/mailboxService.ts` | **Line 365** | `mailboxService.ts:365` |
| **4** | **Real-Time Telemetry & Live Monitor** | `client/src/pages/LiveMonitorPage.tsx` | **Line 51** | `LiveMonitorPage.tsx:51` |

---

## 1. End-to-End Threat Detection & Evidence Fusion Pipeline
> **File**: `server/src/routes/api.ts` -> Function `runAnalysisPipeline()` (Line 48)

Processes raw RFC 5322 MIME messages through 7 specialized forensic analyzers and fuses their outputs with cryptographic integrity.

```
+-------------------------------------------------------------------------+
|                         Incoming Raw Email MIME                         |
+-------------------------------------------------------------------------+
                                    |
                                    v
            [EmailParser.parse()] (emailParser.ts:16)
                                    |
                                    v
     [Deduplication Guard: findExistingCase()] (database.ts:74)
                                    |
           +------------------------+------------------------+
           |                                                 |
           v                                                 v
 [Model B: URL Risk] (urlRiskModel.ts:25)        [Model C: Sender Identity] (identityModel.ts:35)
 - Shannon entropy & TLD hazard                  - Display Name vs From vs Reply-To mismatch
 - Brand imitation & punycode checks             - Organization domain impersonation
           |                                                 |
           +------------------------+------------------------+
           |                                                 |
           v                                                 v
 [Model D: BEC & Financial Fraud] (becModel.ts:40) [Model E: Attachment Model] (attachmentModel.ts:30)
 - Urgent wire / banking instructions            - Double-extension masking (.pdf.exe)
 - Payroll rerouting & gift card fraud           - SHA-256 integrity hashing
           |                                                 |
           +------------------------+------------------------+
           |                                                 |
           v                                                 v
 [Model F: Header Anomaly] (headerModel.ts:30)   [Social Engineering Engine] (socialEngineeringEngine.ts:20)
 - SPF / DKIM / DMARC cryptographic validation   - 9 Psychological dimensions (urgency, fear, etc.)
 - Unauthenticated relay hop detection
           |                                                 |
           +------------------------+------------------------+
                                    |
                                    v
       [Model A: NLP Classifier & Contextual Semantics] (nlpClassifier.ts:35)
                                    |
                                    v
       [Multi-Signal Geolocation Fusion] (locationEvidenceFusion.ts:48)
                                    |
                                    v
          [Evidence Fusion Layer: RiskEngine.evaluate()] (riskEngine.ts:60)
          - Weighted base scoring (0-100)
          - Multi-signal synergy bonuses (e.g. DMARC Fail + Wire Request = +25)
          - Benign evidence discounts
                                    |
                                    v
          [Forensic Hashing: SHA-256 Chain of Custody] (forensicHash.ts:10)
                                    |
                                    v
            [Database Persistence (SQLite)] (database.ts:95)
                                    |
                                    v
         [Real-Time SSE Broadcast: 'email-analyzed'] (api.ts:464)
```

---

## 2. Multi-Signal Geolocation Attribution & Anomaly Forensics
> **File**: `server/src/services/locationEvidenceFusion.ts` -> Function `synthesize()` (Line 48)

Separates physical user claims from transport reality into 3 distinct hypotheses:

```
+---------------------------------------------------------------------------------+
|                       Multi-Signal Geolocation Synthesis                        |
+---------------------------------------------------------------------------------+
                                         |
     +-----------------------------------+-----------------------------------+
     |                                   |                                   |
     v                                   v                                   v
[Tier 1: Infrastructure]      [Tier 2: Recipient Tracking]        [Tier 3: User Location]
(Lines 71-147)                (Lines 152-185)                     (Lines 250-320)
Transmitting MTA IP           Open & Click Telemetry              Client Submission Hop
Autonomous System (ASN)       MPP / Image Proxy Filtered          Workstation ISP & Country
Cloud / Datacenter tagged     Human Interaction Confirmed         Confidence Scaled
     |                                   |                                   |
     +-----------------------------------+-----------------------------------+
                                         |
                                         v
               [Forensic Anomaly Heuristics] (locationProfiler.ts)
               - Impossible Travel: Flagged if speed > 900 km/h between hops
               - Timezone Conflict: Header date timezone vs. physical longitude
               - Historical Anomaly: Deviation from established sender baseline
               - Private IP Guard: Zero coordinate fabrication for RFC 1918 IPs
```

---

## 3. Enterprise Webmail Exchange to SOC Ingestion Bridge
> **File**: `exchange/server/src/services/mailboxService.ts` -> `forwardToSocAndEnrich()` (Line 365)

Automated bridge connecting the employee webmail interface directly into the AI SOC platform:

```
[Employee / Attacker]
       |
       | 1. Types email in Webmail UI
       v
[Exchange Webmail Client] (ComposeModal.tsx)
       |
       | 2. POST /api/send
       v
[Exchange Server SmtpService] (smtpService.ts:109)
       |
       | 3. Delivers via RFC 5321 (127.0.0.1:1025)
       v
[Embedded SMTP Server Daemon] (EmbeddedSmtpServer.ts:25)
       |
       | 4. Saves message to local exchange.db (mailboxService.ts:310)
       v
[MailboxService.forwardToSocAndEnrich()] (mailboxService.ts:365)
       |
       | 5. POST /api/ingest/email { rawEmail }
       v
[MailTrace AI SOC Endpoint] (server/src/routes/api.ts:504)
       |
       | 6. Executes runAnalysisPipeline()
       v
[SOC Response: { riskScore, classification, caseId }]
       |
       | 7. Updates Exchange database (ExchangeDatabase.updateThreatScore)
       v
[Webmail Inbox UI Displays Interactive [🛡️ Threat Badge] & [View in SOC] Button]
```

---

## 4. Real-Time Telemetry & SOC Incident Response Streaming
> **Server File**: `server/src/routes/api.ts` -> `broadcastLiveEvent()` (Line 34) & `GET /live-stream` (Line 490)  
> **Client File**: `client/src/pages/LiveMonitorPage.tsx` -> `useEffect` SSE hook (Line 38)

Zero-polling, continuous streaming telemetry between the detection backend and analyst dashboard:

```
[Threat Analysis Finishes]
            |
            v
[broadcastLiveEvent('email-analyzed', caseData)] (api.ts:34)
            |
            | Pushes SSE payload over persistent HTTP stream
            v
[GET /api/live-stream Client Registry] (api.ts:490)
            |
            | text/event-stream
            v
[LiveMonitorPage.tsx EventSource Listener] (LiveMonitorPage.tsx:51)
            |
            +--> Appends threat event to live incidents table
            +--> Triggers visual radar / ping animation
            +--> Updates high-risk alert counters
            +--> Auto-reconnects with exponential backoff on drop
```
