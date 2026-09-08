# 🏛️ MailTrace AI - Unified End-to-End System Architecture

A single, consolidated architectural model demonstrating the complete flow of data from email ingestion and transport protocols, through the multi-model forensic analysis engines, to the unified database and real-time presentation layers.

---

## 📐 Unified System Architecture Diagram

```mermaid
flowchart TD
    %% ==========================================
    %% 1. PRESENTATION LAYER
    %% ==========================================
    subgraph L1 ["1. PRESENTATION & CLIENT LAYER (React + Vite + Tailwind)"]
        UI_SOC["🛡️ MailTrace SOC Portal (:5000)\n• Threat Dashboard & Dossiers\n• Live Telemetry Radar (SSE)\n• Entity Graph & AI Copilot"]
        UI_EXCH["✉️ Webmail Exchange (:5001)\n• Enterprise Mailbox (Inbox/Sent)\n• Real-Time Threat Badges\n• One-Click Ingest to SOC"]
    end

    %% ==========================================
    %% 2. INGESTION & PROTOCOL GATEWAY
    %% ==========================================
    subgraph L2 ["2. INGESTION & TRANSPORT PROTOCOL GATEWAY"]
        GW_SMTP["Embedded RFC 5321 SMTP Daemon (:1025)\nListens for live MTA traffic & test streams"]
        GW_API["REST Ingestion Endpoint\nPOST /api/ingest/email (Raw RFC 5322 MIME)"]
        GW_SSE["Real-Time Streaming Hub\nGET /api/live-stream (Server-Sent Events)"]
        GW_DEDUP["Deduplication Guard\n30s Burst & Message-ID Hash Matcher"]
    end

    UI_EXCH -->|"1. Send / Receive Mail"| GW_SMTP
    GW_SMTP -->|"2. Forward Raw MIME"| GW_API
    UI_SOC -->|"Upload EML / Search"| GW_API
    GW_API --> GW_DEDUP

    %% ==========================================
    %% 3. MULTI-MODEL FORENSIC ENGINE
    %% ==========================================
    subgraph L3 ["3. MULTI-MODEL THREAT DETECTION PIPELINE (runAnalysisPipeline)"]
        PARSER["MIME Parser & Header Unfolding\n(RFC 5322 Headers, Transit Hops, Body, Attachments)"]
        
        subgraph MODELS ["Parallel Specialized Forensic Engines"]
            M_NLP["Model A: NLP Classifier\n• TF-IDF & Gemini GenAI\n• Contextual Intent & Theft"]
            M_URL["Model B: URL Risk Model\n• Shannon Entropy\n• Punycode & Brand Spoofing"]
            M_ID["Model C: Sender Identity\n• From vs Reply-To vs Return-Path\n• Display Name Deception"]
            M_BEC["Model D: BEC & Wire Fraud\n• Financial Instruction Detection\n• Executive Impersonation"]
            M_ATT["Model E: Attachment Forensics\n• Dual Extension (.pdf.exe)\n• SHA-256 Payload Hashing"]
            M_HDR["Model F: Header & Auth\n• SPF, DKIM, DMARC Validation\n• Unauthenticated Relay Hops"]
            M_SOC["Social Engineering Engine\n• 9 Psychological Vectors\n• Urgency, Fear, Coercion"]
        end
        
        subgraph GEO ["Multi-Signal Geolocation Attribution (LocationEvidenceFusion)"]
            G_T1["Tier 1: MTA Relay Infrastructure"]
            G_T2["Tier 2: Recipient Tracking Telemetry"]
            G_T3["Tier 3: Submitting Client Workstation"]
            G_ANOM["Anomaly Engine\n• Speed > 900 km/h (Impossible Travel)\n• Timezone vs Longitude (15 deg/hr)"]
        end
    end

    GW_DEDUP -->|"3. Parsed Envelope"| PARSER
    PARSER --> MODELS
    PARSER --> GEO

    %% ==========================================
    %% 4. EVIDENCE FUSION & INTEGRITY
    %% ==========================================
    subgraph L4 ["4. EVIDENCE FUSION & CRYPTOGRAPHIC VERIFICATION"]
        FUSION["RiskEngine (Evidence Fusion Layer)\n• Calibrated Multi-Model Weighting (0 - 100)\n• Cross-Signal Synergy Bonuses\n• Benign Evidence Dampening"]
        CRYPTO["ForensicHashService (Chain of Custody)\n• Immutable Evidence SHA-256 Digest\n• Tamper-Evident Report SHA-256 Hash"]
    end

    MODELS --> FUSION
    GEO --> FUSION
    FUSION --> CRYPTO

    %% ==========================================
    %% 5. PERSISTENCE & TELEMETRY
    %% ==========================================
    subgraph L5 ["5. UNIFIED DATA & PERSISTENCE LAYER (SQLite WAL Mode)"]
        DB[("mailtrace.db\nPRAGMA journal_mode = WAL;\nPRAGMA busy_timeout = 5000;")]
        T_CASES["cases\n(Verdict, Score, Hashes)"]
        T_MSGS["messages\n(Mailbox & Threat Badges)"]
        T_IOCS["indicators\n(Threat Hunting Artifacts)"]
        T_GEO["geo_locations\n(7-Day TTL GeoIP Cache)"]
        T_REPORTS["reports\n(Dossiers & PDF Exports)"]
        
        DB --- T_CASES
        DB --- T_MSGS
        DB --- T_IOCS
        DB --- T_GEO
        DB --- T_REPORTS
    end

    CRYPTO -->|"4. Persist Case & IOCs"| DB
    CRYPTO -->|"5. Update Threat Score"| T_MSGS
    CRYPTO -->|"6. Broadcast Event"| GW_SSE
    GW_SSE -->|"7. Real-Time Push"| UI_SOC
    T_MSGS -->|"Refreshes Threat Pill"| UI_EXCH
```

---

## 🧩 Architectural Layers & Responsibilities

| Layer | Component | Function & Role |
|---|---|---|
| **Layer 1: Presentation** | **SOC Portal (`:5000`) & Exchange (`:5001`)** | Single-page React applications providing security operations monitoring, interactive threat graphs, AI copilot chat, and employee email clients with real-time risk badges. |
| **Layer 2: Protocol Gateway** | **Embedded SMTP Daemon (`:1025`) & REST Ingestion** | Handles incoming mail delivery using RFC 5321, captures unedited MIME streams, prevents duplicate processing via a 30-second burst cache, and drives SSE telemetry. |
| **Layer 3: Threat Engines** | **7 Forensic Models + Geolocation Engine** | Analyzes email attributes concurrently: textual sentiment (Model A), URL entropy (Model B), sender spoofing (Model C), BEC heuristics (Model D), file payload hazards (Model E), and SPF/DKIM/DMARC alignment (Model F). |
| **Layer 4: Fusion & Cryptography** | **RiskEngine & ForensicHashService** | Combines all model signals using calibrated scoring matrices and synergy escalations. Seals each case with SHA-256 evidence and verdict digests. |
| **Layer 5: Unified Data Layer** | **SQLite (`mailtrace.db`) with WAL Mode** | A single relational database shared between the SOC platform and webmail exchange. Uses Write-Ahead Logging to guarantee concurrent access without database locks. |

---

## ⏱️ 30-Second Jury Pitch for this Model

> *"MailTrace AI is structured as a **5-layer modular architecture**:*
> 1. *At the top, we have our **Presentation Layer** with dual React frontends for SOC analysts and enterprise employees.*
> 2. *Our **Transport Gateway** ingests email via an embedded RFC 5321 SMTP daemon or REST endpoint, with built-in burst deduplication.*
> 3. *Our **Analysis Layer** evaluates the message across 7 specialized forensic models and a 3-tier geolocation attribution engine that detects impossible physical travel.*
> 4. *Our **Evidence Fusion Layer** synthesizes the scores and seals the case with cryptographic SHA-256 hashes to maintain forensic chain-of-custody.*
> 5. *Finally, our **Unified Data Layer** uses Node 22 native SQLite in WAL mode, concurrently syncing threat scores to the webmail inbox while streaming live telemetry to the SOC screen via Server-Sent Events."*
