# MailTrace AI 🛡️
### AI-Powered Email Threat Detection, Investigation, Geolocation & Forensic Intelligence Platform (SIH 2026)

MailTrace AI is an enterprise-grade, student-accessible cybersecurity forensics web application that investigates suspicious emails, unmasks Business Email Compromise (BEC), credential phishing, weaponized payloads, and sender deception through deep header extraction, Claimed vs. Observed Technical Identity correlation, infrastructure geolocation, Google Gemini AI reasoning, and cryptographic evidence hashing.

---

## 🚀 Key Forensic Innovations

### 1. Claimed Identity vs. Observed Technical Identity
Attackers frequently forge the human-facing `From:` display name and address while relying on foreign `Return-Path` and `Reply-To` routing infrastructure. MailTrace AI explicitly cross-examines:
- `From` display name spoofing against target brands (e.g. PayPal, Microsoft).
- `From` vs. `Reply-To` diversion (silently routing victim replies to attacker-controlled mailboxes).
- `From` vs. `Return-Path` envelope mismatches.
- Lookalike / typosquatted domains (e.g., `paypa1-security.com`, `micros0ft-update.com`) and Punycode homoglyphs (`xn--...`).
- **Core Principle:** Passing SPF/DKIM/DMARC does *not* automatically prove innocence; compromised legitimate accounts or deceptive lookalike domains frequently satisfy standard SPF/DKIM checks while actively transmitting threat payloads.

### 2. Dual-Engine Intelligence: Google Gemini + Deterministic Fallback
- **Google Gemini 2.5 Flash:** Prompts `@google/genai` server-side with structured JSON schemas to perform high-level social engineering assessment, behavioral threat classification, and incident response recommendations.
- **Deterministic Rule Engine:** If `GEMINI_API_KEY` is not configured or network limits are reached, the platform seamlessly and automatically engages its comprehensive rule-based heuristic engine. No simulated or fabricated intelligence is ever displayed.

### 3. Contextual Infrastructure Geolocation & Ethical Disclaimers
- Traces chronological `Received:` transport hops from origin relay to final MX destination.
- Maps public IP hops to Autonomous System Numbers (ASN), Organizations, Countries, and geographic coordinates.
- Recognizes RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`) and displays: *"Geolocation unavailable — private/internal IP"*.
- Strictly enforces the forensic disclaimer: *"IP geolocation represents observed infrastructure and does not establish the physical location or identity of the sender."*

### 4. Non-Execution Payload & Attachment Analysis
- Inspects file attachments, extensions, MIME types, and computes SHA-256 digests.
- Detects deceptive double extensions (`invoice.pdf.exe`), macro-enabled Office formats (`.docm`, `.xlsm`), and dangerous binaries (`.exe`, `.scr`, `.bat`, `.ps1`). Attachments are never executed.

### 5. Interactive Entity Correlation Graph
- Models forensic relationships: `Email ➔ Sender ➔ Domain ➔ IP ➔ ASN ➔ Geo`, `Email ➔ URLs ➔ Domains`, and `Email ➔ Attachments ➔ Hashes`.
- Clickable node inspection reveals direct links and telemetry.

### 6. Forensic Evidence Integrity & Custody Seal
- Uses Node.js `node:crypto` to generate SHA-256 hashes of the raw evidence payload and the final investigative report, providing an immutable audit trail.

---

## 🛠️ Technology Stack

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, React Router v7, Lucide Icons, Recharts.
- **Backend:** Node.js 24, TypeScript, Express, `mailparser`, `dotenv`, `cors`.
- **Database:** SQLite (powered natively by Node 24's zero-dependency `node:sqlite`).
- **AI / LLM:** Google Gemini via `@google/genai` (`gemini-2.5-flash`).
- **Security:** Strict server-side secret handling, zero client-side API key leakage.

---

## 🏁 Getting Started

### 1. Prerequisites
- Node.js v20+ (Node v24 recommended)
- npm v10+

### 2. Configuration (Optional)
To enable Google Gemini AI reasoning, create `server/.env`:
```env
PORT=5000
GEMINI_API_KEY=your_google_gemini_api_key_here
```
*(If left empty, MailTrace AI operates in 100% functional deterministic fallback mode with all checks active).*

### 3. Build & Run
From the project root:

```bash
# Start the unified production server (serves both API and React frontend on port 5000)
npm start

# Or run in development mode:
npm run dev:server   # Starts Express API with tsx watch on port 5000
npm run dev:client   # Starts Vite React dev server on port 5173 (proxied to port 5000)
```

Open your browser at **[http://localhost:5000](http://localhost:5000)** (or [http://localhost:5173](http://localhost:5173) in dev mode).

---

## 📑 Pages & Features

1. **Command Center (`/`)**: Live statistics (Emails Analyzed, Threats Detected, High Risk, Critical, Average Risk), Risk Distribution donut chart, Classification bar chart, and recent investigations registry.
2. **Analyze Email (`/analyze`)**: Drag-and-drop `.eml` upload, raw RFC 822 paste, and 5 pre-built demonstration scenarios with live animated pipeline stage progression.
3. **Investigation (`/investigation/:caseId`)**: 8-tab forensic investigation console:
   - **Overview:** Threat score, Claimed vs Observed Identity, Executive summary, Key findings.
   - **Headers:** Parsed & Raw RFC 822 headers with SPF/DKIM/DMARC alignment badges.
   - **Route:** Interactive chronological mail hop transport timeline.
   - **Geo:** Global infrastructure map with coordinates and forensic disclaimer.
   - **Graph:** Entity relationship diagram.
   - **Indicators:** Actionable IOC extraction table with 1-click copy and JSON export.
   - **Evidence:** Structured evidentiary findings ledger with risk rationale.
   - **Report:** Formal printable Incident Response dossier with SHA-256 seal.
4. **Origin Map (`/map`)**: Global geospatial infrastructure footprint across all investigated cases.
5. **Reports & Cases (`/cases`)**: Searchable and filterable case registry by Case ID, Sender, or Subject.
6. **Methodology (`/methodology`)**: Interactive 4-stage pipeline architecture (Extract ➔ Score ➔ Qualify ➔ Preserve).

---

## ⚖️ Ethical & Legal Compliance Notice
MailTrace AI is engineered strictly for authorized defensive cybersecurity analysis, incident response, and education. It does not perform active probing, offensive exploitation, or malware execution.
