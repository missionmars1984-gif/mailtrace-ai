import { GoogleGenAI } from '@google/genai';
import type {
  AiAssessment,
  IdentityAnalysis,
  SecurityFinding,
  ParsedUrl,
  ParsedAttachment,
  RouteHop,
  EmailAddressInfo,
  CaseRecord,
  AssistantMessage,
  ThreatClassification,
} from '../types/index.js';
import { FallbackAnalyzer } from './fallbackAnalyzer.js';

export class GeminiClient {
  private static client: GoogleGenAI | null = null;

  static initialize(): void {
    const apiKey = process.env.GEMINI_API_KEY?.trim();
    if (apiKey) {
      try {
        this.client = new GoogleGenAI({ apiKey });
        console.log('[MailTrace AI] Gemini AI initialized successfully using GEMINI_API_KEY.');
      } catch (err) {
        console.warn('[MailTrace AI] Failed to initialize GoogleGenAI client:', err);
        this.client = null;
      }
    } else {
      console.log('[MailTrace AI] No GEMINI_API_KEY provided; operating in deterministic fallback mode.');
      this.client = null;
    }
  }

  static async analyzeEmail(params: {
    from: EmailAddressInfo;
    to: EmailAddressInfo[];
    replyTo?: EmailAddressInfo;
    returnPath?: string;
    subject: string;
    bodyText: string;
    identity: IdentityAnalysis;
    findings: SecurityFinding[];
    urls: ParsedUrl[];
    attachments: ParsedAttachment[];
    hops: RouteHop[];
  }): Promise<AiAssessment> {
    const { from, to, replyTo, returnPath, subject, bodyText, identity, findings, urls, attachments, hops } = params;

    const apiKey = process.env.GEMINI_API_KEY?.trim();
    if (!this.client && apiKey) {
      this.initialize();
    }

    if (!this.client) {
      return FallbackAnalyzer.analyze(identity, findings, urls, attachments, subject);
    }

    const prompt = `You are the lead email forensics and threat intelligence AI engine of MailTrace AI (SIH 2026).
Evaluate the following email for signs of Phishing, Business Email Compromise (BEC), Impersonation, Malware delivery, or Clean communications.

=== TECHNICAL EMAIL TELEMETRY ===
Subject: ${subject}
Claimed From: ${from.name ? `"${from.name}" ` : ''}<${from.address}>
Envelope Return-Path: ${returnPath || 'none'}
Reply-To: ${replyTo?.address || 'none'}
To: ${to.map((t) => t.address).join(', ')}

Identity Consistency Rating: ${identity.consistency}
Identity Discrepancies: ${identity.reasons.join('; ')}
Reply-To Mismatch: ${identity.replyToMismatch}
Return-Path Mismatch: ${identity.returnPathMismatch}
Display Name Spoofing: ${identity.displayNameSpoofing}
Typosquatted Domain: ${identity.lookalikeDomain ? `Target: ${identity.lookalikeTarget}` : 'No'}

Extracted URLs (${urls.length}):
${urls.slice(0, 8).map((u) => `- ${u.url} (Domain: ${u.domain}, Level: ${u.riskLevel}, Indicators: ${u.riskIndicators.join(', ')})`).join('\n') || 'None'}

Attachments (${attachments.length}):
${attachments.map((a) => `- ${a.filename} (Size: ${a.size} bytes, Ext: .${a.extension}, Dangerous: ${a.isDangerous}, DoubleExtension: ${a.isDoubleExtension}, SHA-256: ${a.sha256})`).join('\n') || 'None'}

Origin Infrastructure Hops (${hops.length}):
${hops.map((h) => `- Hop ${h.hopNumber}: IP ${h.ip || 'n/a'}, Geo: ${h.geo?.city || 'n/a'}, ${h.geo?.country || 'n/a'}, ASN: ${h.geo?.asn || 'n/a'}, Private: ${h.isPrivate}`).join('\n') || 'None'}

Security Rule Signals Detected (${findings.length}):
${findings.map((f) => `- [${f.severity}] ${f.title}: ${f.observed}`).join('\n') || 'No deterministic rule triggers'}

=== EMAIL BODY PREVIEW ===
${bodyText.substring(0, 2500)}

=== STRICT INSTRUCTIONS ===
1. Classification MUST be one of: "Clean", "Suspicious", "Phishing", "BEC", "Impersonation", "Malware".
2. You MUST NOT invent any technical facts, IPs, cities, countries, ASNs, hashes, or URLs. All technical telemetry is provided above.
3. Compare Claimed Identity vs Observed Technical Identity. Passing SPF/DKIM/DMARC does NOT by itself prove innocence.
4. Evaluate multi-label probabilities independently (0.0 to 1.0) for:
   - phishing intent, credential theft, MFA theft, BEC, impersonation, financial fraud, malware delivery, social engineering, sensitive-data harvesting, legitimate business context.
5. Return ONLY a valid, single JSON object adhering strictly to this schema:
{
  "phishingProbability": <float 0.0-1.0>,
  "credentialProbability": <float 0.0-1.0>,
  "mfaProbability": <float 0.0-1.0>,
  "becProbability": <float 0.0-1.0>,
  "impersonationProbability": <float 0.0-1.0>,
  "financialFraudProbability": <float 0.0-1.0>,
  "malwareProbability": <float 0.0-1.0>,
  "socialEngineeringProbability": <float 0.0-1.0>,
  "dataTheftProbability": <float 0.0-1.0>,
  "legitimateProbability": <float 0.0-1.0>,
  "claimedIdentity": "<detected claimed sender/brand/authority>",
  "attackIntent": "<credential_harvesting | mfa_theft | invoice_redirection | wire_fraud | malware_lure | data_exfiltration | delivery_scam | none>",
  "requestedAction": "<password_reset | verify_mfa | wire_transfer | open_attachment | send_ssn_w2 | none>",
  "targetType": "<employee | finance_team | executive | generic_user>",
  "reasoningEvidence": ["<point 1>", "<point 2>", "..."],
  "classification": "Clean" | "Suspicious" | "Phishing" | "BEC" | "Impersonation" | "Malware",
  "risk_score": <number between 0 and 100>,
  "confidence": <number between 0 and 100>,
  "summary": "<2-3 sentence forensic synthesis>",
  "key_findings": ["<bullet 1>", "<bullet 2>", "..."],
  "identity_assessment": "<explanation of sender authenticity vs deception>",
  "phishing_indicators": ["<indicator 1>", "..."],
  "bec_indicators": ["<indicator 1>", "..."],
  "recommended_actions": ["<immediate action 1>", "<action 2>", "..."]
}`;

    try {
      const response = await this.client.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.1,
        },
      });

      const text = response.text?.trim();
      if (!text) {
        throw new Error('Empty response from Gemini API');
      }

      const parsed = JSON.parse(text);
      const validClasses: ThreatClassification[] = ['Clean', 'Suspicious', 'Phishing', 'BEC', 'Impersonation', 'Malware'];
      let classification: ThreatClassification = validClasses.includes(parsed.classification)
        ? parsed.classification
        : (parsed.classification === 'Legitimate' ? 'Clean' : 'Suspicious');

      const clampProb = (val: any) => Math.min(1, Math.max(0, typeof val === 'number' ? val : 0));
      const risk_score = Math.min(100, Math.max(0, typeof parsed.risk_score === 'number' ? Math.round(parsed.risk_score) : 50));
      const confidence = Math.min(100, Math.max(0, typeof parsed.confidence === 'number' ? Math.round(parsed.confidence) : 80));

      const aiReasoning = {
        phishingProbability: clampProb(parsed.phishingProbability),
        credentialProbability: clampProb(parsed.credentialProbability),
        mfaProbability: clampProb(parsed.mfaProbability),
        becProbability: clampProb(parsed.becProbability),
        impersonationProbability: clampProb(parsed.impersonationProbability),
        financialFraudProbability: clampProb(parsed.financialFraudProbability),
        malwareProbability: clampProb(parsed.malwareProbability),
        socialEngineeringProbability: clampProb(parsed.socialEngineeringProbability),
        dataTheftProbability: clampProb(parsed.dataTheftProbability),
        legitimateProbability: clampProb(parsed.legitimateProbability),
        claimedIdentity: String(parsed.claimedIdentity || identity.claimed.displayName || from.name || ''),
        attackIntent: String(parsed.attackIntent || 'none'),
        requestedAction: String(parsed.requestedAction || 'none'),
        targetType: String(parsed.targetType || 'generic_user'),
        reasoningEvidence: Array.isArray(parsed.reasoningEvidence) ? parsed.reasoningEvidence.map(String) : [],
        classification,
        summary: typeof parsed.summary === 'string' ? parsed.summary : 'AI threat analysis completed.',
      };

      return {
        classification,
        risk_score,
        confidence,
        summary: typeof parsed.summary === 'string' ? parsed.summary : 'AI threat analysis completed.',
        key_findings: Array.isArray(parsed.key_findings) ? parsed.key_findings.map(String) : [],
        identity_assessment: typeof parsed.identity_assessment === 'string' ? parsed.identity_assessment : '',
        phishing_indicators: Array.isArray(parsed.phishing_indicators) ? parsed.phishing_indicators.map(String) : [],
        bec_indicators: Array.isArray(parsed.bec_indicators) ? parsed.bec_indicators.map(String) : [],
        recommended_actions: Array.isArray(parsed.recommended_actions) ? parsed.recommended_actions.map(String) : [],
        isFallback: false,
        aiReasoning,
      };
    } catch (err) {
      console.warn('[MailTrace AI] Gemini inference failed or returned invalid response, falling back to deterministic analyzer:', err);
      return FallbackAnalyzer.analyze(identity, findings, urls, attachments, subject);
    }
  }

  /**
   * Dedicated SOC AI Security Assistant.
   * Grounded strictly in the specific case's technical evidence.
   */
  static async askSecurityAssistant(params: {
    caseData?: CaseRecord | null;
    question: string;
    history?: AssistantMessage[];
  }): Promise<string> {
    const { caseData, question } = params;

    const apiKey = process.env.GEMINI_API_KEY?.trim();
    if (!this.client && apiKey) {
      this.initialize();
    }

    if (this.client && caseData) {
      const originHop = caseData.hops.length > 0 ? caseData.hops[caseData.hops.length - 1] : undefined;
      const prompt = `You are the MailTrace AI SOC Security Assistant, an expert digital forensics investigator.
Answer the security analyst's question based STRICTLY on the following verified investigation evidence.

INVESTIGATION CONTEXT:
Case Number: ${caseData.caseNumber}
Verdict / Threat Classification: ${caseData.classification}
Composite Risk Score: ${caseData.riskScore}/100 (${caseData.riskLevel}, ${caseData.confidence}% confidence)
Subject: ${caseData.metadata.subject}
Claimed Sender: "${caseData.metadata.from.name}" <${caseData.metadata.from.address}>
Envelope Return-Path: ${caseData.metadata.returnPath || 'N/A'}
Reply-To: ${caseData.metadata.replyTo?.address || 'N/A'}
Claimed vs Observed Identity:
- Consistency: ${caseData.identityAnalysis.consistency}
- Inconsistencies: ${caseData.identityAnalysis.reasons.join('; ') || 'None'}
- Display Name Spoofing: ${caseData.identityAnalysis.displayNameSpoofing}
- Lookalike Domain: ${caseData.identityAnalysis.lookalikeDomain ? `Target: ${caseData.identityAnalysis.lookalikeTarget}` : 'No'}
Authentication:
- SPF: ${caseData.metadata.auth.spf.status} (${caseData.metadata.auth.spf.details || ''})
- DKIM: ${caseData.metadata.auth.dkim.status} (${caseData.metadata.auth.dkim.details || ''})
- DMARC: ${caseData.metadata.auth.dmarc.status}
Observed Infrastructure Origin:
- IP: ${originHop?.ip || 'N/A'}
- Jurisdiction / City: ${originHop?.geo?.city || ''}, ${originHop?.geo?.country || 'N/A'}
- Autonomous System: ${originHop?.geo?.asn || ''} (${originHop?.geo?.org || originHop?.geo?.isp || ''})
- Private / Loopback: ${originHop?.isPrivate ? 'Yes (RFC1918 Private subnet)' : 'No (Public)'}
Evidence Findings:
${caseData.findings.map(f => `- [${f.severity}] ${f.title}: ${f.observed} -> Impact: ${f.impact}`).join('\n') || 'None'}
URLs: ${caseData.urls.map(u => `${u.url} (Risk: ${u.riskLevel}, Domain: ${u.domain})`).join('; ') || 'None'}
Attachments: ${caseData.attachments.map(a => `${a.filename} (Size: ${a.size} bytes, SHA-256: ${a.sha256})`).join('; ') || 'None'}
Executive Summary: ${caseData.summary}

USER QUESTION:
"${question}"

STRICT GUIDELINES:
1. Ground your answer completely in the facts above.
2. If the user asks about the origin IP or geolocation, clearly clarify that IP geolocation represents approximate observed network infrastructure and does not prove the legal identity or physical residence of the human sender.
3. Be professional, concise, and technically precise.
4. Do NOT hallucinate external reputation, IPs, or IOCs not present in the record.`;

      try {
        const response = await this.client.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
          config: {
            temperature: 0.2,
          },
        });
        const answer = response.text?.trim();
        if (answer) return answer;
      } catch (err) {
        console.warn('[GeminiClient] Security assistant query failed, using deterministic response:', err);
      }
    }

    // Deterministic evidence-grounded response fallback
    return this.generateDeterministicAssistantAnswer(caseData, question);
  }

  private static generateDeterministicAssistantAnswer(caseData?: CaseRecord | null, question?: string): string {
    if (!caseData) {
      return `Welcome to the MailTrace AI SOC Security Assistant. MailTrace continuously analyzes raw email MIME headers, computes cryptographic hashes, evaluates Claimed vs. Observed Identity, and geolocates public relay infrastructure. To inspect a specific threat, select or open a case from the Case Registry.`;
    }

    const q = (question || '').toLowerCase();
    const originHop = caseData.hops.length > 0 ? caseData.hops[caseData.hops.length - 1] : undefined;

    if (q.includes('flagged') || q.includes('why') || q.includes('reason')) {
      const reasons = caseData.keyFindings.length > 0
        ? caseData.keyFindings.map((f, i) => `${i + 1}. ${f}`).join('\n')
        : 'Multiple security heuristics triggered on envelope inconsistencies and threat signatures.';
      return `Case **${caseData.caseNumber}** was flagged as **${caseData.classification}** (Risk Score: **${caseData.riskScore}/100**) based on the following key evidentiary findings:\n\n${reasons}\n\n*Forensic note: Claimed sender identity consistency is rated ${caseData.identityAnalysis.consistency}.*`;
    }

    if (q.includes('ip') || q.includes('where') || q.includes('geolocate') || q.includes('infrastructure')) {
      if (!originHop || !originHop.ip) {
        return `No public IP address was observed in the technical headers of case ${caseData.caseNumber}.`;
      }
      if (originHop.isPrivate) {
        return `The originating mail relay for case **${caseData.caseNumber}** is **${originHop.ip}**, which is an internal/private RFC 1918 address. Geolocation is unavailable for non-public IP infrastructure.`;
      }
      const geo = originHop.geo;
      return `Observed email infrastructure for case **${caseData.caseNumber}**:\n- **Observed IP:** ${originHop.ip}\n- **Jurisdiction:** ${geo?.city ? geo.city + ', ' : ''}${geo?.country || 'Unknown'}\n- **Autonomous System:** ${geo?.asn || 'Unassigned'} (${geo?.org || geo?.isp || 'Unknown ISP'})\n\n*Forensic Context: IP geolocation represents approximate network infrastructure location. It does not prove the physical location or identity of the human sender.*`;
    }

    if (q.includes('spf') || q.includes('dkim') || q.includes('dmarc') || q.includes('auth')) {
      const auth = caseData.metadata.auth;
      return `Cryptographic Authentication Results for **${caseData.caseNumber}**:\n- **SPF:** ${auth.spf.status.toUpperCase()} (${auth.spf.details || 'SPF evaluation'})\n- **DKIM:** ${auth.dkim.status.toUpperCase()} (${auth.dkim.details || 'Signature verification'})\n- **DMARC:** ${auth.dmarc.status.toUpperCase()}\n\n*Key Forensic Principle:* Passing SPF/DKIM/DMARC does not automatically prove an email is harmless. Attackers frequently register lookalike domains or leverage compromised legitimate relays to achieve passing authentication checks.`;
    }

    if (q.includes('identity') || q.includes('inconsistent') || q.includes('mismatch')) {
      return `Claimed vs Observed Technical Identity Analysis:\n- **Claimed:** "${caseData.identityAnalysis.claimed.displayName}" <${caseData.identityAnalysis.claimed.email}> (@${caseData.identityAnalysis.claimed.domain})\n- **Observed Return-Path:** ${caseData.identityAnalysis.observed.returnPath || 'Not set'}\n- **Observed Reply-To:** ${caseData.identityAnalysis.observed.replyTo || 'Not set'}\n- **Consistency Rating:** **${caseData.identityAnalysis.consistency}**\n\nSpecific discrepancies:\n${caseData.identityAnalysis.reasons.map(r => `• ${r}`).join('\n')}`;
    }

    if (q.includes('score') || q.includes('risk')) {
      return `Case **${caseData.caseNumber}** received a composite risk score of **${caseData.riskScore}/100** (${caseData.riskLevel.toUpperCase()}). This score reflects deterministic signal weighting from envelope identity checks, URL targets, payload analysis, and network infrastructure anomalies.`;
    }

    if (q.includes('indicator') || q.includes('ioc') || q.includes('investigate')) {
      return `Actionable Indicators of Compromise (IOCs) for **${caseData.caseNumber}**:\n- **IOC Count:** ${caseData.iocs.length} extracted items\n- **Primary IOCs:**\n${caseData.iocs.slice(0, 5).map(i => `  • [${i.type}] \`${i.value}\` (${i.severity} severity)`).join('\n')}\n\nRecommended Action: Ingest these IOCs into organizational EDR/SIEM threat feeds and block destination domains.`;
    }

    // General case synthesis
    return `**Case ${caseData.caseNumber} Summary:**\n- **Classification:** ${caseData.classification}\n- **Risk Score:** ${caseData.riskScore}/100 (${caseData.riskLevel})\n- **Subject:** ${caseData.metadata.subject}\n- **Summary:** ${caseData.summary}\n- **Recommended Action:** ${caseData.aiAssessment.recommended_actions[0] || 'Quarantine and notify security operations.'}`;
  }
}
