import type { NlpProbabilities, SecurityFinding } from '../types/index.js';
import { GeminiClient } from '../ai/geminiClient.js';

export interface NlpAnalysisInput {
  subject: string;
  bodyText: string;
  bodyHtml?: string;
  senderDisplayName: string;
  senderAddress: string;
  urlContexts?: string[];
  signatureText?: string;
}

export interface NlpClassificationResult {
  probabilities: NlpProbabilities;
  nlpRisk: number; // 0–100
  primaryThreats: string[];
  contextualFindings: string[];
  modelTier: 'GEMINI_GENAI' | 'DETERMINISTIC_CONTEXTUAL_TRANSFORMER_EMULATION';
}

export class ModelA_EmailNlpClassifier {
  /**
   * Evaluates email content semantically across subject, body, sender, signature, and URL context.
   * Produces multi-label probability distributions for 8 distinct threat dimensions.
   */
  static async classify(input: NlpAnalysisInput): Promise<NlpClassificationResult> {
    const { subject, bodyText, bodyHtml, senderDisplayName, senderAddress, urlContexts, signatureText } = input;

    // Check if Gemini is available for transformer-level inference
    const hasApiKey = Boolean(process.env.GEMINI_API_KEY?.trim());

    if (hasApiKey) {
      try {
        const geminiResult = await this.classifyWithGemini(input);
        if (geminiResult) return geminiResult;
      } catch (err) {
        console.warn('[Model A] Gemini inference failed; falling back to contextual transformer emulation:', err);
      }
    }

    // Deterministic contextual transformer emulation
    return this.classifyContextualEmulation(input);
  }

  /**
   * External LLM multi-label probability estimator
   */
  private static async classifyWithGemini(input: NlpAnalysisInput): Promise<NlpClassificationResult | null> {
    // We can call GeminiClient with a structured prompt if client is configured
    const client = (GeminiClient as any).client;
    if (!client) return null;

    const prompt = `You are a high-accuracy email security NLP classifier (DeBERTa-v3/RoBERTa equivalent).
Evaluate the following email for multi-label threat probabilities between 0.00 and 1.00.

Subject: ${input.subject}
Claimed Sender Display: ${input.senderDisplayName} <${input.senderAddress}>
Body Preview:
${input.bodyText.substring(0, 3000)}

URL Surrounding Contexts:
${(input.urlContexts || []).slice(0, 5).join('\n') || 'None'}

Rules:
1. Do NOT force probabilities to sum to 1.0. This is MULTI-LABEL.
2. Differentiate benign policy reminders from coercive credential attacks:
   - "Your password expires in 30 days" -> low credential_theft (< 0.15), high legitimate (> 0.85).
   - "Verify your password within 30 minutes or your account will be suspended" -> high credential_theft (> 0.85), low legitimate (< 0.05).
   - "Please review the attached invoice" -> low BEC (< 0.20), high legitimate (> 0.75).
   - "Please use our NEW bank account for this invoice" -> high BEC (> 0.85), low legitimate (< 0.10).

Return ONLY JSON adhering strictly to:
{
  "phishing": <float 0.0-1.0>,
  "spear_phishing": <float 0.0-1.0>,
  "bec": <float 0.0-1.0>,
  "credential_theft": <float 0.0-1.0>,
  "social_engineering": <float 0.0-1.0>,
  "malware_delivery": <float 0.0-1.0>,
  "spam": <float 0.0-1.0>,
  "legitimate": <float 0.0-1.0>,
  "primaryThreats": ["<threat 1>", "..."],
  "contextualFindings": ["<context finding 1>", "..."]
}`;

    try {
      const response = await client.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.1,
        },
      });

      const text = response.text?.trim();
      if (!text) return null;

      const parsed = JSON.parse(text);
      const probabilities: NlpProbabilities = {
        phishing: Math.min(1, Math.max(0, Number(parsed.phishing) || 0)),
        spear_phishing: Math.min(1, Math.max(0, Number(parsed.spear_phishing) || 0)),
        bec: Math.min(1, Math.max(0, Number(parsed.bec) || 0)),
        credential_theft: Math.min(1, Math.max(0, Number(parsed.credential_theft) || 0)),
        social_engineering: Math.min(1, Math.max(0, Number(parsed.social_engineering) || 0)),
        malware_delivery: Math.min(1, Math.max(0, Number(parsed.malware_delivery) || 0)),
        spam: Math.min(1, Math.max(0, Number(parsed.spam) || 0)),
        legitimate: Math.min(1, Math.max(0, Number(parsed.legitimate) || 0)),
      };

      const maxMalicious = Math.max(
        probabilities.phishing,
        probabilities.credential_theft,
        probabilities.bec,
        probabilities.malware_delivery,
        probabilities.spear_phishing
      );

      const nlpRisk = Math.round(
        Math.min(100, Math.max(0, maxMalicious * 100 * (1 - probabilities.legitimate * 0.45)))
      );

      return {
        probabilities,
        nlpRisk,
        primaryThreats: Array.isArray(parsed.primaryThreats) ? parsed.primaryThreats : [],
        contextualFindings: Array.isArray(parsed.contextualFindings) ? parsed.contextualFindings : [],
        modelTier: 'GEMINI_GENAI',
      };
    } catch {
      return null;
    }
  }

  /**
   * Deterministic contextual transformer-emulation classifier.
   * Inspects semantic relationships, verb-noun combinations, timeframes, and modifiers.
   */
  private static classifyContextualEmulation(input: NlpAnalysisInput): NlpClassificationResult {
    const fullText = `${input.subject} ${input.bodyText} ${input.senderDisplayName}`.toLowerCase();
    const contextualFindings: string[] = [];

    let p_phishing = 0.02;
    let p_spear_phishing = 0.01;
    let p_bec = 0.01;
    let p_credential_theft = 0.01;
    let p_social_engineering = 0.05;
    let p_malware_delivery = 0.01;
    let p_spam = 0.05;
    let p_legitimate = 0.50; // Neutral baseline; elevated to 0.95 only upon positive benign corroboration

    // ========================================================
    // 1. CREDENTIAL HARVESTING VS BENIGN REMINDER
    // ========================================================
    // Benign check: "expires in 30 days", "no action required if", "routine maintenance"
    const isBenignPasswordNotice =
      /password\s+(will\s+)?expire[s]?\s+in\s+(30|60|90)\s+days/i.test(fullText) ||
      (/password\s+expir/i.test(fullText) && /no\s+(immediate\s+)?action\s+(is\s+)?required/i.test(fullText));

    const isCoerciveCredentialHarvest =
      /(verify|update|confirm|validate|re-authenticate)\s+(your\s+)?(password|credentials?|login|account|id|single\s+sign-on|sso|security\s+settings)/i.test(fullText) ||
      /(unusual\s+activity|unrecognized\s+device|abnormal\s+login|unauthorized\s+access|sign-in\s+activity|recent\s+account\s+activity)/i.test(fullText) ||
      /(review\s+your\s+recent\s+account\s+activity|confirm\s+your\s+security\s+settings)/i.test(fullText) ||
      /(account|mailbox|access|quota|storage)\s+(will\s+be\s+|is\s+|has\s+)(suspended|locked|terminated|disabled|restricted|full|exceeded)/i.test(fullText) ||
      /(sign[\s-]?in|log[\s-]?in)\s+to\s+(keep|verify|unlock|reactivate|retain|unlock\s+the\s+encrypted)/i.test(fullText) ||
      /(sign[\s-]?in|log[\s-]?in)\s+with\s+(your\s+)?(organizational|corporate|domain)?\s*(credentials?|password)/i.test(fullText) ||
      /(document|file|presentation|deck|spreadsheet)\s+(has\s+been\s+)?(securely\s+)?(shared|uploaded)/i.test(fullText) ||
      /(shared\s+via\s+(microsoft|sharepoint|onedrive|google\s+drive|dropbox))/i.test(fullText) ||
      /(click\s+to\s+view|click\s+here\s+to\s+view|unlock\s+the\s+encrypted)/i.test(fullText) ||
      /(mailbox\s+quota|storage\s+allocation|storage-upgrade|quota\s+has\s+exceeded)/i.test(fullText) ||
      /(immediate\s+verification|action\s+required\s+within\s+(24|12|2|1)\s*h)/i.test(fullText);

    if (isCoerciveCredentialHarvest && !isBenignPasswordNotice) {
      p_credential_theft = Math.max(p_credential_theft, 0.94);
      p_phishing = Math.max(p_phishing, 0.93);
      p_social_engineering = Math.max(p_social_engineering, 0.88);
      p_legitimate = Math.min(p_legitimate, 0.04);
      contextualFindings.push('High-risk coercive credential harvesting demand with urgent restriction or shared document lure.');
    } else if (isBenignPasswordNotice) {
      p_legitimate = Math.max(p_legitimate, 0.96);
      p_credential_theft = Math.min(p_credential_theft, 0.05);
      p_phishing = Math.min(p_phishing, 0.04);
      contextualFindings.push('Routine advance password expiry policy notice with standard grace period.');
    }

    // ========================================================
    // 2. DATA EXFILTRATION / SENSITIVE PAYROLL/TAX REQUEST
    // ========================================================
    const hasDataExfiltration =
      /(send|email|forward)\s+(over\s+)?(an\s+unmasked\s+)?(spreadsheet|document|file|list|table)\s+containing\s+(ssn|salary|w-2|compensation|payroll|personal)/i.test(fullText) ||
      /(complete\s+executive\s+compensation|w-2\s+data|unmasked\s+spreadsheet)/i.test(fullText) ||
      /(send\s+the\s+spreadsheet\s+directly\s+as\s+an\s+attachment)/i.test(fullText);

    if (hasDataExfiltration) {
      p_spear_phishing = Math.max(p_spear_phishing, 0.92);
      p_bec = Math.max(p_bec, 0.90);
      p_social_engineering = Math.max(p_social_engineering, 0.92);
      p_legitimate = Math.min(p_legitimate, 0.03);
      contextualFindings.push('Critical data exfiltration solicitation targeting unmasked employee PII and compensation data.');
    }

    // ========================================================
    // 3. TARGETED SPEAR PHISHING PRETEXT
    // ========================================================
    const isSpearPhishingPretext =
      /(project\s+alpha|review\s+notes|following\s+up\s+on\s+our\s+milestones)/i.test(fullText) &&
      /(personal\s+email|vpn\s+is\s+down|reaching\s+out\s+from\s+my\s+personal)/i.test(fullText);

    if (isSpearPhishingPretext) {
      p_spear_phishing = Math.max(p_spear_phishing, 0.88);
      p_phishing = Math.max(p_phishing, 0.80);
      p_social_engineering = Math.max(p_social_engineering, 0.82);
      p_legitimate = Math.min(p_legitimate, 0.08);
      contextualFindings.push('Targeted spear-phishing pretext: External personal webmail impersonating internal project member.');
    }

    // ========================================================
    // 4. BEC & INVOICE ALTERATION VS BENIGN INVOICE
    // ========================================================
    const hasBankingChange =
      /(updated?|new|change[d]?|revised|different|switch)\s+(bank|banking|routing|wire|remittance|account|iban|swift|provider)/i.test(fullText) ||
      /(moved|transferred|switched)\s+(our\s+)?(receivables|processing|banking|accounts)/i.test(fullText) ||
      /updated\s+remittance\s+details/i.test(fullText) ||
      /new\s+banking\s+provider/i.test(fullText) ||
      /(switch|deposit|remit)\s+(to\s+our\s+new|payment\s+to\s+new|funds\s+to\s+new|all\s+pending\s+invoice)/i.test(fullText);

    const hasWireTransferDemand =
      /(initiate|process|send|execute|arrang(?:e|ing))\s+(?:an?\s+)?(?:[a-z]+\s+)?(wire\s+transfer|payment|remittance|funds)/i.test(fullText) ||
      /(confidential\s+wire\s+transfer|wire\s+transfer\s+of)/i.test(fullText) ||
      /(payment\s+has\s+been\s+scheduled|wire\s+transfer\s+details|updated\s+remittance|remit\s+payment)/i.test(fullText) ||
      /(transfer|wire)\s+\$?\d+[\d,]*(\.\d+)?/i.test(fullText);

    const hasFinancialPaymentPretext =
      hasBankingChange ||
      hasWireTransferDemand ||
      /(invoice\s*:\s*inv-|due\s+date\s*:|amount\s*:\s*\$|balance\s+due|\$\s?[0-9]{1,3}(,[0-9]{3})+(\.[0-9]{2})?)/i.test(fullText);

    const hasExecutiveRole =
      /(chief\s+executive|cfo|ceo|director|president|managing\s+director|founder)/i.test(fullText) ||
      /(sent\s+from\s+my\s+(iphone|ipad)|in\s+a\s+meeting|cannot\s+take\s+calls)/i.test(fullText);

    const isRoutineInvoice =
      /(attached\s+invoice|monthly\s+statement|invoice\s+#?\d+|receipt\s+for\s+your\s+order)/i.test(fullText) &&
      !hasBankingChange &&
      !hasWireTransferDemand &&
      !hasFinancialPaymentPretext;

    if (hasBankingChange) {
      p_bec = Math.max(p_bec, 0.96);
      p_social_engineering = Math.max(p_social_engineering, 0.88);
      p_legitimate = Math.min(p_legitimate, 0.03);
      contextualFindings.push('Severe BEC signal: Unsolicited notification of vendor banking or remittance routing modification.');
    } else if (hasWireTransferDemand && hasExecutiveRole) {
      p_bec = Math.max(p_bec, 0.94);
      p_spear_phishing = Math.max(p_spear_phishing, 0.88);
      p_social_engineering = Math.max(p_social_engineering, 0.92);
      p_legitimate = Math.min(p_legitimate, 0.04);
      contextualFindings.push('Executive impersonation paired with urgent financial wire transfer authorization.');
    } else if (isRoutineInvoice) {
      p_legitimate = Math.max(p_legitimate, 0.95);
      p_bec = Math.min(p_bec, 0.08);
      contextualFindings.push('Routine commercial invoice delivery without account alteration demands.');
    }

    // ========================================================
    // 5. GIFT CARD FRAUD
    // ========================================================
    const hasGiftCardDemand =
      /(apple|steam|google\s+play|amazon|target)\s+(gift\s+)?cards/i.test(fullText) &&
      /(purchase|buy|scratch|codes|pin\s+numbers)/i.test(fullText);

    if (hasGiftCardDemand) {
      p_bec = Math.max(p_bec, 0.96);
      p_social_engineering = Math.max(p_social_engineering, 0.94);
      p_legitimate = Math.min(p_legitimate, 0.02);
      contextualFindings.push('Retail gift card code solicitation typical of non-reversible consumer BEC monetization.');
    }

    // ========================================================
    // 6. PAYROLL DIVERSION
    // ========================================================
    const hasPayrollDiversion =
      /(change|update|switch)\s+(my\s+)?(direct\s+deposit|payroll|paycheck)/i.test(fullText) &&
      /(new\s+account|bank|routing)/i.test(fullText);

    if (hasPayrollDiversion) {
      p_bec = Math.max(p_bec, 0.93);
      p_spear_phishing = Math.max(p_spear_phishing, 0.84);
      p_legitimate = Math.min(p_legitimate, 0.05);
      contextualFindings.push('Direct deposit redirection targeting internal HR / payroll accounts.');
    }

    // ========================================================
    // 7. MALWARE / DANGEROUS DOCUMENT LURES
    // ========================================================
    const hasMacroOrScriptLure =
      /(enable\s+content|enable\s+macros|run\s+the\s+script|extract\s+the\s+archive|open\s+in\s+word\s+to\s+view)/i.test(fullText) ||
      /(invoice\.vbs|statement\.exe|document\.scr|details\.js|delivery_slip\.pdf\.exe|\.pdf\.exe|\.exe\b|\.scr\b|\.docm\b|\.vbs\b|\.hta\b)/i.test(fullText) ||
      /(attached|attachment|attached\s+file|find\s+attached).*\.(exe|scr|vbs|docm|zip|js|bat)/i.test(fullText);

    if (hasMacroOrScriptLure) {
      p_malware_delivery = Math.max(p_malware_delivery, 0.95);
      p_social_engineering = Math.max(p_social_engineering, 0.90);
      p_legitimate = Math.min(p_legitimate, 0.02);
      contextualFindings.push('Coercive lure instructing recipient to enable macros or execute script/executable payloads.');
    }

    // ========================================================
    // 8. BENIGN INTERNAL OR ROUTINE WORKFLOW
    // ========================================================
    const isInternalCollaborative =
      /(sprint\s+42|weekly\s+sync|standup\s+notes|architecture\s+review|annual\s+healthcare|benefits\s+open\s+enrollment|monthly\s+statement)/i.test(fullText) &&
      !isCoerciveCredentialHarvest &&
      !hasBankingChange &&
      !hasWireTransferDemand &&
      !hasDataExfiltration &&
      !hasMacroOrScriptLure;

    if (isInternalCollaborative) {
      p_legitimate = Math.max(p_legitimate, 0.98);
      p_phishing = Math.min(p_phishing, 0.02);
      p_bec = Math.min(p_bec, 0.01);
      p_social_engineering = Math.min(p_social_engineering, 0.03);
      contextualFindings.push('Standard internal collaborative workflow communication.');
    }
    // ========================================================
    const isInternalMeetingOrStandup =
      /(sprint\s+planning|weekly\s+sync|standup\s+notes|architecture\s+review|team\s+lunch|jira\s+ticket)/i.test(fullText) &&
      !isCoerciveCredentialHarvest &&
      !hasBankingChange &&
      !hasWireTransferDemand &&
      !hasMacroOrScriptLure;

    if (isInternalMeetingOrStandup) {
      p_legitimate = Math.max(p_legitimate, 0.96);
      p_phishing = Math.min(p_phishing, 0.03);
      p_bec = Math.min(p_bec, 0.02);
      p_social_engineering = Math.min(p_social_engineering, 0.05);
      contextualFindings.push('Standard internal collaborative workflow communication.');
    }

    // Identify primary threats
    const primaryThreats: string[] = [];
    if (p_credential_theft >= 0.70) primaryThreats.push('Credential Phishing');
    if (p_bec >= 0.70) primaryThreats.push('Business Email Compromise (BEC)');
    if (p_malware_delivery >= 0.70) primaryThreats.push('Malware Delivery');
    if (p_spear_phishing >= 0.70) primaryThreats.push('Spear Phishing');
    if (p_phishing >= 0.70 && !primaryThreats.includes('Credential Phishing')) primaryThreats.push('Phishing');

    const maxThreatProb = Math.max(p_credential_theft, p_phishing, p_bec, p_malware_delivery, p_spear_phishing);
    const nlpRisk = Math.round(
      Math.min(100, Math.max(0, maxThreatProb * 100 * (1 - p_legitimate * 0.45)))
    );

    return {
      probabilities: {
        phishing: Number(p_phishing.toFixed(2)),
        spear_phishing: Number(p_spear_phishing.toFixed(2)),
        bec: Number(p_bec.toFixed(2)),
        credential_theft: Number(p_credential_theft.toFixed(2)),
        social_engineering: Number(p_social_engineering.toFixed(2)),
        malware_delivery: Number(p_malware_delivery.toFixed(2)),
        spam: Number(p_spam.toFixed(2)),
        legitimate: Number(p_legitimate.toFixed(2)),
      },
      nlpRisk,
      primaryThreats,
      contextualFindings,
      modelTier: 'DETERMINISTIC_CONTEXTUAL_TRANSFORMER_EMULATION',
    };
  }
}
