import type { SecurityFinding } from '../types/index.js';

export interface BecModelInput {
  subject: string;
  bodyText: string;
  senderDisplayName: string;
  senderAddress: string;
  replyToAddress?: string;
  identityRisk?: number;
}

export interface BecModelOutput {
  becRisk: number; // 0–100
  indicators: string[];
  monetarySignals: string[];
  detectedPatterns: {
    hasExecutivePretext: boolean;
    hasFinanceTarget: boolean;
    hasPaymentRequest: boolean;
    hasBankAccountChange: boolean;
    hasUnusualBeneficiary: boolean;
    hasGiftCards: boolean;
    hasUrgency: boolean;
    hasConfidentiality: boolean;
    hasBypassApproval: boolean;
    hasHighMonetaryValue: boolean;
    hasCallbackPhishing?: boolean;
    hasQuishing?: boolean;
    hasFinancialDispute?: boolean;
  };
  findings: SecurityFinding[];
  modelTier: 'COMBINATORIAL_BEC_MODEL';
}

export class ModelD_BecModel {
  /**
   * Combinatorial BEC and Financial Fraud Detection Engine.
   * Evaluates interactions between executive claims, remittance modifications, secrecy, and bypass instructions.
   */
  static analyze(input: BecModelInput): BecModelOutput {
    const { subject, bodyText, senderDisplayName, senderAddress, replyToAddress } = input;
    const fullText = `${subject} ${bodyText} ${senderDisplayName}`.toLowerCase();
    const findings: SecurityFinding[] = [];
    const indicators: string[] = [];
    const monetarySignals: string[] = [];

    // 1. Executive Identity Pretext
    const hasExecutivePretext =
      /(chief\s+executive|cfo|ceo|director|president|managing\s+director|founder|chairman|treasurer)/i.test(senderDisplayName) ||
      /(chief\s+executive|cfo|ceo|president|managing\s+director)/i.test(subject) ||
      /(in\s+a\s+meeting|traveling\s+abroad|reach\s+me\s+only\s+by\s+email|sent\s+from\s+my\s+iphone|sent\s+from\s+my\s+ipad)/i.test(bodyText);

    // 2. Finance / Accounting Recipient Context
    const hasFinanceTarget =
      /(finance|accounting|accounts\s+payable|ap@|billing|payroll|treasury|controller)/i.test(fullText);

    // 3. Payment / Wire Request
    const hasPaymentRequest =
      /(wire\s+transfer|initiate\s+(a\s+)?payment|send\s+(a\s+)?(wire|payment)|process\s+(this\s+)?invoice|electronic\s+funds\s+transfer|transfer\s+funds|remit\s+(payment|balance)|arrang(?:e|ing)\s+payment|payment\s+has\s+been\s+scheduled|settle\s+(this\s+)?(invoice|balance)|amount\s+due|balance\s+due|due\s+date|pay\s+(this\s+)?invoice|invoice\s*:\s*inv-)/i.test(fullText);

    // 4. Bank Account / Routing Number Alteration
    const hasBankAccountChange =
      /(new|updated?|change[d]?|revised|different|switch(?:ed)?)\s+(?:[\w\s]{0,25})?(bank|banking|routing|wire|remittance|account|iban|swift|provider|depository|settlement|payment\s+details)/i.test(fullText) ||
      /(depository\s+institution|bank(?:ing)?\s+details?|remittance\s+details?|settlement\s+account|routing\s+transit\s+number)\s+(?:[\w\s]{0,20})?(has\s+changed|changed|updated)/i.test(fullText) ||
      /(do\s+not\s+remit|stop\s+sending\s+payment|do\s+not\s+send)\s+.*?\b(previous|old|former)\b/i.test(fullText) ||
      /(moved|transferred|switched)\s+(our\s+)?(receivables|processing|banking|accounts|depository)/i.test(fullText) ||
      /(bank\s+name|account\s+name|routing\s+(?:transit\s+)?number|account\s+number|swift\/bic|iban)\s*:/i.test(fullText) ||
      /updated\s+remittance\s+details/i.test(fullText) ||
      /new\s+banking\s+provider/i.test(fullText) ||
      /(switch\s+payment\s+to|remit\s+to\s+new|deposit\s+to\s+(our\s+)?new)/i.test(fullText);

    // 5. Unusual / External Beneficiary
    const hasUnusualBeneficiary =
      /(external\s+beneficiary|overseas\s+account|third-party\s+escrow|special\s+beneficiary|new\s+vendor\s+account)/i.test(fullText) ||
      Boolean(replyToAddress && !replyToAddress.includes(senderAddress.split('@')[1]));

    // 6. Gift Cards Solicitation
    const hasGiftCards =
      /(apple|steam|google\s+play|amazon|target)\s+(gift\s+)?cards/i.test(fullText) &&
      /(purchase|buy|scratch|codes|pins?)/i.test(fullText);

    // 7. Urgency & Strict Deadline
    const hasUrgency =
      /(urgent|immediate\s+attention|time-sensitive|before\s+end\s+of\s+day|wire\s+today|cutoff\s+time|asap)/i.test(fullText);

    // 8. Secrecy & Confidentiality Demand
    const hasConfidentiality =
      /(strictly\s+confidential|keep\s+this\s+(between\s+us|private|confidential)|do\s+not\s+(discuss|mention)|confidential\s+acquisition)/i.test(fullText);

    // 9. Bypassing Approval & Standard Verification
    const hasBypassApproval =
      /(bypass\s+(normal|standard)|waive\s+dual\s+authorization|skip\s+the\s+paperwork|handle\s+this\s+personally|do\s+not\s+call\s+me|cannot\s+take\s+calls)/i.test(fullText);

    // 10. High Monetary Value Extraction
    let hasHighMonetaryValue = false;
    const amountMatches = bodyText.match(/\$\s?([0-9]{1,3}(,[0-9]{3})+(\.[0-9]{2})?|\b[0-9]{5,}\b)/g);
    if (amountMatches) {
      for (const rawAmt of amountMatches) {
        const clean = Number(rawAmt.replace(/[\$,\s]/g, ''));
        if (clean >= 10000) {
          hasHighMonetaryValue = true;
          monetarySignals.push(rawAmt);
        }
      }
    }
    if (/(hundred\s+thousand|fifty\s+thousand|million\s+dollars|\$\s?100,000|\$\s?50,000)/i.test(bodyText)) {
      hasHighMonetaryValue = true;
      monetarySignals.push('$50,000+ indicated');
    }

    // 11. Callback Phishing / Reverse Vishing Lure
    const hasCallbackPhishing =
      /(auto-?debit(?:ed)?|successfully\s+renewed|subscription\s+renewal|order\s+confirmation|total\s+protection\s+plan|membership\s+fee)/i.test(fullText) &&
      /(toll-?free|helpline|support\s+line|call\s+us|contact\s+(?:our\s+)?dispute\s+department|\+\s?1\s?\([0-9]{3}\)|[0-9]{3}-[0-9]{4})/i.test(fullText) &&
      /(refund|cancel(?:lation)?|did\s+not\s+authorize|dispute)/i.test(fullText);

    // 12. Quishing / QR Code Lure
    const hasQuishing =
      /(qr\s+code|scan\s+(the\s+)?(code|image)|scan\s+with\s+your\s+phone|camera\s+and\s+scan)/i.test(fullText) &&
      /(authenticator|mfa|2fa|login|verify|credential|enrollment|keep\s+active)/i.test(fullText);

    // 13. Vendor Commercial Dispute / Delinquency Notice (Elevated AP Review without Fraud Indicators)
    const hasFinancialDispute =
      /(delinquent|past\s+due|overdue|collections|refer\s+(?:the\s+)?balance|pause\s+(?:our\s+)?support|unpaid\s+statement|unpaid\s+deliverables)/i.test(fullText) &&
      /(invoice|payment|balance|statement|retainer|payable)/i.test(fullText);

    // ========================================================
    // COMBINATORIAL EVIDENCE CALCULATION
    // ========================================================
    let becRisk = 0;

    // Critical Combination A: Executive + Payment + Secrecy + High Value / Bypass
    if (hasExecutivePretext && hasPaymentRequest && (hasConfidentiality || hasBypassApproval) && (hasHighMonetaryValue || hasUnusualBeneficiary)) {
      becRisk = 96;
      indicators.push('Executive impersonation wire fraud with confidentiality and procedure bypass instructions');
      findings.push({
        type: 'BEC',
        severity: 'CRITICAL',
        title: 'Executive Wire Transfer Fraud with Secrecy Isolation',
        source: 'BEC model',
        observed: `Executive identity combined with ${monetarySignals.join(', ') || 'wire request'} and strict secrecy demand`,
        impact: 'Classic CEO fraud seeking unauthorized financial exfiltration while deliberately evading internal dual controls.',
      });
    }
    // Critical Combination B: Bank Account Modification on Invoice / Remittance
    else if (hasBankAccountChange) {
      becRisk = 94;
      indicators.push('Unsolicited vendor banking / remittance redirection request');
      findings.push({
        type: 'BEC',
        severity: 'CRITICAL',
        title: 'Fraudulent Remittance & Bank Account Alteration',
        source: 'BEC model',
        observed: 'Request to substitute official banking / routing numbers on pending settlement',
        impact: 'Redirects corporate vendor disbursements directly to attacker-controlled mule accounts.',
      });
    }
    // Critical Combination C: Gift Card Fraud
    else if (hasGiftCards) {
      becRisk = 95;
      indicators.push('Retail gift card code solicitation');
      findings.push({
        type: 'BEC',
        severity: 'CRITICAL',
        title: 'Retail Gift Card / Voucher Solicitations',
        source: 'BEC model',
        observed: 'Request to purchase gift cards and transmit serial PIN codes',
        impact: 'Non-reversible consumer fraud vector providing instantaneous financial extraction.',
      });
    }
    // High Combination C2: Confidential Employee Data / W-2 Exfiltration
    else if (
      /(ssn|w-2|unmasked\s+spreadsheet|compensation\s+table|executive\s+compensation)/i.test(fullText) &&
      (hasConfidentiality || hasExecutivePretext || fullText.includes('confidential'))
    ) {
      becRisk = 88;
      indicators.push('Confidential employee PII / W-2 exfiltration request');
      findings.push({
        type: 'BEC',
        severity: 'HIGH',
        title: 'Confidential Employee PII & Salary Data Exfiltration',
        source: 'BEC model',
        observed: 'Solicitation of unmasked corporate salary and tax data via email',
        impact: 'Used for secondary identity theft and corporate spear phishing.',
      });
    }
    // High Combination D: Executive + Payment Request
    else if (hasExecutivePretext && hasPaymentRequest) {
      becRisk = 85;
      indicators.push('Executive identity requesting urgent payment transfer');
      findings.push({
        type: 'BEC',
        severity: 'HIGH',
        title: 'Executive Payment Transfer Solicitation',
        source: 'BEC model',
        observed: 'Executive requesting funds disbursement without established approval documentation',
        impact: 'Exploits organizational hierarchy to rush financial transactions.',
      });
    }
    // High Combination E: Payroll / Direct Deposit Change
    else if (fullText.includes('direct deposit') && (fullText.includes('payroll') || fullText.includes('paycheck'))) {
      becRisk = 88;
      indicators.push('Employee payroll / direct deposit diversion attempt');
      findings.push({
        type: 'BEC',
        severity: 'HIGH',
        title: 'Payroll Direct Deposit Diversion',
        source: 'BEC model',
        observed: 'Request to modify employee salary disbursement account details',
        impact: 'Reroutes payroll funds into unauthorized accounts.',
      });
    }
    // High Combination E2: Callback Phishing / Reverse Vishing Invoice Scam
    else if (hasCallbackPhishing) {
      becRisk = 88;
      indicators.push('Callback phishing / reverse vishing invoice scam prompting phone cancellation');
      findings.push({
        type: 'BEC',
        severity: 'HIGH',
        title: 'Callback Phishing / Reverse Vishing Invoice Scam',
        source: 'BEC model',
        snippet: subject,
        observed: 'Fraudulent auto-renewal invoice directing user to call a dispute phone helpline',
        impact: 'Victim is socially engineered to contact a fraudulent call center run by attackers to facilitate remote access compromise.',
      });
    }
    // High Combination E3: Quishing / QR-Code Credential Lure
    else if (hasQuishing) {
      becRisk = 82;
      indicators.push('Quishing / QR-code credential redirection lure');
      findings.push({
        type: 'BEC',
        severity: 'HIGH',
        title: 'Quishing / QR-Code Credential Lure',
        source: 'BEC model',
        snippet: subject,
        observed: 'Request to scan embedded QR code for multi-factor authentication enrollment',
        impact: 'Bypasses email gateway URL inspection by transitioning the victim to an unmonitored mobile device.',
      });
    }
    // Borderline Combination E4: Commercial Vendor Collections Dispute
    else if (hasFinancialDispute && !hasBankAccountChange) {
      becRisk = 45;
      indicators.push('Commercial account delinquent notice / corporate collections dispute');
      findings.push({
        type: 'BEC',
        severity: 'MEDIUM',
        title: 'Commercial Account Delinquent Dispute',
        source: 'BEC model',
        snippet: subject,
        observed: 'External vendor reporting overdue balance and threatening services suspension or collections',
        impact: 'Elevated accounts payable priority; requires verification before disbursement.',
      });
    }
    // Moderate Combination F: Payment request alone
    else if (hasPaymentRequest) {
      becRisk = 40;
      indicators.push('Financial payment reference detected in text');
    }
    // Moderate Combination G: Executive pretext alone
    else if (hasExecutivePretext) {
      becRisk = 25;
      indicators.push('Executive communication pattern observed');
    }

    return {
      becRisk,
      indicators,
      monetarySignals,
      detectedPatterns: {
        hasExecutivePretext,
        hasFinanceTarget,
        hasPaymentRequest,
        hasBankAccountChange,
        hasUnusualBeneficiary,
        hasGiftCards,
        hasUrgency,
        hasConfidentiality,
        hasBypassApproval,
        hasHighMonetaryValue,
        hasCallbackPhishing,
        hasQuishing,
        hasFinancialDispute,
      },
      findings,
      modelTier: 'COMBINATORIAL_BEC_MODEL',
    };
  }
}
