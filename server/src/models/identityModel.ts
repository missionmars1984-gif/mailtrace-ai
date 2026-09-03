import type {
  EmailAddressInfo,
  AuthenticationResults,
  IdentityAnalysis,
  SecurityFinding,
  ConsistencyRating,
} from '../types/index.js';

export interface IdentityModelInput {
  from: EmailAddressInfo;
  replyTo?: EmailAddressInfo;
  returnPath?: string;
  urlDomains?: string[];
  signatureText?: string;
  auth?: AuthenticationResults;
}

export interface IdentityModelOutput {
  identityRisk: number; // 0–100
  identityConsistencyScore: number; // 0–100 (100 = perfectly consistent, 0 = severe deception)
  claimedIdentity: string;
  observedIdentity: string;
  identityAnalysis: IdentityAnalysis;
  findings: SecurityFinding[];
  modelTier: 'HEURISTIC_IDENTITY_MODEL';
}

const BRAND_DOMAINS: Record<string, string> = {
  microsoft: 'microsoft.com',
  office365: 'microsoft.com',
  outlook: 'microsoft.com',
  sharepoint: 'microsoft.com',
  onedrive: 'microsoft.com',
  google: 'google.com',
  gmail: 'google.com',
  apple: 'apple.com',
  paypal: 'paypal.com',
  netflix: 'netflix.com',
  amazon: 'amazon.com',
  chase: 'chase.com',
  bankofamerica: 'bankofamerica.com',
  wellsfargo: 'wellsfargo.com',
  dhl: 'dhl.com',
  fedex: 'fedex.com',
  ups: 'ups.com',
  adobe: 'adobe.com',
  docusign: 'docusign.com',
};

const SUSPICIOUS_TLDS = new Set([
  'top', 'xyz', 'buzz', 'click', 'rest', 'bar', 'gq', 'cf', 'ml', 'tk', 'work', 'loan', 'cam', 'country', 'stream', 'kim', 'bid', 'surf', 'icu', 'monster', 'hair', 'beauty', 'quest', 'cfd', 'sbs'
]);

const FREE_WEBMAIL_PROVIDERS = new Set([
  'gmail.com',
  'yahoo.com',
  'hotmail.com',
  'outlook.com',
  'aol.com',
  'icloud.com',
  'protonmail.com',
  'proton.me',
  'mail.com',
  'yandex.com',
  'zoho.com',
]);

export class ModelC_SenderIdentityModel {
  /**
   * Levenshtein Distance for typosquatting / lookalike domain detection.
   */
  static levenshtein(a: string, b: string): number {
    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Evaluates identity consistency across human-facing display elements and technical envelope records.
   */
  static analyze(input: IdentityModelInput): IdentityModelOutput {
    const { from, replyTo, returnPath, urlDomains = [], auth } = input;
    const findings: SecurityFinding[] = [];
    const reasons: string[] = [];

    const fromAddress = from.address.toLowerCase().trim();
    const fromDomain = fromAddress.includes('@') ? fromAddress.split('@')[1] : 'unknown';
    const displayName = (from.name || '').trim();
    const cleanReturnPath = (returnPath || fromAddress).toLowerCase().replace(/[<>]/g, '').trim();
    const returnPathDomain = cleanReturnPath.includes('@') ? cleanReturnPath.split('@')[1] : cleanReturnPath;
    const replyToAddress = replyTo?.address ? replyTo.address.toLowerCase().trim() : undefined;
    const replyToDomain = replyToAddress?.includes('@') ? replyToAddress.split('@')[1] : undefined;

    let replyToMismatch = false;
    let returnPathMismatch = false;
    let displayNameSpoofing = false;
    let lookalikeDomain = false;
    let lookalikeTarget: string | undefined;
    let punycodeDetected = fromDomain.startsWith('xn--') || fromDomain.includes('.xn--');

    let inconsistencyPoints = 0;

    // 1. Reply-To Envelope Redirection Check
    if (replyToDomain && replyToDomain !== fromDomain) {
      replyToMismatch = true;
      inconsistencyPoints += 35;
      reasons.push(`Reply-To address (@${replyToDomain}) diverts responses away from visible From domain (@${fromDomain}).`);
      findings.push({
        type: 'IDENTITY',
        severity: 'HIGH',
        title: 'Reply-To Envelope Redirection Mismatch',
        source: 'Sender model',
        snippet: `From: ${fromAddress} | Reply-To: ${replyToAddress}`,
        observed: `Reply routing altered to external destination: ${replyToAddress}`,
        impact: 'Victim replies will be sent to an attacker-controlled inbox rather than the claimed sender domain.',
      });
    }

    // 2. Return-Path Technical Envelope Mismatch Check
    if (returnPathDomain && returnPathDomain !== fromDomain) {
      // Check if it's an authenticated ESP bounce domain (e.g. mailgun, sendgrid, amazonses)
      const isKnownEspBounce =
        returnPathDomain.includes('sendgrid') ||
        returnPathDomain.includes('amazonses') ||
        returnPathDomain.includes('mailgun') ||
        returnPathDomain.includes('mailchimp');

      if (!isKnownEspBounce) {
        returnPathMismatch = true;
        inconsistencyPoints += 25;
        reasons.push(`Technical envelope Return-Path (@${returnPathDomain}) diverges from human-facing From domain (@${fromDomain}).`);
        findings.push({
          type: 'IDENTITY',
          severity: 'HIGH',
          title: 'Return-Path Domain Divergence',
          source: 'Sender model',
          snippet: `Return-Path: ${cleanReturnPath}`,
          observed: `Envelope bounce domain (@${returnPathDomain}) does not match sender domain (@${fromDomain})`,
          impact: 'Indicates message was injected through third-party or untrusted mail relay infrastructure.',
        });
      }
    }

    // 3. Display Name Brand Impersonation Check
    const lowerDisplayName = displayName.toLowerCase();
    for (const [brand, officialDomain] of Object.entries(BRAND_DOMAINS)) {
      if (lowerDisplayName.includes(brand)) {
        if (!fromDomain.includes(brand) && fromDomain !== officialDomain) {
          displayNameSpoofing = true;
          inconsistencyPoints += 45;
          reasons.push(`Display name claims "${displayName}" but sending address originates from untrusted domain (@${fromDomain}).`);
          findings.push({
            type: 'IDENTITY',
            severity: 'CRITICAL',
            title: `Display Name Brand Impersonation (${brand.toUpperCase()})`,
            source: 'Sender model',
            snippet: `Name: "${displayName}" <${fromAddress}>`,
            observed: `Sender claims identity of ${brand} while using external domain ${fromDomain}`,
            impact: 'Severe deception designed to exploit brand trust and deceive recipients on mobile displays.',
          });
          break;
        }
      }
    }

    // 4. Executive Role Display Name Spoofing
    const isExecutivePretext =
      /(chief\s+executive|cfo|ceo|director|president|founder|managing\s+director|treasurer)/i.test(lowerDisplayName);
    const isFreeWebmail = FREE_WEBMAIL_PROVIDERS.has(fromDomain);

    if (isExecutivePretext && isFreeWebmail) {
      displayNameSpoofing = true;
      inconsistencyPoints += 50;
      reasons.push(`Executive title claimed in display name ("${displayName}") while sending from free webmail provider (@${fromDomain}).`);
      findings.push({
        type: 'IDENTITY',
        severity: 'CRITICAL',
        title: 'Executive Impersonation via Public Webmail',
        source: 'Sender model',
        snippet: `"${displayName}" <${fromAddress}>`,
        observed: `Corporate executive authority claimed from public consumer webmail: ${fromDomain}`,
        impact: 'Classic spear-phishing / BEC initial contact vector.',
      });
    }

    // 5. Typosquatting / Lookalike Domain Detection
    const baseFromDomain = fromDomain.split('.')[0];
    for (const [brand, officialDomain] of Object.entries(BRAND_DOMAINS)) {
      if (fromDomain === officialDomain) continue;

      // Character substitutions e.g. paypa1, micros0ft, g00gle
      const canonicalSubstituted = baseFromDomain.replace(/1/g, 'l').replace(/0/g, 'o').replace(/vv/g, 'w');
      const dist = this.levenshtein(canonicalSubstituted, brand);

      if (
        (dist > 0 && dist <= 2 && baseFromDomain.length >= 4) ||
        (canonicalSubstituted.includes(brand) && fromDomain !== officialDomain) ||
        (fromDomain.includes(brand) && fromDomain !== officialDomain)
      ) {
        lookalikeDomain = true;
        lookalikeTarget = brand;
        inconsistencyPoints += 55;
        reasons.push(`Domain @${fromDomain} is a deceptive typosquatted clone mimicking legitimate brand "${brand}".`);
        findings.push({
          type: 'IDENTITY',
          severity: 'CRITICAL',
          title: `Typosquatted Lookalike Domain Mimicking ${brand.toUpperCase()}`,
          source: 'Sender model',
          snippet: fromDomain,
          observed: `Registered domain @${fromDomain} visually clones authentic domain ${officialDomain}`,
          impact: 'Bypasses visual inspection by mimicking official company communication channels.',
        });
        break;
      }
    }

    // 6. Punycode Detection
    if (punycodeDetected) {
      inconsistencyPoints += 50;
      reasons.push(`Internationalized Punycode homoglyph detected in sender domain (@${fromDomain}).`);
      findings.push({
        type: 'IDENTITY',
        severity: 'CRITICAL',
        title: 'Punycode Homoglyph Sender Domain',
        source: 'Sender model',
        snippet: fromDomain,
        observed: `Encoded ASCII representation: ${fromDomain}`,
        impact: 'Deceptive homoglyph characters used to spoof official ASCII domain names.',
      });
    }

    // 7. Suspicious High-Abuse TLD Check
    const tld = fromDomain.includes('.') ? fromDomain.split('.').pop()! : '';
    if (SUSPICIOUS_TLDS.has(tld)) {
      inconsistencyPoints += 30;
      reasons.push(`Sending domain uses high-abuse/suspicious top-level domain (.${tld}).`);
      findings.push({
        type: 'IDENTITY',
        severity: 'HIGH',
        title: `Suspicious High-Abuse TLD (.${tld.toUpperCase()})`,
        source: 'Sender model',
        snippet: fromDomain,
        observed: `Sender address registered under known high-abuse TLD: .${tld}`,
        impact: 'High-risk infrastructure frequently utilized in disposable phishing operations.',
      });
    }

    // 8. Domain Syntax Anomalies Check (excessive hyphens or numeric strings)
    if (fromDomain.includes('--') || /^[0-9.-]+$/.test(fromDomain) || (fromDomain.match(/-/g) || []).length >= 3) {
      inconsistencyPoints += 25;
      reasons.push(`Sending domain syntax exhibits anomalies (excessive hyphens or numeric patterns).`);
    }

    // Determine Consistency Rating
    let consistency: ConsistencyRating = 'HIGH';
    if (inconsistencyPoints >= 45) {
      consistency = 'LOW';
    } else if (inconsistencyPoints >= 20) {
      consistency = 'MEDIUM';
    } else {
      consistency = 'HIGH';
    }

    if (consistency === 'HIGH' && reasons.length === 0) {
      reasons.push('Claimed sender identity strictly aligns with transport envelope and domain records.');
    }

    // Calculate Identity Consistency Score (0 = completely inconsistent, 100 = completely consistent)
    const identityConsistencyScore = Math.max(0, Math.min(100, 100 - inconsistencyPoints));

    // Calculate Identity Risk Score (0 = safe, 100 = severe identity risk)
    const identityRisk = Math.min(100, Math.max(0, inconsistencyPoints));

    const claimedIdentity = displayName ? `"${displayName}" <${fromAddress}>` : fromAddress;
    const observedIdentity = returnPathDomain ? `@${returnPathDomain}` : fromDomain;

    const identityAnalysis: IdentityAnalysis = {
      claimed: {
        displayName,
        email: fromAddress,
        domain: fromDomain,
      },
      observed: {
        returnPath: cleanReturnPath,
        replyTo: replyToAddress || fromAddress,
        sendingDomain: returnPathDomain,
      },
      consistency,
      reasons,
      replyToMismatch,
      returnPathMismatch,
      displayNameSpoofing,
      lookalikeDomain,
      lookalikeTarget,
      punycodeDetected,
    };

    return {
      identityRisk,
      identityConsistencyScore,
      claimedIdentity,
      observedIdentity,
      identityAnalysis,
      findings,
      modelTier: 'HEURISTIC_IDENTITY_MODEL',
    };
  }

  static calculateSenderRisk(identity: IdentityAnalysis): number {
    let score = 0;
    if (identity.lookalikeDomain) score = Math.max(score, 95);
    if (identity.punycodeDetected) score = Math.max(score, 95);
    if (identity.displayNameSpoofing) score = Math.max(score, 85);
    if (identity.returnPathMismatch) score = Math.max(score, 50);
    return Math.min(100, score);
  }

  static calculateReplyToRisk(identity: IdentityAnalysis): number {
    if (!identity.replyToMismatch) return 0;
    let score = 75;
    const replyTo = identity.observed.replyTo.toLowerCase();
    if (replyTo.includes('harvest') || replyTo.includes('wire') || replyTo.includes('settlement') || replyTo.includes('drop')) {
      score = 95;
    } else if (replyTo.includes('proton') || replyTo.includes('gmail') || replyTo.includes('mailinator')) {
      score = 88;
    }
    return Math.min(100, score);
  }
}
