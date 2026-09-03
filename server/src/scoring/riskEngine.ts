import type {
  IdentityAnalysis,
  AuthenticationResults,
  SecurityFinding,
  ParsedUrl,
  ParsedAttachment,
  RouteHop,
  AiAssessment,
  ScoreBreakdown,
  ScoreContributor,
  RiskLevel,
  ThreatClassification,
  ComponentScores,
  EvidenceItem,
  NlpProbabilities,
  SocialEngineeringSignals,
  IOCItem,
} from '../types/index.js';
import { CalibrationEngine } from './calibration.js';

export interface FusionWeights {
  nlpModel: number;             // 18%
  urlModel: number;             // 18%
  identityModel: number;        // 17%
  senderModel: number;          // 10%
  becModel: number;             // 10%
  financialModel: number;       // 7%
  headerAuthModel: number;      // 7%
  socialEngineering: number;    // 6%
  attachmentModel: number;      // 5%
  brandModel: number;           // 2%
}

export const DEFAULT_FUSION_WEIGHTS: FusionWeights = {
  nlpModel: 0.18,
  urlModel: 0.18,
  identityModel: 0.17,
  senderModel: 0.10,
  becModel: 0.10,
  financialModel: 0.07,
  headerAuthModel: 0.07,
  socialEngineering: 0.06,
  attachmentModel: 0.05,
  brandModel: 0.02,
};

export interface RiskEngineEvaluationInput {
  nlpProbabilities: NlpProbabilities;
  nlpRisk: number;
  urlRisk: number;
  urls: ParsedUrl[];
  identityRisk: number;
  identityConsistencyScore: number;
  identityAnalysis: IdentityAnalysis;
  claimedIdentity: string;
  observedIdentity: string;
  becRisk: number;
  becPatterns: {
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
  };
  attachmentRisk: number | null;
  attachments: ParsedAttachment[];
  authenticationRisk: number;
  headerRisk: number;
  auth?: AuthenticationResults;
  hops: RouteHop[];
  socialSignals: SocialEngineeringSignals;
  findings: SecurityFinding[];
  weights?: FusionWeights;
  parsedEmail?: {
    from: string;
    to: string[];
    cc: string[];
    replyTo?: string;
    subject: string;
    body: string;
    attachments: Array<{ filename: string; size?: number; contentType?: string; sha256?: string }>;
    urls: string[];
  };
}

export interface RiskEngineEvaluationOutput extends ScoreBreakdown {
  riskScore: number;
  confidence: number;
  classification: ThreatClassification;
  threatTypes: string[];
  claimedIdentity: string;
  observedIdentity: string;
  identityConsistency: number;
  componentScores: ComponentScores;
  indicators: string[];
  extractedIOCs: IOCItem[];
  campaignIndicators: string[];
  quarantineRecommendation: boolean;
  recommendedAction: string;
  evidence: EvidenceItem[];
  appliedEscalationRules: string[];
  benignEvidenceScore: number;
  modelAgreementRatio: number;
}

export class RiskEngine {
  /**
   * Executes the multi-model Evidence Fusion Layer, applies combination synergy rules,
   * enforces hard escalation thresholds, factors in benign negative evidence, and calculates
   * calibrated 0-100 risk score and independent diagnostic confidence.
   */
  static evaluate(input: RiskEngineEvaluationInput): RiskEngineEvaluationOutput {
    const weights = input.weights || DEFAULT_FUSION_WEIGHTS;
    const {
      nlpProbabilities,
      nlpRisk,
      urlRisk,
      urls,
      identityRisk,
      identityConsistencyScore,
      identityAnalysis,
      claimedIdentity,
      observedIdentity,
      becRisk,
      becPatterns,
      attachmentRisk,
      attachments,
      authenticationRisk,
      headerRisk,
      auth,
      hops,
      socialSignals,
      findings,
    } = input;

    const contributors: ScoreContributor[] = [];
    const scoringReasons: string[] = [];
    const appliedEscalationRules: string[] = [];

    const addContributor = (
      name: string,
      points: number,
      source: string,
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
    ) => {
      contributors.push({ name, points, source, severity });
    };

    // 1. Calculate Threat Intel & Contextual Behavior Risks
    let threatIntelRisk: number | null = null;
    let behaviorContextRisk = 0;

    for (const h of hops) {
      if (h.ip && (h.ip.startsWith('185.220.') || h.from?.includes('tor'))) {
        threatIntelRisk = Math.max(threatIntelRisk || 0, 92);
      }
    }

    if (identityAnalysis.replyToMismatch) behaviorContextRisk += 40;
    if (socialSignals.procedureBypass >= 75) behaviorContextRisk += 45;
    behaviorContextRisk = Math.min(100, behaviorContextRisk);

    const activeAttachmentRisk = attachmentRisk !== null ? attachmentRisk : 0;

    // Pre-calculate component risks
    const senderRisk = ModelC_Helper.calculateSenderRisk(identityAnalysis);
    const replyToRisk = ModelC_Helper.calculateReplyToRisk(identityAnalysis);
    const credentialRisk = Math.round(Math.min(100, Math.max(0, nlpProbabilities.credential_theft * 100)));
    const mfaRisk = Math.round(
      Math.min(100, Math.max(0, findings.some((f) => /mfa|otp|2fa|authenticator/i.test(f.title + ' ' + f.observed)) ? 88 : nlpProbabilities.credential_theft * 70))
    );
    const financialRisk = Math.round(
      Math.min(100, Math.max(0, becPatterns.hasBankAccountChange ? 96 : becPatterns.hasPaymentRequest ? 88 : nlpProbabilities.bec * 85))
    );
    const brandRisk = Math.round(
      Math.min(100, Math.max(0, identityAnalysis.lookalikeDomain ? 95 : identityAnalysis.displayNameSpoofing ? 85 : 0))
    );

    // 2. Base Evidence Weighting (proportional normalization for missing models)
    let activeWeightsSum =
      weights.nlpModel +
      weights.identityModel +
      weights.senderModel +
      weights.becModel +
      weights.financialModel +
      weights.headerAuthModel +
      weights.socialEngineering +
      weights.brandModel;

    let baseScoreSum =
      nlpRisk * weights.nlpModel +
      identityRisk * weights.identityModel +
      senderRisk * weights.senderModel +
      becRisk * weights.becModel +
      financialRisk * weights.financialModel +
      Math.max(authenticationRisk, headerRisk) * weights.headerAuthModel +
      socialSignals.overallRisk * weights.socialEngineering +
      brandRisk * weights.brandModel;

    if (urlRisk !== null && urls.length > 0) {
      activeWeightsSum += weights.urlModel;
      baseScoreSum += urlRisk * weights.urlModel;
    }

    if (attachmentRisk !== null && attachments.length > 0) {
      activeWeightsSum += weights.attachmentModel;
      baseScoreSum += attachmentRisk * weights.attachmentModel;
    }

    const weightedBase = activeWeightsSum > 0 ? baseScoreSum / activeWeightsSum : baseScoreSum;

    // 3. Multi-Signal Combination Synergy Boosters (Section 10)
    let synergyBonus = 0;

    // A. Credential harvesting cascade: Credential request + Suspicious URL
    const hasCredentialCascade =
      (nlpProbabilities.credential_theft >= 0.70 || nlpProbabilities.phishing >= 0.75) &&
      (urlRisk >= 60 || urls.some((u) => u.hasSuspiciousKeywords || u.isIpHost));

    if (hasCredentialCascade) {
      const bonus = 28;
      synergyBonus += bonus;
      addContributor('Synergy: Credential Phishing Attack Cascade', bonus, 'URL & NLP fusion', 'CRITICAL');
      scoringReasons.push('Combination of credential harvesting demand with suspicious target URL.');
    }

    // B. Executive BEC wire fraud cascade: Executive impersonation + Financial request + Secrecy
    const hasExecutiveBecCascade =
      (nlpProbabilities.bec >= 0.70 || becRisk >= 70) &&
      (becPatterns.hasExecutivePretext || identityAnalysis.displayNameSpoofing) &&
      (becPatterns.hasPaymentRequest || becPatterns.hasBankAccountChange) &&
      (becPatterns.hasConfidentiality || becPatterns.hasBypassApproval);

    if (hasExecutiveBecCascade) {
      const bonus = 32;
      synergyBonus += bonus;
      addContributor('Synergy: Executive BEC Wire Fraud Cascade', bonus, 'BEC & Identity fusion', 'CRITICAL');
      scoringReasons.push('Combination of executive impersonation, urgent payment request, and secrecy instruction.');
    }

    // C. Vendor Remittance / Bank Account Alteration Cascade
    const hasInvoiceFraudCascade =
      (becPatterns.hasBankAccountChange || nlpProbabilities.bec >= 0.70) &&
      (becPatterns.hasPaymentRequest || becPatterns.hasFinanceTarget || becRisk >= 70 || nlpProbabilities.bec >= 0.80);

    if (hasInvoiceFraudCascade) {
      const bonus = 32;
      synergyBonus += bonus;
      addContributor('Synergy: Vendor Remittance & Banking Modification Cascade', bonus, 'BEC model', 'CRITICAL');
      scoringReasons.push('Vendor banking alteration combined with payment redirection request.');
    }

    // D. Brand impersonation + Domain mismatch
    const hasBrandSpoofingCascade =
      (identityAnalysis.lookalikeDomain || identityAnalysis.displayNameSpoofing || identityAnalysis.punycodeDetected) &&
      (urlRisk >= 50 || nlpRisk >= 50 || identityRisk >= 60);

    if (hasBrandSpoofingCascade) {
      const bonus = 26;
      synergyBonus += bonus;
      addContributor('Synergy: Deceptive Brand Impersonation Cascade', bonus, 'Identity & URL fusion', 'CRITICAL');
      scoringReasons.push('Claimed legitimate brand combined with unregistered lookalike infrastructure.');
    }

    // E. Weaponized attachment + Social engineering lure
    const hasWeaponizedAttachmentCascade =
      activeAttachmentRisk >= 75 &&
      (socialSignals.overallRisk >= 50 || nlpProbabilities.malware_delivery >= 60 || nlpRisk >= 40);

    if (hasWeaponizedAttachmentCascade) {
      const bonus = 30;
      synergyBonus += bonus;
      addContributor('Synergy: Weaponized Payload Delivery Cascade', bonus, 'Attachment & NLP fusion', 'CRITICAL');
      scoringReasons.push('Dangerous attachment payload paired with social engineering pretext.');
    }

    // F. Reply-To Envelope Routing Diversion Cascade
    const hasReplyToDiversionCascade =
      identityAnalysis.replyToMismatch &&
      (identityRisk >= 40 || becRisk >= 20 || nlpRisk >= 20 || socialSignals.overallRisk >= 30);

    if (hasReplyToDiversionCascade) {
      const bonus = 28;
      synergyBonus += bonus;
      addContributor('Synergy: Reply-To Envelope Routing Diversion', bonus, 'Identity check', 'CRITICAL');
      scoringReasons.push('Reply-To routing diverts victim responses to external email infrastructure.');
    }

    // 4. Component contributors
    if (urlRisk >= 70) {
      addContributor('High-Risk Destination URL', Math.round(urlRisk * 0.22), 'URL Model', 'CRITICAL');
    }
    if (nlpRisk >= 70) {
      addContributor('NLP Threat Semantic Classification', Math.round(nlpRisk * 0.22), 'NLP Model', 'CRITICAL');
    }
    if (identityRisk >= 70) {
      addContributor('Severe Identity Inconsistency', Math.round(identityRisk * 0.20), 'Identity Model', 'CRITICAL');
    }
    if (becRisk >= 70) {
      addContributor('Financial Fraud / Remittance Alteration', Math.round(becRisk * 0.22), 'BEC Model', 'CRITICAL');
    }
    if (activeAttachmentRisk >= 75) {
      addContributor('Dangerous File Attachment Payload', Math.round(activeAttachmentRisk * 0.25), 'Attachment Model', 'CRITICAL');
    }
    if (authenticationRisk >= 60) {
      addContributor('Cryptographic Authentication Policy Failure', Math.round(authenticationRisk * 0.15), 'Header Engine', 'HIGH');
    }

    // 5. Calculate preliminary raw score
    let rawScore = Math.round(weightedBase * 1.35 + synergyBonus * 0.7);

    // ========================================================
    // 6. HARD RISK ESCALATION RULES (Section 11)
    // ========================================================
    // Rule 1: IF credential theft probability >= 0.80 AND suspicious URL risk >= 70 THEN min risk >= 75
    if (nlpProbabilities.credential_theft >= 0.80 && urlRisk >= 70) {
      if (rawScore < 76) {
        rawScore = 76;
        appliedEscalationRules.push('Escalation Safeguard: P(credential_theft) >= 0.80 & URL risk >= 70 -> Floor 76');
      }
    }

    // Rule 2: IF credential theft probability >= 0.90 AND identity inconsistency >= 80 AND URL risk >= 80 THEN min risk >= 90
    const identityInconsistency = 100 - identityConsistencyScore;
    if (nlpProbabilities.credential_theft >= 0.90 && identityInconsistency >= 80 && urlRisk >= 80) {
      if (rawScore < 91) {
        rawScore = 91;
        appliedEscalationRules.push('Escalation Safeguard: P(credential_theft) >= 0.90 & Identity Inconsistency >= 80 & URL >= 80 -> Floor 91');
      }
    }

    // Rule 3: IF BEC probability >= 0.85 AND financial request detected AND identity inconsistency >= 70 THEN min risk >= 88
    if (nlpProbabilities.bec >= 0.85 && becPatterns.hasPaymentRequest && identityInconsistency >= 70) {
      if (rawScore < 88) {
        rawScore = 88;
        appliedEscalationRules.push('Escalation Safeguard: P(BEC) >= 0.85 & Financial Request & Identity Inconsistency >= 70 -> Floor 88');
      }
    }

    // Rule 4: IF BEC probability >= 0.90 AND payment amount unusually high AND secrecy/bypass exists THEN min risk >= 93
    if (
      nlpProbabilities.bec >= 0.90 &&
      (becPatterns.hasHighMonetaryValue || becPatterns.hasBankAccountChange) &&
      (becPatterns.hasConfidentiality || becPatterns.hasBypassApproval)
    ) {
      if (rawScore < 94) {
        rawScore = 94;
        appliedEscalationRules.push('Escalation Safeguard: P(BEC) >= 0.90 & High Value/Remittance & Secrecy/Bypass -> Floor 94');
      }
    }

    // ========================================================
    // 6. MINIMUM EVIDENCE SANITY CHECK & HARD ESCALATIONS
    // ========================================================
    // Rule 5: Dangerous Attachment Payload (CRITICAL: An executable/script/macro attachment is an inherent threat)
    const isDangerousAttachment =
      activeAttachmentRisk >= 75 ||
      attachments.some((a) => a.isDangerous || a.isDoubleExtension || a.isMacro);

    if (isDangerousAttachment) {
      const floor = activeAttachmentRisk >= 90 ? 94 : 88;
      if (rawScore < floor) {
        rawScore = floor;
        appliedEscalationRules.push(`Sanity Check Safeguard: Dangerous Attachment Payload (${activeAttachmentRisk || 90}/100) -> Floor ${floor}`);
      }
    }

    // Rule 6: Bank Account Alteration / Remittance Modification (CRITICAL: Must NEVER become 0)
    if (becPatterns.hasBankAccountChange || (becRisk >= 88 && nlpProbabilities.bec >= 0.60)) {
      const floor = 89;
      if (rawScore < floor) {
        rawScore = floor;
        appliedEscalationRules.push(`Sanity Check Safeguard: Bank Account / Remittance Modification Detected -> Floor ${floor}`);
      }
    }

    // Rule 6B: Financial / Payment Request with Pretext or Anomalies
    if (becPatterns.hasPaymentRequest && (becPatterns.hasUrgency || becPatterns.hasConfidentiality || becPatterns.hasBypassApproval || identityRisk >= 35 || nlpProbabilities.bec >= 0.50)) {
      const floor = 85;
      if (rawScore < floor) {
        rawScore = floor;
        appliedEscalationRules.push(`Sanity Check Safeguard: High-Risk Payment/Wire Request -> Floor ${floor}`);
      }
    }

    // Rule 7: IF High-Risk Destination URL with Credential Harvesting Pretext THEN min risk >= 82
    if (urlRisk >= 68 && (nlpProbabilities.credential_theft >= 0.60 || nlpProbabilities.phishing >= 0.60 || nlpRisk >= 50 || socialSignals.urgency >= 60)) {
      if (rawScore < 82) {
        rawScore = 82;
        appliedEscalationRules.push('Escalation Safeguard: High-Risk Destination URL with Credential/Urgency Prompt -> Floor 82');
      }
    }

    // Rule 8: IF Reply-To Routing Diversion on Corporate/Sensitive Pretext THEN min risk >= 78
    if (identityAnalysis.replyToMismatch && (identityRisk >= 40 || nlpRisk >= 25 || becRisk >= 25 || socialSignals.overallRisk >= 30)) {
      if (rawScore < 78) {
        rawScore = 78;
        appliedEscalationRules.push('Escalation Safeguard: Reply-To Envelope Diversion -> Floor 78');
      }
    }

    // Rule 9: IF Confidential Data Exfiltration or Spear-Phishing Lure THEN min risk >= 80
    if ((nlpProbabilities.spear_phishing >= 0.85 || becRisk >= 85) && (socialSignals.secrecy >= 60 || socialSignals.overallRisk >= 60 || identityRisk >= 40)) {
      if (rawScore < 80) {
        rawScore = 80;
        appliedEscalationRules.push('Escalation Safeguard: Confidential Data Exfiltration Lure -> Floor 80');
      }
    }

    // ========================================================
    // 7. BENIGN EVIDENCE REDUCTION (Section 12)
    // ========================================================
    let benignEvidenceScore = 0;
    if (auth) {
      if (auth.spf.status === 'pass') benignEvidenceScore += 15;
      if (auth.dkim.status === 'pass') benignEvidenceScore += 15;
      if (auth.dmarc.status === 'pass') benignEvidenceScore += 20;
    }
    if (identityAnalysis.consistency === 'HIGH' && !identityAnalysis.replyToMismatch && !identityAnalysis.displayNameSpoofing) {
      benignEvidenceScore += 25;
    }
    if (urlRisk === 0 && urls.length > 0 && !urls.some((u) => u.hasSuspiciousKeywords || u.isShortened)) {
      benignEvidenceScore += 15;
    }
    if (nlpProbabilities.legitimate >= 0.85) {
      benignEvidenceScore += 20;
    }

    // CRITICAL SAFEGUARD: Do not allow benign signals to cancel active threat signals!
    const hasAnyThreatSignal =
      appliedEscalationRules.length > 0 ||
      nlpProbabilities.credential_theft >= 0.40 ||
      nlpProbabilities.phishing >= 0.40 ||
      nlpProbabilities.bec >= 0.40 ||
      nlpProbabilities.malware_delivery >= 0.40 ||
      nlpProbabilities.spear_phishing >= 0.40 ||
      urlRisk >= 35 ||
      identityRisk >= 35 ||
      activeAttachmentRisk >= 40 ||
      becRisk >= 40 ||
      socialSignals.overallRisk >= 40;

    if (benignEvidenceScore > 0 && !hasAnyThreatSignal) {
      const discount = Math.round(Math.sqrt(benignEvidenceScore) * 3.0);
      rawScore = Math.max(0, rawScore - discount);
      if (rawScore <= 20) {
        scoringReasons.push('Verified domain alignment, cryptographic authentication pass, and absence of deceptive payloads.');
      }
    }

    // 8. Clamp Final Risk Score (0–100)
    const riskScore = Math.min(100, Math.max(0, rawScore));

    // 9. Five-Tier Classification (Section 13)
    // 0–20: CLEAN | 21–40: LOW RISK | 41–60: SUSPICIOUS | 61–80: HIGH RISK | 81–100: CRITICAL
    let riskLevel: RiskLevel = 'Clean';
    if (riskScore >= 81) {
      riskLevel = 'Critical';
    } else if (riskScore >= 61) {
      riskLevel = 'High Risk';
    } else if (riskScore >= 41) {
      riskLevel = 'Suspicious';
    } else if (riskScore >= 21) {
      riskLevel = 'Low Risk';
    } else {
      riskLevel = 'Clean';
    }

    // 10. Threat Types Categorization
    const threatTypes: string[] = [];
    if (nlpProbabilities.credential_theft >= 0.65 || urlRisk >= 65) {
      threatTypes.push('Credential Phishing');
    }
    if (identityAnalysis.displayNameSpoofing || identityAnalysis.lookalikeDomain || identityAnalysis.punycodeDetected) {
      if (becPatterns.hasExecutivePretext) threatTypes.push('Executive Impersonation');
      else threatTypes.push('Brand Impersonation');
    }
    if (nlpProbabilities.bec >= 0.65 || becRisk >= 65) {
      if (becPatterns.hasBankAccountChange) threatTypes.push('Invoice Fraud');
      else threatTypes.push('Business Email Compromise (BEC)');
    }
    if (nlpProbabilities.malware_delivery >= 0.65 || activeAttachmentRisk >= 65) {
      threatTypes.push('Malware Delivery');
    }
    if (identityAnalysis.replyToMismatch && !threatTypes.includes('Business Email Compromise (BEC)')) {
      threatTypes.push('Reply-To Spoofing');
    }
    if (threatTypes.length === 0) {
      if (riskScore >= 41) threatTypes.push('Suspicious');
      else threatTypes.push('Clean');
    }

    // 11. Specific Threat Classification for Top Level Verdict
    let classification: ThreatClassification = 'Clean';
    if (riskScore <= 20) {
      classification = 'Clean';
    } else if (riskScore >= 61) {
      if (threatTypes.includes('Malware Delivery')) classification = 'Malware';
      else if (threatTypes.includes('Business Email Compromise (BEC)') || threatTypes.includes('Invoice Fraud')) classification = 'BEC';
      else if (threatTypes.includes('Brand Impersonation') || threatTypes.includes('Executive Impersonation')) classification = 'Impersonation';
      else classification = 'Phishing';
    } else if (riskScore >= 41) {
      classification = 'Suspicious';
    } else {
      classification = 'Clean';
    }

    // 12. Component Scores (Section 16 schema)
    const componentScores: ComponentScores = {
      senderRisk,
      identityRisk,
      replyToRisk,
      urlRisk: urls.length > 0 ? (urlRisk !== null ? urlRisk : 0) : null,
      nlpRisk,
      credentialRisk,
      mfaRisk,
      financialRisk,
      becRisk,
      brandRisk,
      attachmentRisk: attachments.length > 0 ? (attachmentRisk !== null ? attachmentRisk : 0) : null,
      headerRisk,
      socialEngineeringRisk: socialSignals.overallRisk,
      threatIntelRisk: threatIntelRisk,
      contentRisk: nlpRisk,
      benignEvidence: benignEvidenceScore,
    };

    // 13. Model Agreement & Diagnostic Confidence Calculation (Section 14)
    const { confidence, agreementRatio } = CalibrationEngine.calculateConfidence({
      nlpRisk,
      urlRisk,
      identityRisk,
      headerRisk,
      attachmentRisk,
      becRisk,
      authPresent: Boolean(auth && auth.spf.status !== 'unknown'),
      hopCount: hops.length,
    });

    // 14. Key Indicators
    const indicators: string[] = [];
    if (nlpProbabilities.credential_theft >= 0.70) indicators.push('Credential harvesting solicitation');
    if (urlRisk >= 60) indicators.push('Suspicious destination URL detected');
    if (identityAnalysis.displayNameSpoofing) indicators.push('Display name impersonation');
    if (identityAnalysis.lookalikeDomain) indicators.push('Lookalike typosquatted domain');
    if (identityAnalysis.replyToMismatch) indicators.push('Reply-To routing diversion');
    if (becRisk >= 70) indicators.push('BEC / financial transfer solicitation');
    if (activeAttachmentRisk >= 75) indicators.push('Dangerous attachment file type');
    if (authenticationRisk >= 60) indicators.push('Cryptographic authentication policy violation');
    if (socialSignals.urgency >= 75) indicators.push('Artificial temporal urgency');
    if (socialSignals.secrecy >= 75) indicators.push('Confidentiality / isolation pressure');
    if (indicators.length === 0) {
      if (riskScore <= 20) indicators.push('Valid cryptographic authentication', 'Sender identity verified', 'No threat payloads');
      else indicators.push('Minor header/domain irregularities');
    }

    // 15. Evidence mapping
    const evidence: EvidenceItem[] = findings.map((f) => ({
      finding: f.title,
      source: f.source || 'General',
      severity: f.severity,
      explanation: f.impact,
      observed: f.observed,
    }));

    // 16. Extracted IOCs & Campaign Indicators
    const extractedIOCs: Array<{ type: 'IP' | 'DOMAIN' | 'URL' | 'EMAIL' | 'HASH' | 'ATTACHMENT'; value: string; severity: 'LOW' | 'MEDIUM' | 'HIGH'; context: string }> = findings
      .filter((f) => f.snippet || f.observed)
      .map((f) => {
        let type: 'IP' | 'DOMAIN' | 'URL' | 'EMAIL' | 'HASH' | 'ATTACHMENT' = 'DOMAIN';
        if (f.type === 'INFRASTRUCTURE' || (f.observed && /^\d+\.\d+\.\d+\.\d+$/.test(f.observed))) type = 'IP';
        else if (f.type === 'URL') type = 'URL';
        else if (f.type === 'ATTACHMENT') type = 'ATTACHMENT';
        else if (f.type === 'IDENTITY' && f.observed.includes('@')) type = 'EMAIL';
        return {
          type,
          value: f.snippet || f.observed,
          severity: f.severity === 'CRITICAL' ? 'HIGH' : f.severity === 'INFO' ? 'LOW' : (f.severity as any),
          context: f.title,
        };
      });

    const campaignIndicators: string[] = [
      ...urls.map((u) => u.domain),
      ...attachments.map((a) => a.sha256).filter(Boolean) as string[],
      observedIdentity,
    ].filter(Boolean);

    const quarantineRecommendation =
      riskScore >= 75 ||
      isDangerousAttachment ||
      (becRisk >= 80 && financialRisk >= 60) ||
      (credentialRisk >= 80 && urlRisk !== null && urlRisk >= 60);

    // 17. Recommended Action
    let recommendedAction = 'Message appears legitimate. No defensive actions required.';
    if (riskScore >= 61) {
      if (threatTypes.includes('Credential Phishing')) {
        recommendedAction = 'Do not click links or enter credentials. Report message to SOC and block destination domain at perimeter gateway.';
      } else if (threatTypes.includes('Business Email Compromise (BEC)') || threatTypes.includes('Invoice Fraud')) {
        recommendedAction = 'Do not initiate payment or alter banking details. Conduct out-of-band verbal authorization with the known authorized executive.';
      } else if (threatTypes.includes('Malware Delivery')) {
        recommendedAction = 'Do not open attachments. Quarantine message and submit file hash for enterprise EDR endpoint isolation.';
      } else {
        recommendedAction = 'Quarantine email immediately and conduct endpoint verification before interacting with links or attachments.';
      }
    } else if (riskScore >= 41) {
      recommendedAction = 'Exercise caution. Verify sender identity through independent secondary channels before following instructions.';
    }

    // 18. Forensic whyHighRisk summary
    let whyHighRisk = '';
    if (riskScore >= 61) {
      const topReasons = contributors.slice(0, 3).map((c) => c.name);
      whyHighRisk = `Classified as ${riskLevel.toUpperCase()} due to concurrent presence of: ${topReasons.join(', ') || threatTypes.join(', ')}. Evidence indicates active attack targeting credentials, financial assets, or system compromise.`;
    } else if (riskScore >= 41) {
      whyHighRisk = 'Classified as SUSPICIOUS. Anomalies identified in message telemetry without direct malicious payload confirmation.';
    } else {
      whyHighRisk = 'Classified as CLEAN. Technical telemetry and authentication records show no indicators of active deception or threat payloads.';
    }

    // ========================================================
    // MANDATORY AUDIT TRACE LOG (Logged for EVERY analyzed email)
    // ========================================================
    const auditLog = {
      parsedEmail: input.parsedEmail || {
        from: claimedIdentity,
        to: [],
        cc: [],
        replyTo: identityAnalysis.observed.replyTo,
        subject: '',
        body: '',
        attachments: attachments.map((a) => ({
          filename: a.filename,
          size: a.size,
          contentType: a.contentType,
          sha256: a.sha256,
        })),
        urls: urls.map((u) => u.url),
      },
      extractedFeatures: {
        credentialRequest: Boolean(
          nlpProbabilities.credential_theft >= 0.60 ||
          findings.some((f) => f.title.toLowerCase().includes('credential') || f.observed.toLowerCase().includes('credential'))
        ),
        financialRequest: Boolean(
          becPatterns.hasPaymentRequest ||
          becPatterns.hasHighMonetaryValue ||
          nlpProbabilities.bec >= 0.60
        ),
        bankAccountChange: Boolean(becPatterns.hasBankAccountChange),
        paymentRequest: Boolean(becPatterns.hasPaymentRequest),
        attachmentPresent: Boolean(attachments && attachments.length > 0),
        attachmentRisk: attachmentRisk,
        urgency: Boolean(socialSignals.urgency >= 60 || becPatterns.hasUrgency),
        secrecy: Boolean(socialSignals.secrecy >= 60 || becPatterns.hasConfidentiality),
        impersonation: Boolean(
          identityAnalysis.displayNameSpoofing ||
          identityAnalysis.lookalikeDomain ||
          identityAnalysis.punycodeDetected ||
          becPatterns.hasExecutivePretext
        ),
        sensitiveInformationRequest: Boolean(
          nlpProbabilities.spear_phishing >= 0.70 ||
          findings.some((f) => f.title.toLowerCase().includes('exfiltration') || f.title.toLowerCase().includes('w-2'))
        ),
        suspiciousDomain: Boolean(
          identityAnalysis.lookalikeDomain ||
          identityAnalysis.punycodeDetected ||
          urls.some((u) => u.hasSuspiciousKeywords || u.isIpHost || u.riskLevel === 'HIGH')
        ),
        urlCount: urls.length,
      },
      modelOutputs: {
        nlpRisk,
        urlRisk,
        senderRisk,
        identityRisk,
        becRisk,
        attachmentRisk,
        headerRisk,
        socialEngineeringRisk: socialSignals.overallRisk,
      },
      fusion: {
        rawScore,
        bonuses: synergyBonus,
        penalties: appliedEscalationRules.length,
        benignEvidence: benignEvidenceScore,
        finalScore: riskScore,
      },
    };

    console.log('\n==================== [MAILTRACE PIPELINE AUDIT TRACE] ====================');
    console.log(JSON.stringify(auditLog, null, 2));
    console.log('================== [END MAILTRACE PIPELINE AUDIT TRACE] ==================\n');

    return {
      riskScore,
      finalScore: riskScore,
      riskLevel,
      confidence,
      classification,
      threatTypes,
      claimedIdentity,
      observedIdentity,
      identityConsistency: identityConsistencyScore,
      componentScores,
      indicators,
      extractedIOCs,
      campaignIndicators,
      quarantineRecommendation,
      evidence,
      recommendedAction,
      contributors,
      synergyBonus,
      whyHighRisk,
      scoringReasons,
      appliedEscalationRules,
      benignEvidenceScore,
      modelAgreementRatio: agreementRatio,
      components: {
        identityScore: identityRisk,
        authScore: authenticationRisk,
        threatContentScore: nlpRisk,
        urlScore: urlRisk,
        attachmentScore: activeAttachmentRisk,
        infrastructureScore: headerRisk,
        synergyScore: synergyBonus,
        aiInfluenceScore: 0,
      },
    };
  }
}

class ModelC_Helper {
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
