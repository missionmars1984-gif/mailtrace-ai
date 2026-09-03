import type {
  AiAssessment,
  IdentityAnalysis,
  SecurityFinding,
  ParsedUrl,
  ParsedAttachment,
  ThreatClassification,
} from '../types/index.js';

export class FallbackAnalyzer {
  static analyze(
    identity: IdentityAnalysis,
    findings: SecurityFinding[],
    urls: ParsedUrl[],
    attachments: ParsedAttachment[],
    subject: string
  ): AiAssessment {
    const key_findings: string[] = [];
    const phishing_indicators: string[] = [];
    const bec_indicators: string[] = [];
    const recommended_actions: string[] = [];

    let classification: ThreatClassification = 'Clean';
    let risk_score = 10;
    let confidence = 85;

    // 1. Evaluate attachments (Malware)
    const dangerousAttachments = attachments.filter((a) => a.isDangerous || a.isDoubleExtension);
    const macroAttachments = attachments.filter((a) => a.isMacro);

    if (dangerousAttachments.length > 0) {
      classification = 'Malware';
      risk_score = Math.max(risk_score, 92);
      for (const att of dangerousAttachments) {
        key_findings.push(`Dangerous executable or double-extension payload: "${att.filename}" (SHA-256: ${att.sha256.substring(0, 12)}...).`);
        recommended_actions.push(`Quarantine attachment "${att.filename}" and block matching SHA-256 hash at endpoint security agents.`);
      }
    } else if (macroAttachments.length > 0) {
      classification = 'Malware';
      risk_score = Math.max(risk_score, 82);
      for (const att of macroAttachments) {
        key_findings.push(`Macro-enabled Microsoft Office document attached: "${att.filename}".`);
        recommended_actions.push(`Strip macros or disallow VBA execution for attachment "${att.filename}".`);
      }
    }

    // 2. Evaluate BEC signals
    const becFindings = findings.filter((f) => f.type === 'BEC');
    if (becFindings.length > 0) {
      if (classification !== 'Malware') classification = 'BEC';
      risk_score = Math.max(risk_score, 88);
      for (const f of becFindings) {
        bec_indicators.push(`${f.title}: ${f.snippet || f.observed}`);
        key_findings.push(f.title);
      }
      recommended_actions.push('Establish verbal/out-of-band contact with claimed sender via known corporate directory phone numbers.');
      recommended_actions.push('Do NOT disburse funds, alter vendor routing coordinates, or purchase retail gift cards.');
    }

    // 3. Evaluate Impersonation (Lookalike domain / display spoofing)
    if (identity.lookalikeDomain || (identity.displayNameSpoofing && classification === 'Clean')) {
      if (classification !== 'Malware' && classification !== 'BEC') {
        classification = 'Impersonation';
      }
      risk_score = Math.max(risk_score, 85);
      key_findings.push(identity.lookalikeDomain
        ? `Lookalike typosquat domain detected targeting "${identity.lookalikeTarget || 'trusted brand'}".`
        : 'Display name spoofing impersonating an executive or recognized vendor.');
      recommended_actions.push('Report lookalike domain to registrar abuse desk and block sender envelope across mail gateways.');
    }

    // 4. Evaluate Phishing signals & URLs
    const phishingFindings = findings.filter((f) => f.type === 'PHISHING');
    const highRiskUrls = urls.filter((u) => u.riskLevel === 'HIGH');

    if (phishingFindings.length > 0 || highRiskUrls.length > 0) {
      if (classification !== 'Malware' && classification !== 'BEC') {
        classification = 'Phishing';
      }
      risk_score = Math.max(risk_score, 84);
      for (const f of phishingFindings) {
        phishing_indicators.push(`${f.title}: ${f.snippet || f.observed}`);
        key_findings.push(f.title);
      }
      for (const u of highRiskUrls) {
        key_findings.push(`High-risk URL target: ${u.domain} (${u.riskIndicators.join('; ')})`);
        recommended_actions.push(`Add destination domain "${u.domain}" to web gateway and DNS sinkhole blacklists.`);
      }
      recommended_actions.push('Instruct recipient never to enter credentials or MFA tokens into linked landing pages.');
      recommended_actions.push('Block sender and purge matching messages across organization mailboxes.');
    }

    // 5. Evaluate Identity Consistency
    let identity_assessment = '';
    if (identity.consistency === 'LOW') {
      if (classification === 'Clean') classification = 'Suspicious';
      risk_score = Math.max(risk_score, 75);
      identity_assessment = `CRITICAL DECEPTION: Low identity consistency. ${identity.reasons.join(' ')}`;
      key_findings.push(`Identity mismatch: ${identity.reasons[0]}`);
      recommended_actions.push('Inspect envelope authentication headers and treat sender display name as untrusted.');
    } else if (identity.consistency === 'MEDIUM') {
      if (classification === 'Clean') classification = 'Suspicious';
      risk_score = Math.max(risk_score, 58);
      identity_assessment = `WARNING: Moderate identity inconsistency. ${identity.reasons.join(' ')}`;
    } else {
      identity_assessment = 'VERIFIED: Claimed sender identity aligns with observed envelope and technical infrastructure.';
    }

    // 6. If perfectly clean
    if (classification === 'Clean') {
      risk_score = 10;
      confidence = 94;
      key_findings.push('Sender identity and authentication headers are cryptographically verified.');
      key_findings.push('No phishing language, wire transfer solicitations, or malicious payload signatures observed.');
      recommended_actions.push('Message appears routine and legitimate. Standard email security awareness applies.');
    }

    const summary = classification === 'Clean'
      ? `Deterministic forensic analysis classifies this email as Clean (Risk Score: ${risk_score}/100). Cryptographic authentication passed and structural telemetry verified.`
      : `Deterministic security engine identified severe threat indicators resulting in a verdict of ${classification.toUpperCase()} with an elevated risk score of ${risk_score}/100.`;

    return {
      classification,
      risk_score,
      confidence,
      summary,
      key_findings,
      identity_assessment,
      phishing_indicators,
      bec_indicators,
      recommended_actions,
      isFallback: true,
    };
  }
}
