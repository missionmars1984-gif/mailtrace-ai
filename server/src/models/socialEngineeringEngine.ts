import type { SocialEngineeringSignals, SecurityFinding } from '../types/index.js';

export class SocialEngineeringEngine {
  /**
   * Evaluates psychological coercion and manipulation dimensions:
   * Urgency, Authority, Fear, Secrecy, Pressure, Reward, Curiosity, Trust Exploitation, Procedure Bypass.
   */
  static analyze(subject: string, bodyText: string, senderDisplayName: string): {
    signals: SocialEngineeringSignals;
    findings: SecurityFinding[];
  } {
    const text = `${subject} ${bodyText} ${senderDisplayName}`.toLowerCase();
    const indicators: string[] = [];
    const findings: SecurityFinding[] = [];

    // 1. Urgency (0–100)
    let urgency = 0;
    if (/(immediately|within\s+(24|12|2|1)\s*hours?|act\s+now|urgent\s+action|deadline\s+is\s+today|time-sensitive)/i.test(text)) {
      urgency = 85;
      indicators.push('Manufactured temporal urgency');
    } else if (/(asap|promptly|quick\s+response|today)/i.test(text)) {
      urgency = 45;
    }

    // 2. Authority (0–100)
    let authority = 0;
    if (/(chief\s+executive|ceo|cfo|president|managing\s+director|legal\s+counsel|board\s+of\s+directors)/i.test(text)) {
      authority = 90;
      indicators.push('Executive authority invocation');
    } else if (/(it\s+support|system\s+administrator|human\s+resources|hr\s+director|compliance\s+officer)/i.test(text)) {
      authority = 70;
      indicators.push('Institutional administration authority invocation');
    }

    // 3. Fear & Intimidation (0–100)
    let fear = 0;
    if (/(account\s+suspended|terminated|disabled|legal\s+consequences|disciplinary\s+action|loss\s+of\s+access|permanent\s+deletion)/i.test(text)) {
      fear = 90;
      indicators.push('Account suspension or punitive coercion pretext');
    } else if (/(unauthorized\s+access|security\s+breach|suspicious\s+login)/i.test(text)) {
      fear = 60;
    }

    // 4. Secrecy & Isolation (0–100)
    let secrecy = 0;
    if (/(strictly\s+confidential|keep\s+this\s+(private|between\s+us|to\s+yourself)|do\s+not\s+(mention|discuss|share)|secret\s+deal)/i.test(text)) {
      secrecy = 92;
      indicators.push('Isolation / strict confidentiality demand');
    }

    // 5. Psychological Pressure (0–100)
    let pressure = 0;
    if (/(failure\s+to\s+comply|must\s+complete\s+now|do\s+not\s+delay|no\s+exceptions)/i.test(text)) {
      pressure = 80;
      indicators.push('High-pressure compliance enforcement');
    }

    // 6. Reward / Incentive (0–100)
    let reward = 0;
    if (/(special\s+bonus|gift\s+card\s+incentive|compensation\s+payout|won\s+a\s+prize|grant\s+approved)/i.test(text)) {
      reward = 75;
      indicators.push('Financial reward / voucher bait');
    }

    // 7. Curiosity Bait (0–100)
    let curiosity = 0;
    if (/(confidential\s+salary\s+table|compensation\s+review|confidential\s+inquiry|leaked\s+document)/i.test(text)) {
      curiosity = 75;
      indicators.push('Curiosity exploitation bait');
    }

    // 8. Trust Exploitation (0–100)
    let trustExploitation = 0;
    if (/(your\s+trusted\s+colleague|internal\s+team\s+broadcast|as\s+we\s+discussed|following\s+up\s+on\s+our\s+talk)/i.test(text)) {
      trustExploitation = 65;
    }

    // 9. Procedure Bypass (0–100)
    let procedureBypass = 0;
    if (/(bypass\s+(normal|standard)|waive\s+dual\s+authorization|skip\s+the\s+paperwork|handle\s+this\s+personally|do\s+not\s+call\s+me|cannot\s+take\s+calls)/i.test(text)) {
      procedureBypass = 95;
      indicators.push('Explicit instruction to bypass normal controls and procedures');
    }

    // Calculate Overall Social Engineering Risk
    // High urgency + fear, or authority + secrecy + bypass produce extreme scores
    let overallRisk = 0;
    if (urgency >= 80 && (fear >= 80 || procedureBypass >= 80)) {
      overallRisk = 92;
    } else if (authority >= 80 && (secrecy >= 80 || procedureBypass >= 80)) {
      overallRisk = 94;
    } else if (urgency >= 70 || fear >= 70 || secrecy >= 70 || procedureBypass >= 70) {
      overallRisk = 75;
    } else if (authority >= 60 || reward >= 60 || pressure >= 60) {
      overallRisk = 50;
    } else if (indicators.length > 0) {
      overallRisk = 30;
    }

    if (overallRisk >= 75) {
      findings.push({
        type: 'PHISHING',
        severity: overallRisk >= 85 ? 'CRITICAL' : 'HIGH',
        title: 'High-Coercion Social Engineering Tactics Detected',
        source: 'Social engineering model',
        observed: `Active manipulation vectors: [${indicators.join(', ')}]`,
        impact: 'Deliberately reduces recipient scrutiny and critical thinking through psychological manipulation.',
      });
    }

    return {
      signals: {
        urgency,
        authority,
        fear,
        secrecy,
        pressure,
        reward,
        curiosity,
        trustExploitation,
        procedureBypass,
        overallRisk,
        indicators,
      },
      findings,
    };
  }
}
