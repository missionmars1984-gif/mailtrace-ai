import type { SecurityFinding } from '../types/index.js';

interface PhishingPattern {
  name: string;
  category: 'URGENCY' | 'CREDENTIAL' | 'SUSPENSION' | 'ACTION_REQUIRED' | 'SOCIAL_ENGINEERING' | 'BENIGN_SIGNAL';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  regex: RegExp;
  description: string;
  impact: string;
}

const PHISHING_PATTERNS: PhishingPattern[] = [
  {
    name: 'Immediate Account Suspension Threat',
    category: 'SUSPENSION',
    severity: 'CRITICAL',
    regex: /(account\s+will\s+be\s+(suspended|terminated|disabled|locked|closed|deleted)|suspend\s+your\s+account|within\s+(24|12|48|2|1)\s*hours|immediate\s+closure|temporary\s+suspension|action\s+required\s+to\s+prevent\s+closure)/i,
    description: 'Threatens imminent account lockout, suspension, or termination to induce panic and hasty compliance.',
    impact: 'Social engineering coercion tactic forcing the recipient to bypass normal security verification procedures.',
  },
  {
    name: 'Credential Harvesting / Login Solicitation',
    category: 'CREDENTIAL',
    severity: 'CRITICAL',
    regex: /(update\s+your\s+(password|credentials|account\s+details|profile)|verify\s+your\s+(login|identity|credentials|account|email)|log\s*in\s+to\s+(keep\s+your\s+account|verify|confirm|continue|review)|confirm\s+your\s+password|sign\s*in\s+to\s+(view|verify|review|update)|validate\s+your\s+account|click\s+here\s+to\s+(log\s*in|sign\s*in|verify))/i,
    description: 'Prompts recipient to enter existing credentials, passwords, or authentication secrets via a link.',
    impact: 'Direct vector for credential harvesting and account takeover through attacker-controlled authentication portals.',
  },
  {
    name: 'Artificial Urgency / Strict Deadline',
    category: 'URGENCY',
    severity: 'HIGH',
    regex: /(urgent\s+action\s+required|act\s+now|immediate\s+attention|respond\s+immediately|expires\s+in\s+\d+\s*(hours|minutes)|failure\s+to\s+comply|time-sensitive\s+(notice|request)|deadline\s+is\s+today)/i,
    description: 'Manufactures psychological pressure through tight, arbitrary time constraints.',
    impact: 'Artificially reduces critical scrutiny and cognitive reflection before clicking links or executing instructions.',
  },
  {
    name: 'Security Alert / Unauthorized Login Bait',
    category: 'ACTION_REQUIRED',
    severity: 'HIGH',
    regex: /(unauthorized\s+login\s+detected|suspicious\s+activity\s+alert|new\s+sign-in\s+from|security\s+alert:\s+unrecognized\s+device|verify\s+your\s+mfa|unusual\s+sign-in\s+attempt|compromised\s+account\s+warning)/i,
    description: 'Spoofs an automated security warning to provoke defensive clicking into a credential phishing replica.',
    impact: 'Tricks users into submitting credentials or MFA OTP tokens under the impression of securing their accounts.',
  },
  {
    name: 'MFA / Multi-Factor Token Interception',
    category: 'CREDENTIAL',
    severity: 'CRITICAL',
    regex: /(enter\s+the\s+(6|six)[-\s]digit\s+code|verify\s+your\s+one-time\s+(code|passcode|pin)|provide\s+your\s+mfa\s+token|approve\s+the\s+sign-in\s+prompt|authenticator\s+code)/i,
    description: 'Solicits real-time Multi-Factor Authentication (MFA) tokens or One-Time Passcodes (OTP).',
    impact: 'Enables real-time adversary-in-the-middle (AiTM) session hijacking and token replay.',
  },
  {
    name: 'Fake IT Support / Mailbox Storage Migration',
    category: 'ACTION_REQUIRED',
    severity: 'HIGH',
    regex: /(mailbox\s+(quota|storage)\s+(exceeded|is\s+full)|it\s+helpdesk\s+(notice|upgrade|migration)|system\s+administrator\s+broadcast|keep\s+same\s+password\s+after\s+upgrade|email\s+server\s+maintenance)/i,
    description: 'Impersonates internal IT helpdesk or messaging administration regarding storage limits or server migrations.',
    impact: 'Common spear-phishing pretext used to harvest corporate single sign-on (SSO) credentials.',
  },
  {
    name: 'Fake Cloud Document / Shared File Lure',
    category: 'SOCIAL_ENGINEERING',
    severity: 'HIGH',
    regex: /(shared\s+a\s+(document|file|folder)\s+with\s+you|view\s+(shared\s+)?(document|contract|pdf|proposal)\s+on\s+(onedrive|sharepoint|google\s+drive|dropbox)|click\s+to\s+view\s+the\s+secure\s+document)/i,
    description: 'Pretends to share a confidential cloud document or business proposal.',
    impact: 'Redirects victim to fake cloud login portals that harvest OAuth tokens or account passwords.',
  },
  {
    name: 'Fake Delivery / Courier Exception Notice',
    category: 'SOCIAL_ENGINEERING',
    severity: 'MEDIUM',
    regex: /(delivery\s+(attempt\s+failed|exception|pending)|track\s+your\s+(dhl|fedex|ups|usps)\s+package|unpaid\s+customs\s+fee|package\s+held\s+at\s+terminal|reschedule\s+delivery)/i,
    description: 'Spoofs shipping courier notifications regarding pending package delivery or customs payments.',
    impact: 'Lures users into entering personal tracking numbers, payment credentials, or installing malicious payload apps.',
  },
  {
    name: 'Generic Salutation / Impersonal Greeting',
    category: 'SOCIAL_ENGINEERING',
    severity: 'LOW',
    regex: /^(dear\s+(customer|user|member|client|account\s+holder|valued\s+customer|employee))/im,
    description: 'Uses generic impersonal greeting lacking specific recipient name or corporate directory context.',
    impact: 'Characteristic of mass-distributed opportunistic phishing campaigns.',
  },
  {
    name: 'Undisclosed Financial / Invoicing Claim',
    category: 'ACTION_REQUIRED',
    severity: 'MEDIUM',
    regex: /(unpaid\s+invoice|overdue\s+payment|billing\s+discrepancy|order\s+confirmation\s*#\w+|payment\s+receipt\s+attached|past\s+due\s+balance)/i,
    description: 'Claims unexpected financial balance, transaction receipts, or billing irregularities.',
    impact: 'Lures recipient into clicking malicious tracking links or opening weaponized invoice attachments.',
  },
  {
    name: 'Bypass Security Procedures / Coercive Secrecy',
    category: 'SOCIAL_ENGINEERING',
    severity: 'HIGH',
    regex: /(do\s+not\s+(contact|notify|verify\s+with)\s+(the\s+helpdesk|it|security)|bypass\s+(standard|normal)\s+(procedure|protocol)|urgent\s+exception\s+requested)/i,
    description: 'Instructs recipient to explicitly avoid contacting internal IT or security departments.',
    impact: 'Subverts organizational safety controls by deterring secondary validation.',
  },
];

export class PhishingAnalyzer {
  static analyze(text: string, html?: string, subject?: string): SecurityFinding[] {
    const combined = `${subject || ''}\n${text || ''}\n${html || ''}`;
    const findings: SecurityFinding[] = [];
    const matchedNames = new Set<string>();

    // Check for routine, benign password expiration (e.g. "expires in 14 days", "expires in 30 days", "contact IT if needed")
    const isRoutinePasswordNotice = /password\s+expires\s+in\s+(1[0-9]|[2-9][0-9])\s*days/i.test(combined);
    const hasExtremeUrgency = /(within\s+(2|1)\s*hours|immediate\s+closure|action\s+required\s+today)/i.test(combined);

    for (const pattern of PHISHING_PATTERNS) {
      // If it's a routine password reminder with ample days notice, do not trigger credential pressure alarms
      if (pattern.category === 'CREDENTIAL' && isRoutinePasswordNotice && !hasExtremeUrgency) {
        continue;
      }

      const match = pattern.regex.exec(combined);
      if (match && !matchedNames.has(pattern.name)) {
        matchedNames.add(pattern.name);

        const start = Math.max(0, match.index - 30);
        const end = Math.min(combined.length, match.index + match[0].length + 40);
        const snippet = combined.substring(start, end).replace(/\s+/g, ' ').trim();

        findings.push({
          type: 'PHISHING',
          severity: pattern.severity,
          title: pattern.name,
          source: 'Content analysis',
          snippet: `"...${snippet}..."`,
          observed: `Detected pattern matching: ${pattern.description}`,
          impact: pattern.impact,
        });
      }
    }

    return findings;
  }
}
