import type { SecurityFinding } from '../types/index.js';

interface BecPattern {
  name: string;
  category: 'WIRE_TRANSFER' | 'EXECUTIVE_PRESSURE' | 'INVOICE_FRAUD' | 'GIFT_CARD' | 'CONFIDENTIALITY' | 'PAYROLL';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  regex: RegExp;
  description: string;
  impact: string;
}

const BEC_PATTERNS: BecPattern[] = [
  {
    name: 'Wire Transfer / Direct Payment Request',
    category: 'WIRE_TRANSFER',
    severity: 'CRITICAL',
    regex: /(wire\s+transfer|send\s+a\s+(payment|wire)|initiate\s+(a\s+)?wire|transfer\s+\$?\d+[\d,]*|bank\s+transfer\s+today|electronic\s+funds\s+transfer)/i,
    description: 'Direct request to initiate an electronic funds wire transfer.',
    impact: 'Primary vector for financial exfiltration in Business Email Compromise incidents.',
  },
  {
    name: 'Urgent Secrecy / Confidentiality Demand',
    category: 'CONFIDENTIALITY',
    severity: 'HIGH',
    regex: /(keep\s+this\s+(strictly\s+)?confidential|do\s+not\s+(mention|discuss)\s+this|confidential\s+acquisition|private\s+matter|strictly\s+between\s+us)/i,
    description: 'Demands strict confidentiality to prevent recipient from corroborating with colleagues or managers.',
    impact: 'Isolates the target employee from internal accounting controls and dual-authorization processes.',
  },
  {
    name: 'Executive Availability / Mobile Inaccessibility Pretext',
    category: 'EXECUTIVE_PRESSURE',
    severity: 'HIGH',
    regex: /(in\s+a\s+(meeting|conference)|cannot\s+take\s+calls|email\s+only|traveling\s+abroad|sent\s+from\s+my\s+ipad|sent\s+from\s+my\s+iphone|reach\s+me\s+only\s+by\s+email)/i,
    description: 'Explains why the sender cannot be reached via phone or voice verification.',
    impact: 'Pre-emptively neutralizes out-of-band identity verification (e.g. phone call).',
  },
  {
    name: 'Vendor Banking / Direct Deposit Alteration',
    category: 'INVOICE_FRAUD',
    severity: 'CRITICAL',
    regex: /(updated?\s+(banking|wire|account)\s+details|new\s+routing\s+number|remittance\s+address\s+has\s+changed|audit\s+issues\s+with\s+our\s+previous\s+account)/i,
    description: 'Requests substitution of vendor payment account with an attacker-controlled bank account.',
    impact: 'Redirects legitimate corporate vendor settlements directly into fraudulent mule accounts.',
  },
  {
    name: 'Gift Card / Retail Voucher Solicitations',
    category: 'GIFT_CARD',
    severity: 'CRITICAL',
    regex: /(apple\s+gift\s+cards|steam\s+cards|google\s+play\s+cards|purchase\s+\d+\s+gift\s+cards|scratch\s+the\s+codes|send\s+me\s+the\s+pin\s+numbers)/i,
    description: 'Requests purchase and code disclosure of retail gift cards under pretext of employee incentives or client gifts.',
    impact: 'Instant, non-reversible monetization of fraud with virtually zero banking chargeback recourse.',
  },
  {
    name: 'Payroll / Direct Deposit Diversion',
    category: 'PAYROLL',
    severity: 'HIGH',
    regex: /(change\s+my\s+direct\s+deposit|update\s+my\s+payroll\s+info|deposit\s+my\s+paycheck\s+to\s+new\s+account)/i,
    description: 'Impersonates an employee requesting HR/payroll team to switch direct deposit destinations.',
    impact: 'Intercepts salary disbursements into unauthorized bank accounts.',
  },
];

export class BecAnalyzer {
  static analyze(text: string, html?: string, subject?: string): SecurityFinding[] {
    const combined = `${subject || ''}\n${text}\n${html || ''}`;
    const findings: SecurityFinding[] = [];
    const matchedNames = new Set<string>();

    for (const pattern of BEC_PATTERNS) {
      const match = pattern.regex.exec(combined);
      if (match && !matchedNames.has(pattern.name)) {
        matchedNames.add(pattern.name);

        const start = Math.max(0, match.index - 30);
        const end = Math.min(combined.length, match.index + match[0].length + 40);
        const snippet = combined.substring(start, end).replace(/\s+/g, ' ').trim();

        findings.push({
          type: 'BEC',
          severity: pattern.severity,
          title: pattern.name,
          source: 'Content analysis',
          snippet: `"...${snippet}..."`,
          observed: `Detected BEC pattern: ${pattern.description}`,
          impact: pattern.impact,
        });
      }
    }

    return findings;
  }
}
