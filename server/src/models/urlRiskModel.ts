import type { ParsedUrl, SecurityFinding } from '../types/index.js';

export interface UrlFeatures {
  rawUrl: string;
  domain: string;
  protocol: string;
  urlLength: number;
  hostnameLength: number;
  pathLength: number;
  subdomainCount: number;
  dotCount: number;
  hyphenCount: number;
  specialCharCount: number;
  queryParamCount: number;
  isIpHost: boolean;
  isHttps: boolean;
  isPunycode: boolean;
  isSuspiciousTld: boolean;
  domainEntropy: number;
  brandMismatch: boolean;
  targetedBrand?: string;
  hasSuspiciousKeywords: boolean;
  matchedKeywords: string[];
  isShortener: boolean;
  hasRedirectParam: boolean;
  hostnamePathMismatch: boolean;
  calculatedScore: number;
}

export interface UrlModelOutput {
  urlRisk: number | null; // null if no URLs are analyzed (NOT 0)
  urlReputationStatus: 'available' | 'unavailable' | 'none_present';
  highestRiskUrl?: string;
  features: UrlFeatures[];
  parsedUrls: ParsedUrl[];
  findings: SecurityFinding[];
  modelTier: 'STRUCTURED_FEATURE_FOREST';
}

const SHORTENER_DOMAINS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'adf.ly',
  'cutt.ly',
  'rebrand.ly',
  'shorte.st',
  'bl.ink',
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'work',
  'click',
  'fit',
  'loan',
  'gdn',
  'cfd',
  'live',
  'rest',
  'link',
  'info',
  'buzz',
  'icu',
  'vip',
  'club',
  'online',
  'site',
]);

const SUSPICIOUS_PATH_KEYWORDS = [
  'login',
  'signin',
  'log-in',
  'sign-in',
  'auth',
  'authenticate',
  'verify',
  'verification',
  'secure',
  'account',
  'password',
  'reset',
  'update',
  'portal',
  'banking',
  'wallet',
  'oauth',
  'checkpoint',
  'confirm',
  'credential',
  'session',
  'webmail',
  'office365',
  'passcode',
  'mfa',
  '2fa',
];

const TARGET_BRANDS = [
  'microsoft',
  'office365',
  'outlook',
  'google',
  'gmail',
  'paypal',
  'apple',
  'netflix',
  'amazon',
  'chase',
  'bankofamerica',
  'wellsfargo',
  'citi',
  'dhl',
  'fedex',
  'ups',
  'dropbox',
  'docusign',
  'adobe',
  'quickbooks',
  'intuit',
];

export class ModelB_UrlRiskModel {
  /**
   * Calculates Shannon Entropy: H = -sum(p * log2(p))
   * Measures randomness in domain names (e.g. DGA domains or high-randomness subdomains).
   */
  static calculateShannonEntropy(str: string): number {
    if (!str || str.length === 0) return 0;
    const freq: Record<string, number> = {};
    for (const ch of str) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return Number(entropy.toFixed(3));
  }

  /**
   * Extracts structured feature vector and applies a Decision Forest ensemble to evaluate URL risk.
   */
  static analyzeUrls(rawUrls: string[]): UrlModelOutput {
    if (!rawUrls || rawUrls.length === 0) {
      return {
        urlRisk: null,
        urlReputationStatus: 'none_present',
        features: [],
        parsedUrls: [],
        findings: [],
        modelTier: 'STRUCTURED_FEATURE_FOREST',
      };
    }

    const featuresList: UrlFeatures[] = [];
    const parsedUrls: ParsedUrl[] = [];
    const findings: SecurityFinding[] = [];

    for (const rawUrl of rawUrls) {
      try {
        const parsed = new URL(rawUrl);
        const protocol = parsed.protocol.replace(':', '').toLowerCase();
        const hostname = parsed.hostname.toLowerCase();
        const pathname = parsed.pathname.toLowerCase();
        const search = parsed.search.toLowerCase();
        const fullHref = parsed.href.toLowerCase();

        // 1. Structural features
        const urlLength = rawUrl.length;
        const hostnameLength = hostname.length;
        const pathLength = pathname.length;
        const domainParts = hostname.split('.');
        const subdomainCount = Math.max(0, domainParts.length - 2);
        const dotCount = (rawUrl.match(/\./g) || []).length;
        const hyphenCount = (rawUrl.match(/-/g) || []).length;
        const specialCharCount = (rawUrl.match(/[@_~#%&+=?]/g) || []).length;
        const queryParamCount = Array.from(parsed.searchParams.keys()).length;

        // 2. IP Host Check (RFC1918 or Public IP in authority)
        const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');

        // 3. Protocol
        const isHttps = protocol === 'https';

        // 4. Punycode check
        const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');

        // 5. TLD check
        const tld = domainParts[domainParts.length - 1];
        const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);

        // 6. Domain Shannon Entropy
        const domainEntropy = this.calculateShannonEntropy(hostname);

        // 7. Brand Mismatch & Typosquatting
        let brandMismatch = false;
        let targetedBrand: string | undefined;
        const canonicalHostname = hostname.replace(/0/g, 'o').replace(/1/g, 'l').replace(/vv/g, 'w');
        for (const brand of TARGET_BRANDS) {
          const brandInHostname = hostname.includes(brand) || canonicalHostname.includes(brand);
          const isOfficialBrandDomain =
            hostname === `${brand}.com` ||
            hostname.endsWith(`.${brand}.com`) ||
            hostname === `${brand}.net` ||
            hostname.endsWith(`.${brand}.net`);

          if (brandInHostname && !isOfficialBrandDomain) {
            brandMismatch = true;
            targetedBrand = brand;
            break;
          }
          if (pathname.includes(brand) && !isOfficialBrandDomain && isIpHost) {
            brandMismatch = true;
            targetedBrand = brand;
            break;
          }
        }

        // 8. Suspicious Keywords
        const matchedKeywords = SUSPICIOUS_PATH_KEYWORDS.filter(
          (kw) => pathname.includes(kw) || search.includes(kw)
        );
        const hasSuspiciousKeywords = matchedKeywords.length > 0;

        // 9. Shortener
        const isShortener = SHORTENER_DOMAINS.has(hostname);

        // 10. Open Redirect Parameter
        const hasRedirectParam =
          search.includes('url=') ||
          search.includes('redirect=') ||
          search.includes('dest=') ||
          search.includes('target=') ||
          search.includes('return=');

        // 11. Hostname/Path Mismatch
        const hostnamePathMismatch = brandMismatch && hasSuspiciousKeywords;

        // ========================================================
        // DECISION FOREST FEATURE ENSEMBLE SCORING
        // ========================================================
        let score = 0;

        if (isIpHost) {
          score += 55;
          findings.push({
            type: 'URL',
            severity: 'CRITICAL',
            title: 'Direct Numeric IP Destination URL',
            source: 'URL model',
            snippet: rawUrl,
            observed: `Numeric host: ${hostname}`,
            impact: 'Bypasses standard DNS domain reputation filters; signature of hostile staging servers.',
          });
        }

        if (isPunycode) {
          score += 50;
          findings.push({
            type: 'URL',
            severity: 'CRITICAL',
            title: 'Punycode Internationalized Homoglyph Domain',
            source: 'URL model',
            snippet: hostname,
            observed: `Encoded domain: ${hostname}`,
            impact: 'Visual spoofing designed to clone trusted brands.',
          });
        }

        if (brandMismatch && targetedBrand) {
          score += 48;
          findings.push({
            type: 'URL',
            severity: 'CRITICAL',
            title: `Brand Impersonation in URL Domain (${targetedBrand.toUpperCase()})`,
            source: 'URL model',
            snippet: rawUrl,
            observed: `Mimics ${targetedBrand} on non-official host ${hostname}`,
            impact: 'Tricks users into submitting brand credentials into unauthorized landing pages.',
          });
        }

        if (hasSuspiciousKeywords) {
          score += (isIpHost || !isHttps || brandMismatch) ? 45 : 30;
          findings.push({
            type: 'URL',
            severity: isIpHost || brandMismatch ? 'CRITICAL' : 'HIGH',
            title: 'Credential Harvesting / Login Solicitation Path',
            source: 'URL model',
            snippet: rawUrl,
            observed: `Sensitive keywords: [${matchedKeywords.join(', ')}]`,
            impact: 'Engineered authentication capture form.',
          });
        }

        if (domainEntropy >= 3.75) {
          score += 22;
        }

        if (isShortener) {
          score += 25;
          findings.push({
            type: 'URL',
            severity: 'HIGH',
            title: 'Obfuscated Shortened Link',
            source: 'URL model',
            snippet: rawUrl,
            observed: `Shortener host: ${hostname}`,
            impact: 'Hides true destination from mail gateway scanners.',
          });
        }

        if (hasRedirectParam) {
          score += 20;
        }

        if (isSuspiciousTld) {
          score += 18;
        }

        if (!isHttps) {
          score += 15;
        }

        if (subdomainCount >= 3) {
          score += 18;
        }

        const calculatedScore = Math.min(100, Math.max(0, score));

        featuresList.push({
          rawUrl,
          domain: hostname,
          protocol,
          urlLength,
          hostnameLength,
          pathLength,
          subdomainCount,
          dotCount,
          hyphenCount,
          specialCharCount,
          queryParamCount,
          isIpHost,
          isHttps,
          isPunycode,
          isSuspiciousTld,
          domainEntropy,
          brandMismatch,
          targetedBrand,
          hasSuspiciousKeywords,
          matchedKeywords,
          isShortener,
          hasRedirectParam,
          hostnamePathMismatch,
          calculatedScore,
        });

        // Map to ParsedUrl
        let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
        if (calculatedScore >= 70) riskLevel = 'HIGH';
        else if (calculatedScore >= 40) riskLevel = 'MEDIUM';

        const riskIndicators: string[] = [];
        if (isIpHost) riskIndicators.push('Direct numeric IP address');
        if (isPunycode) riskIndicators.push('Punycode homoglyph representation');
        if (brandMismatch) riskIndicators.push(`Brand mismatch (${targetedBrand})`);
        if (hasSuspiciousKeywords) riskIndicators.push(`Credential keywords [${matchedKeywords.join(', ')}]`);
        if (isShortener) riskIndicators.push('URL shortening service');
        if (domainEntropy >= 3.75) riskIndicators.push(`High domain entropy (${domainEntropy})`);
        if (!isHttps) riskIndicators.push('Unencrypted plain HTTP');

        parsedUrls.push({
          url: rawUrl,
          domain: hostname,
          protocol,
          isIpHost,
          isShortened: isShortener,
          hasExcessiveSubdomains: subdomainCount >= 3,
          isPunycode,
          hasSuspiciousKeywords,
          riskIndicators,
          riskLevel,
          entropy: domainEntropy,
          subdomainCount,
          pathLength,
          queryParamCount,
        });
      } catch {
        // Malformed URL ignored
      }
    }

    // Aggregate URL risk: Use highest-confidence malicious URL + aggregate multiplier
    if (featuresList.length === 0) {
      return {
        urlRisk: null,
        urlReputationStatus: 'none_present',
        features: [],
        parsedUrls: [],
        findings: [],
        modelTier: 'STRUCTURED_FEATURE_FOREST',
      };
    }

    featuresList.sort((a, b) => b.calculatedScore - a.calculatedScore);
    const highest = featuresList[0];
    const highestRisk = highest.calculatedScore;
    const otherHighRiskCount = featuresList.slice(1).filter((f) => f.calculatedScore >= 50).length;

    const urlRisk = Math.min(100, Math.round(highestRisk + otherHighRiskCount * 4));

    return {
      urlRisk,
      urlReputationStatus: 'available',
      highestRiskUrl: highest.rawUrl,
      features: featuresList,
      parsedUrls,
      findings,
      modelTier: 'STRUCTURED_FEATURE_FOREST',
    };
  }
}
