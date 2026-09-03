import type { ParsedUrl, SecurityFinding } from '../types/index.js';
import { ModelB_UrlRiskModel, type UrlModelOutput } from '../models/urlRiskModel.js';

export class UrlAnalyzer {
  /**
   * Extracts every URL from plain text, HTML anchor tags, attributes, and plain domains.
   */
  static extractUrls(text: string, html?: string): string[] {
    const raw = `${text || ''} ${html || ''}`;
    const cleanedUrls = new Set<string>();

    // 1. Match standard http/https URLs (including angle brackets, quotes, markdown)
    const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`[\]()]+)/gi;
    const matches = raw.match(urlRegex) || [];
    for (const u of matches) {
      const clean = u.replace(/[.,;!?:)"'>]+$/, '').replace(/&amp;/g, '&');
      if (clean.startsWith('http://') || clean.startsWith('https://')) {
        cleanedUrls.add(clean);
      }
    }

    // 2. Extract HTML href attributes: href=["'](https?:\/\/[^"']+)["']
    if (html) {
      const hrefRegex = /href\s*=\s*["'](https?:\/\/[^"'\s>]+)["']/gi;
      let m: RegExpExecArray | null;
      while ((m = hrefRegex.exec(html)) !== null) {
        if (m[1]) {
          const clean = m[1].replace(/[.,;!?:)"'>]+$/, '').replace(/&amp;/g, '&');
          cleanedUrls.add(clean);
        }
      }

      // Also check for anchor hrefs with relative or protocol-less domains
      const protoLessRegex = /href\s*=\s*["'](?:www\.)([^"'\s>]+\.[a-z]{2,}[^"'\s>]*)["']/gi;
      while ((m = protoLessRegex.exec(html)) !== null) {
        if (m[1]) {
          cleanedUrls.add(`https://www.${m[1].replace(/&amp;/g, '&')}`);
        }
      }
    }

    // 3. Match www. prefixes in text
    const wwwRegex = /(?:^|\s)(www\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+[^\s<>"'{}|\\^`[\]()]*)/gi;
    let wwwMatch: RegExpExecArray | null;
    while ((wwwMatch = wwwRegex.exec(raw)) !== null) {
      if (wwwMatch[1]) {
        const clean = wwwMatch[1].replace(/[.,;!?:)"'>]+$/, '');
        cleanedUrls.add(`https://${clean}`);
      }
    }

    return Array.from(cleanedUrls);
  }

  /**
   * Evaluates extracted URLs using Model B's Decision Forest structured feature ensemble.
   */
  static analyze(rawUrls: string[]): { urls: ParsedUrl[]; findings: SecurityFinding[]; urlRisk: number | null } {
    const res: UrlModelOutput = ModelB_UrlRiskModel.analyzeUrls(rawUrls);
    return {
      urls: res.parsedUrls,
      findings: res.findings,
      urlRisk: res.urlRisk,
    };
  }
}
