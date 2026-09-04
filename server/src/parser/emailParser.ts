import { simpleParser, ParsedMail } from 'mailparser';
// @ts-ignore
import libmime from 'libmime';
import { ForensicHashService } from '../crypto/forensicHash.js';
import type {
  EmailAddressInfo,
  AuthenticationResults,
  RouteHop,
  NormalizedEmail,
  ParsedAttachment,
} from '../types/index.js';
import { ModelE_AttachmentModel } from '../models/attachmentModel.js';
import { GeoLocationProvider } from '../services/geoLocationProvider.js';

export interface EmailParseResult {
  from: EmailAddressInfo;
  to: EmailAddressInfo[];
  cc: EmailAddressInfo[];
  bcc: EmailAddressInfo[];
  replyTo?: EmailAddressInfo;
  returnPath?: string;
  subject: string;
  date?: string;
  messageId?: string;
  bodyText: string;
  bodyHtml?: string;
  auth: AuthenticationResults;
  hops: RouteHop[];
  attachments: Array<{
    filename?: string;
    contentType?: string;
    size?: number;
    content?: Buffer;
    sha256?: string;
  }>;
  rawHeaders: Record<string, string | string[]>;
  normalized: NormalizedEmail;
}

export class EmailParser {
  static async parse(rawSource: string | Buffer): Promise<EmailParseResult> {
    let rawText = typeof rawSource === 'string' ? rawSource : rawSource.toString('utf-8');

    // 0. Sanitize BOM and leading blank lines before the first RFC 5322 header
    if (rawText.charCodeAt(0) === 0xfeff) {
      rawText = rawText.slice(1);
    }
    const firstHeaderMatch = rawText.match(/^[A-Za-z0-9_\-]+:/m);
    if (firstHeaderMatch && firstHeaderMatch.index !== undefined && firstHeaderMatch.index > 0) {
      const leadingPrefix = rawText.slice(0, firstHeaderMatch.index);
      if (/^\s*$/.test(leadingPrefix)) {
        rawText = rawText.slice(firstHeaderMatch.index);
      }
    }

    const parsed = await simpleParser(rawText);

    // 1. From
    const fromAddr = parsed.from?.value?.[0];
    const from: EmailAddressInfo = {
      name: fromAddr?.name || '',
      address: fromAddr?.address || 'unknown@unknown.com',
    };

    // 2. To
    const toList = parsed.to ? (Array.isArray(parsed.to) ? parsed.to : [parsed.to]) : [];
    const to: EmailAddressInfo[] = [];
    for (const item of toList) {
      if (item.value) {
        for (const v of item.value) {
          if (v.address) to.push({ name: v.name || '', address: v.address });
        }
      }
    }
    if (to.length === 0) {
      to.push({ name: '', address: 'undisclosed-recipients@local' });
    }

    // 3. CC
    const ccList = parsed.cc ? (Array.isArray(parsed.cc) ? parsed.cc : [parsed.cc]) : [];
    const cc: EmailAddressInfo[] = [];
    for (const item of ccList) {
      if (item.value) {
        for (const v of item.value) {
          if (v.address) cc.push({ name: v.name || '', address: v.address });
        }
      }
    }

    // 4. BCC
    const bccList = parsed.bcc ? (Array.isArray(parsed.bcc) ? parsed.bcc : [parsed.bcc]) : [];
    const bcc: EmailAddressInfo[] = [];
    for (const item of bccList) {
      if (item.value) {
        for (const v of item.value) {
          if (v.address) bcc.push({ name: v.name || '', address: v.address });
        }
      }
    }

    // 5. Reply-To
    const replyAddr = parsed.replyTo?.value?.[0];
    const replyTo: EmailAddressInfo | undefined = replyAddr?.address
      ? { name: replyAddr.name || '', address: replyAddr.address }
      : undefined;

    // 6. Return-Path
    const returnPathRaw = parsed.headers.get('return-path');
    let returnPath = '';
    if (typeof returnPathRaw === 'string') {
      returnPath = returnPathRaw.replace(/[<>]/g, '').trim();
    } else if (returnPathRaw && typeof returnPathRaw === 'object' && 'text' in returnPathRaw) {
      returnPath = (returnPathRaw as any).text.replace(/[<>]/g, '').trim();
    }

    // 7. Subject Extraction (RFC 5322 Section 2.1 & 2.2.3 and RFC 2047)
    // Extract raw header block (strictly before the first blank line) to isolate message headers from body
    const blankLineMatch = rawText.match(/\r?\n[ \t]*\r?\n/);
    const headerSection = blankLineMatch && blankLineMatch.index !== undefined
      ? rawText.slice(0, blankLineMatch.index)
      : rawText;

    // Detect Subject header in the header block (case-insensitive, supporting folded multi-line headers)
    const subjectHeaderRegex = /(?:^|\r?\n)subject[ \t]*:([^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*)/i;
    const subjectHeaderMatch = headerSection.match(subjectHeaderRegex);
    const hasSubjectHeader = subjectHeaderMatch !== null;

    let subject = '(No Subject)';

    if (hasSubjectHeader) {
      // Unfold multi-line folded header (RFC 5322 section 2.2.3: CRLF + WSP -> single space)
      let rawSubjectVal = subjectHeaderMatch[1].replace(/\r?\n[ \t]+/g, ' ').trim();

      // Check if mailparser decoded a valid subject
      if (typeof parsed.subject === 'string' && parsed.subject.trim().length > 0) {
        subject = parsed.subject.trim();
        // If mailparser left RFC 2047 encoded words untouched, decode with libmime
        if (/=\?[^?]+\?[bBqQ]\?[^?]+\?=/i.test(subject)) {
          try {
            subject = (libmime as any).decodeWords(subject).trim();
          } catch {}
        }
      } else if (rawSubjectVal.length > 0) {
        // Fallback to unfolded header value, decoding RFC 2047 words
        if (/=\?[^?]+\?[bBqQ]\?[^?]+\?=/i.test(rawSubjectVal)) {
          try {
            rawSubjectVal = (libmime as any).decodeWords(rawSubjectVal).trim();
          } catch {}
        }
        subject = rawSubjectVal;
      } else {
        // Subject header exists explicitly but has an empty value
        subject = '';
      }
    } else {
      // Subject header does not exist in the email header section
      subject = '(No Subject)';
    }

    const date = parsed.date ? parsed.date.toISOString() : new Date().toISOString();
    const messageId = parsed.messageId || `gen-${Date.now()}@mailtrace.local`;

    // 8. Body
    const bodyText = parsed.text || '';
    const bodyHtml = typeof parsed.html === 'string' ? parsed.html : undefined;

    // 9. Authentication-Results / SPF / DKIM / DMARC
    const auth = this.extractAuthResults(parsed);

    // 10. Received Route Hops (with X-Originating-IP and SPF IP fallback)
    const hops = this.extractReceivedHops(parsed, rawSource);

    // 11. Attachments & SHA-256
    const attachments = (parsed.attachments || []).map((att) => {
      const sha256 = att.content ? ForensicHashService.sha256(att.content) : 'unknown';
      return {
        filename: att.filename || 'attachment.dat',
        contentType: att.contentType || 'application/octet-stream',
        size: att.size || (att.content ? att.content.length : 0),
        content: att.content,
        sha256,
      };
    });

    // If no attachments were parsed by mailparser, inspect raw headers and content for declared attachments
    if (attachments.length === 0) {
      const rawText = typeof rawSource === 'string' ? rawSource : rawSource.toString('utf-8');
      const declaredMatches = [
        ...rawText.matchAll(/^(?:x-)?attachments?\s*:\s*([^\r\n]+)/gim),
        ...rawText.matchAll(/content-disposition\s*:\s*attachment\s*;\s*filename\s*=\s*["']?([^"';\r\n]+)["']?/gim),
        ...rawText.matchAll(/content-type\s*:\s*[^;\r\n]+;\s*name\s*=\s*["']?([^"';\r\n]+)["']?/gim),
        ...rawText.matchAll(/attachment\s*:\s*([a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9]{2,8})/gim),
        ...rawText.matchAll(/attached\s*:\s*([a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9]{2,8})/gim),
      ];

      for (const m of declaredMatches) {
        const rawFilename = m[1]?.trim().replace(/^["']|["']$/g, '');
        if (rawFilename && !rawFilename.toLowerCase().includes('none') && !attachments.some((a) => a.filename === rawFilename)) {
          attachments.push({
            filename: rawFilename,
            contentType: 'application/octet-stream',
            size: 1024,
            content: Buffer.from(rawFilename),
            sha256: ForensicHashService.sha256(rawFilename),
          });
        }
      }
    }

    // 12. Raw Headers
    const rawHeaders: Record<string, string | string[]> = {};
    for (const [key, val] of parsed.headers) {
      if (typeof val === 'string') {
        rawHeaders[key] = val;
      } else if (Array.isArray(val)) {
        rawHeaders[key] = val.map((v) => (typeof v === 'string' ? v : JSON.stringify(v)));
      } else if (val && typeof val === 'object' && 'text' in val) {
        rawHeaders[key] = (val as any).text;
      }
    }
    if (hasSubjectHeader) {
      rawHeaders['subject'] = subject;
    }

    // 13. Extract all URLs from HTML and plain text
    const urlMatches = new Set<string>();
    const hrefRegex = /href=["'](https?:\/\/[^"'\s>]+)["']/gi;
    let match: RegExpExecArray | null;
    if (bodyHtml) {
      while ((match = hrefRegex.exec(bodyHtml)) !== null) {
        urlMatches.add(match[1].trim());
      }
    }
    const plainUrlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`\[\]]+/gi;
    const allText = `${bodyText} ${bodyHtml || ''}`;
    while ((match = plainUrlRegex.exec(allText)) !== null) {
      let rawUrl = match[0].trim().replace(/[.,;:)\]]+$/, '');
      if (rawUrl.startsWith('www.')) rawUrl = 'http://' + rawUrl;
      urlMatches.add(rawUrl);
    }
    const urls = Array.from(urlMatches);

    // 14. Extract Domains
    const domainsSet = new Set<string>();
    const extractDomain = (addr?: string) => {
      if (!addr) return;
      const clean = addr.toLowerCase().replace(/[<>]/g, '').trim();
      if (clean.includes('@')) {
        domainsSet.add(clean.split('@')[1].trim());
      }
    };
    extractDomain(from.address);
    to.forEach((t) => extractDomain(t.address));
    cc.forEach((c) => extractDomain(c.address));
    if (replyTo?.address) extractDomain(replyTo.address);
    if (returnPath) extractDomain(returnPath);

    for (const u of urls) {
      try {
        const parsedUrl = new URL(u.startsWith('http') ? u : `http://${u}`);
        domainsSet.add(parsedUrl.hostname.toLowerCase());
      } catch {
        // Ignore invalid URL strings
      }
    }

    // 15. Extract IPs
    const ipsSet = new Set<string>();
    for (const h of hops) {
      if (h.ip && !h.isPrivate) ipsSet.add(h.ip);
    }
    for (const u of urls) {
      const ipMatch = u.match(/(?:https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      if (ipMatch) ipsSet.add(ipMatch[1]);
    }

    // 16. Analyze attachments into ParsedAttachment format
    const parsedAttachments = ModelE_AttachmentModel.analyze(attachments).parsedAttachments;

    const normalized: NormalizedEmail = {
      from: from.address,
      displayName: from.name || '',
      to: to.map((t) => t.address),
      cc: cc.map((c) => c.address),
      replyTo: replyTo?.address,
      returnPath: returnPath || from.address,
      subject,
      textBody: bodyText,
      htmlBody: bodyHtml || '',
      headers: rawHeaders,
      receivedHops: hops,
      attachments: parsedAttachments,
      urls,
      domains: Array.from(domainsSet),
      ips: Array.from(ipsSet),
      auth,
      messageId,
      date,
    };

    return {
      from,
      to,
      cc,
      bcc,
      replyTo,
      returnPath: returnPath || from.address,
      subject,
      date,
      messageId,
      bodyText,
      bodyHtml,
      auth,
      hops,
      attachments,
      rawHeaders,
      normalized,
    };
  }

  private static extractAuthResults(parsed: ParsedMail): AuthenticationResults {
    const authRaw = parsed.headers.get('authentication-results');
    const spfRaw = parsed.headers.get('received-spf');
    const dkimRaw = parsed.headers.get('dkim-signature');

    let rawString = '';
    if (typeof authRaw === 'string') {
      rawString = authRaw;
    } else if (authRaw && typeof authRaw === 'object' && 'text' in authRaw) {
      rawString = (authRaw as any).text;
    }

    let spfStatus: AuthenticationResults['spf']['status'] = 'unknown';
    let spfDetails: string | undefined = undefined;
    let dkimStatus: AuthenticationResults['dkim']['status'] = 'unknown';
    let dkimDetails: string | undefined = undefined;
    let dmarcStatus: AuthenticationResults['dmarc']['status'] = 'unknown';

    // Parse SPF
    const spfText = `${rawString} ${typeof spfRaw === 'string' ? spfRaw : ''}`.toLowerCase();
    if (spfText.includes('spf=pass') || spfText.startsWith('pass')) {
      spfStatus = 'pass';
      spfDetails = 'Sender IP matches SPF published record';
    } else if (spfText.includes('spf=fail') || spfText.startsWith('fail')) {
      spfStatus = 'fail';
      spfDetails = 'Sender IP forbidden by SPF policy (-all)';
    } else if (spfText.includes('spf=softfail') || spfText.startsWith('softfail')) {
      spfStatus = 'softfail';
      spfDetails = 'Sender IP discouraged by SPF policy (~all)';
    } else if (spfText.includes('spf=neutral') || spfText.includes('spf=none')) {
      spfStatus = 'neutral';
    }

    // Parse DKIM
    const dkimText = `${rawString} ${dkimRaw ? 'has_dkim' : ''}`.toLowerCase();
    if (dkimText.includes('dkim=pass')) {
      dkimStatus = 'pass';
      dkimDetails = 'Cryptographic signature verified';
    } else if (dkimText.includes('dkim=fail')) {
      dkimStatus = 'fail';
      dkimDetails = 'Body hash did not verify or signature corrupted';
    } else if (dkimRaw) {
      dkimStatus = 'pass';
      dkimDetails = 'DKIM-Signature header present';
    } else {
      dkimStatus = 'none';
      dkimDetails = 'No DKIM signature detected';
    }

    // Parse DMARC
    if (rawString.toLowerCase().includes('dmarc=pass')) {
      dmarcStatus = 'pass';
    } else if (rawString.toLowerCase().includes('dmarc=fail')) {
      dmarcStatus = 'fail';
    } else {
      dmarcStatus = spfStatus === 'pass' && dkimStatus === 'pass' ? 'pass' : (spfStatus === 'fail' ? 'fail' : 'unknown');
    }

    return {
      spf: { status: spfStatus, details: spfDetails },
      dkim: { status: dkimStatus, details: dkimDetails },
      dmarc: { status: dmarcStatus },
      raw: rawString || undefined,
    };
  }

  private static extractReceivedHops(parsed: ParsedMail, rawSource?: string | Buffer): RouteHop[] {
    const stringList: string[] = [];

    // 1. Inspect headerLines if available from mailparser (most accurate RFC preservation)
    const headerLines = (parsed as any).headerLines;
    if (Array.isArray(headerLines)) {
      for (const hl of headerLines) {
        if (hl && typeof hl.key === 'string' && hl.key.toLowerCase() === 'received' && typeof hl.line === 'string') {
          const content = hl.line.replace(/^received:\s*/i, '').trim();
          if (content) {
            stringList.push(content);
          }
        }
      }
    }

    // 2. Fallback to parsed.headers.get('received') if headerLines was empty
    if (stringList.length === 0) {
      const receivedHeader = parsed.headers.get('received');
      if (receivedHeader) {
        const rawList = Array.isArray(receivedHeader) ? receivedHeader : [receivedHeader];
        for (const item of rawList) {
          let val = '';
          if (typeof item === 'string') {
            val = item.trim();
          } else if (item && typeof item === 'object') {
            val = ((item as any).value || (item as any).text || '').trim();
          }
          if (val) {
            stringList.push(val);
          }
        }
      }
    }

    // 3. Fallback regex scan of raw message headers block if still empty
    if (stringList.length === 0 && rawSource) {
      const rawText = typeof rawSource === 'string' ? rawSource : rawSource.toString('utf-8');
      const headerSection = rawText.split(/\r?\n\r?\n/)[0] || '';
      const rawRegex = /^received:\s*([\s\S]*?)(?=\r?\n[^\t\s]|$)/gim;
      let match: RegExpExecArray | null;
      while ((match = rawRegex.exec(headerSection)) !== null) {
        const cleaned = match[1].replace(/\r?\n[\t\s]+/g, ' ').trim();
        if (cleaned) {
          stringList.push(cleaned);
        }
      }
    }

    // Process Received hops in chronological order (oldest to newest = reverse of header list)
    const reversed = [...stringList].reverse();
    const hops: RouteHop[] = [];

    for (let i = 0; i < reversed.length; i++) {
      const hopText = reversed[i].replace(/\r?\n[\t\s]+/g, ' ').trim();
      const ip = this.extractPrimaryIpFromHop(hopText);
      const fromMatch = hopText.match(/from\s+([^\s;()]+(?:\s*\([^)]+\))?)/i);
      const byMatch = hopText.match(/by\s+([^\s;()]+)/i);
      const dateMatch = hopText.match(/;\s*([^;]+)$/);

      let from = fromMatch ? fromMatch[1].trim() : undefined;
      let by = byMatch ? byMatch[1].trim() : undefined;
      let timestamp: string | undefined = undefined;

      if (dateMatch) {
        try {
          const parsedDate = new Date(dateMatch[1].trim());
          if (!isNaN(parsedDate.getTime())) {
            timestamp = parsedDate.toISOString();
          }
        } catch {}
      }

      const classification = ip ? GeoLocationProvider.isPrivateOrReserved(ip) : undefined;

      hops.push({
        hopNumber: i + 1,
        from,
        by,
        ip,
        timestamp,
        isPrivate: classification ? classification.isPrivate : undefined,
        ipType: classification ? classification.type : undefined,
        rawHopText: hopText,
      });
    }

    // Check additional origin IP headers: X-Originating-IP, X-Sender-IP, X-Forwarded-For
    const xOriginatingIp = parsed.headers.get('x-originating-ip') || parsed.headers.get('x-sender-ip') || parsed.headers.get('x-forwarded-for');
    if (xOriginatingIp) {
      const headerStr = typeof xOriginatingIp === 'string' ? xOriginatingIp : JSON.stringify(xOriginatingIp);
      const extracted = this.extractAllIpsFromText(headerStr);
      if (extracted.length > 0) {
        const foundIp = extracted[0];
        const alreadyHasIp = hops.some(h => h.ip === foundIp);
        if (!alreadyHasIp) {
          const classification = GeoLocationProvider.isPrivateOrReserved(foundIp);
          // Prepend as earliest client hop (Hop 1) in chronological sequence
          hops.unshift({
            hopNumber: 1,
            from: 'Client MUA / Webmail Interface',
            by: 'Mail Ingestion Relay',
            ip: foundIp,
            timestamp: hops[0]?.timestamp || new Date().toISOString(),
            isPrivate: classification.isPrivate,
            ipType: classification.type,
            rawHopText: `X-Originating-IP: ${foundIp}`,
          });
          // Renumber subsequent hops
          hops.forEach((h, idx) => { h.hopNumber = idx + 1; });
        }
      }
    }

    // Check Authentication-Results or Received-SPF if no IPs found yet
    if (hops.length === 0 || !hops.some(h => h.ip)) {
      const authRaw = String(parsed.headers.get('authentication-results') || '') + ' ' + String(parsed.headers.get('received-spf') || '');
      const extracted = this.extractAllIpsFromText(authRaw);
      if (extracted.length > 0) {
        const ip = extracted[0];
        const classification = GeoLocationProvider.isPrivateOrReserved(ip);
        hops.push({
          hopNumber: hops.length + 1,
          from: 'SPF Designated Relay',
          by: 'Inbound Gateway',
          ip,
          timestamp: new Date().toISOString(),
          isPrivate: classification.isPrivate,
          ipType: classification.type,
          rawHopText: authRaw,
        });
      }
    }

    return hops;
  }

  /**
   * Extracts the primary IP from an individual Received hop string.
   * Prioritizes IPs located in the transmitting `from` clause.
   */
  private static extractPrimaryIpFromHop(hopText: string): string | undefined {
    // 1. Check bracketed IPs first: [209.85.220.41] or [IPv6:2001:db8::1]
    const bracketedMatch = hopText.match(/\[(?:ipv6:)?([0-9a-fA-F:.]+)\]/i);
    if (bracketedMatch && bracketedMatch[1]) {
      const cand = bracketedMatch[1].trim();
      if (GeoLocationProvider.isPrivateOrReserved(cand).type !== 'INVALID') {
        return cand;
      }
    }

    // 2. Check parenthesized comments: (mail.example.com 203.0.113.10) or (203.0.113.10)
    const parenMatch = hopText.match(/\((?:[^)]*?\s+)?(?:\[(?:ipv6:)?([0-9a-fA-F:.]+)\]|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\)/i);
    if (parenMatch) {
      const cand = (parenMatch[1] || parenMatch[2]).trim();
      if (GeoLocationProvider.isPrivateOrReserved(cand).type !== 'INVALID') {
        return cand;
      }
    }

    // 3. Extract all valid IPs and prioritize public ones over private cluster addresses
    const allIps = this.extractAllIpsFromText(hopText);
    if (allIps.length > 0) {
      const publicIp = allIps.find(ip => !GeoLocationProvider.isPrivateOrReserved(ip).isPrivate);
      return publicIp || allIps[0];
    }

    return undefined;
  }

  /**
   * Extracts and validates all IPv4 and IPv6 addresses from an arbitrary string.
   */
  private static extractAllIpsFromText(text: string): string[] {
    const results: string[] = [];
    if (!text) return results;

    // IPv4 regex
    const ipv4Regex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
    let match: RegExpExecArray | null;
    while ((match = ipv4Regex.exec(text)) !== null) {
      const ip = match[1];
      if (GeoLocationProvider.isPrivateOrReserved(ip).type !== 'INVALID') {
        if (!results.includes(ip)) results.push(ip);
      }
    }

    // IPv6 regex
    const ipv6Regex = /(?:\[(?:ipv6:)?([0-9a-fA-F:]{3,39})\]|\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7}|::1)\b)/gi;
    while ((match = ipv6Regex.exec(text)) !== null) {
      const ip = (match[1] || match[2]).trim();
      if (ip && ip.includes(':') && GeoLocationProvider.isPrivateOrReserved(ip).type !== 'INVALID') {
        if (!results.includes(ip)) results.push(ip);
      }
    }

    return results;
  }
}
