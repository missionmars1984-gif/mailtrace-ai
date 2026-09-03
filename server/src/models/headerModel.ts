import type { AuthenticationResults, RouteHop, SecurityFinding } from '../types/index.js';

export interface HeaderModelInput {
  auth?: AuthenticationResults;
  rawHeaders?: Record<string, string | string[]>;
  hops?: RouteHop[];
  fromDomain?: string;
  returnPathDomain?: string;
  replyToDomain?: string;
}

export interface HeaderModelOutput {
  authenticationRisk: number; // 0–100
  headerRisk: number; // 0–100
  spfStatus: string;
  dkimStatus: string;
  dmarcStatus: string;
  routingAnomalies: string[];
  findings: SecurityFinding[];
  modelTier: 'AUTH_ANOMALY_ENGINE';
}

export class ModelF_HeaderAnomalyEngine {
  /**
   * Evaluates technical header records, cryptographic authentication policies, and transmission hops.
   * NOTE: Authentication is never the sole verdict; compromised legitimate accounts can pass SPF/DKIM/DMARC.
   */
  static analyze(input: HeaderModelInput): HeaderModelOutput {
    const { auth, hops = [], fromDomain = '', returnPathDomain = '', replyToDomain, rawHeaders } = input;
    const findings: SecurityFinding[] = [];
    const routingAnomalies: string[] = [];

    let authRisk = 0;
    let headerRisk = 0;

    const spfStatus = auth?.spf.status || 'unknown';
    const dkimStatus = auth?.dkim.status || 'unknown';
    const dmarcStatus = auth?.dmarc.status || 'unknown';

    // 1. DMARC Policy Evaluation
    if (dmarcStatus === 'fail') {
      authRisk += 50;
      findings.push({
        type: 'AUTH',
        severity: 'HIGH',
        title: 'DMARC Domain Alignment Failure',
        source: 'Header anomaly engine',
        observed: `DMARC status: ${dmarcStatus}`,
        impact: 'Originating message violates the published DMARC policy of the claimed sender domain.',
      });
    }

    // 2. SPF Policy Evaluation
    if (spfStatus === 'fail') {
      authRisk += 40;
      findings.push({
        type: 'AUTH',
        severity: 'HIGH',
        title: 'SPF Hardfail (Unauthorized Sending IP)',
        source: 'Header anomaly engine',
        observed: `SPF status: ${spfStatus}`,
        impact: 'Connecting IP is not designated as an authorized sender in the domain SPF record.',
      });
    } else if (spfStatus === 'softfail') {
      authRisk += 25;
      findings.push({
        type: 'AUTH',
        severity: 'MEDIUM',
        title: 'SPF Softfail Policy Warning',
        source: 'Header anomaly engine',
        observed: `SPF status: ${spfStatus}`,
        impact: 'Sending IP is weakly marked as unauthorized (~all) by the sending organization.',
      });
    }

    // 3. DKIM Cryptographic Signature Evaluation
    if (dkimStatus === 'fail') {
      authRisk += 40;
      findings.push({
        type: 'AUTH',
        severity: 'HIGH',
        title: 'DKIM Cryptographic Signature Invalidation',
        source: 'Header anomaly engine',
        observed: `DKIM status: ${dkimStatus}`,
        impact: 'Digital signature verification failed; message headers or body content were altered in transit.',
      });
    }

    // Missing authentication records in modern email
    if (spfStatus === 'unknown' && dkimStatus === 'unknown') {
      authRisk += 25;
      routingAnomalies.push('Complete absence of cryptographic authentication headers (SPF/DKIM/DMARC).');
    }

    // 4. Return-Path Mismatch
    if (returnPathDomain && fromDomain && returnPathDomain !== fromDomain) {
      headerRisk += 25;
      routingAnomalies.push(`Return-Path domain (@${returnPathDomain}) differs from From domain (@${fromDomain}).`);
    }

    // 5. Reply-To Mismatch
    if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
      headerRisk += 30;
      routingAnomalies.push(`Reply-To address (@${replyToDomain}) diverts away from From domain.`);
    }

    // 6. Suspicious Transit Hops (Tor exits, bulletproof proxies)
    for (const h of hops) {
      if (h.ip && (h.ip.startsWith('185.220.') || h.from?.toLowerCase().includes('tor-exit'))) {
        headerRisk += 50;
        routingAnomalies.push(`Tor anonymity exit node identified in Received transit line: ${h.ip}`);
        findings.push({
          type: 'INFRASTRUCTURE',
          severity: 'CRITICAL',
          title: 'Anonymized Tor Exit Node in Relay Path',
          source: 'Header anomaly engine',
          snippet: `Received IP: ${h.ip}`,
          observed: `Hop #${h.hopNumber} resolves to known Tor exit relay`,
          impact: 'Conceals true origin network infrastructure behind dynamic anonymity circuits.',
        });
      }
    }

    // 7. Message-ID Validation
    if (rawHeaders) {
      const msgId = rawHeaders['message-id'];
      if (!msgId || (typeof msgId === 'string' && (!msgId.includes('@') || msgId.length < 5))) {
        headerRisk += 15;
        routingAnomalies.push('Missing or non-standard RFC 5322 Message-ID header.');
      }
    }

    const authenticationRisk = Math.min(100, Math.max(0, authRisk));
    const finalHeaderRisk = Math.min(100, Math.max(0, Math.max(authRisk * 0.5, headerRisk)));

    return {
      authenticationRisk,
      headerRisk: finalHeaderRisk,
      spfStatus,
      dkimStatus,
      dmarcStatus,
      routingAnomalies,
      findings,
      modelTier: 'AUTH_ANOMALY_ENGINE',
    };
  }
}
