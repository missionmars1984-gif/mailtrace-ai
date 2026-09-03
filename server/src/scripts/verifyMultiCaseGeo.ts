import { runAnalysisPipeline } from '../routes/api.js';
import { DatabaseService } from '../db/database.js';
import { GeoLocationProvider } from '../services/geoLocationProvider.js';

interface CaseVerificationResult {
  caseName: string;
  passed: boolean;
  details: Record<string, any>;
  error?: string;
}

async function verifyMultipleCases() {
  console.log('================================================================================');
  console.log('   MAILTRACE AI — MULTI-CASE GEOLOCATION INTEGRITY & DYNAMIC UPDATE TEST');
  console.log('================================================================================\n');

  const results: CaseVerificationResult[] = [];

  // CASE 1: Multi-Hop Email (Private MUA -> German Relay -> Inbound MX)
  try {
    console.log('[CASE 1] Multi-Hop: Private MUA (10.0.1.50) -> German Relay (185.220.101.5) -> Inbound MX (209.85.220.41)');
    const rawEmail1 = [
      'Received: from mx.targetcorp.com (mx.targetcorp.com [209.85.220.41]) by mail.inbound.net id mx01; Thu, 03 Sep 2026 14:00:00 -0000',
      'Received: from relay-germany.node.net (relay-germany.node.net [185.220.101.5]) by mx.targetcorp.com id rel02; Thu, 03 Sep 2026 13:59:00 -0000',
      'Received: from internal-client.lan (internal-client.lan [10.0.1.50]) by relay-germany.node.net id client03; Thu, 03 Sep 2026 13:58:00 -0000',
      'From: "Alert Service" <alert@node.net>',
      'To: security@targetcorp.com',
      'Subject: Critical Node Telemetry Update',
      '',
      'Node status report attached.'
    ].join('\r\n');

    const c1 = await runAnalysisPipeline(rawEmail1);
    const hop1 = c1.hops[0];
    const hop2 = c1.hops[1];
    const hop3 = c1.hops[2];

    const c1Passed =
      c1.hops.length === 3 &&
      hop1?.ip === '10.0.1.50' &&
      hop1?.isPrivate === true &&
      hop2?.ip === '185.220.101.5' &&
      hop2?.isPrivate === false &&
      hop2?.isPublicOriginRelay === true &&
      Boolean(hop2?.geo?.country) &&
      c1.observedOriginRelay?.ip === '185.220.101.5' &&
      c1.identityAnalysis.observed.sendingIp === '185.220.101.5';

    results.push({
      caseName: 'CASE 1: Multi-Hop (Private MUA + German Public Origin Relay)',
      passed: c1Passed,
      details: {
        totalHops: c1.hops.length,
        hop1: `${hop1?.ip} (Private: ${hop1?.isPrivate})`,
        hop2: `${hop2?.ip} (Country: ${hop2?.geo?.country}, isPublicOriginRelay: ${hop2?.isPublicOriginRelay})`,
        hop3: `${hop3?.ip} (Inbound MX)`,
        observedOriginRelay: `${c1.observedOriginRelay?.ip} (${c1.observedOriginRelay?.geo?.country})`,
        sendingIp: c1.identityAnalysis.observed.sendingIp,
      }
    });
    console.log(`  -> ${c1Passed ? 'PASSED' : 'FAILED'}\n`);
  } catch (err: any) {
    results.push({ caseName: 'CASE 1', passed: false, details: {}, error: String(err) });
  }

  // CASE 2: Single-Hop Public Email (Google)
  try {
    console.log('[CASE 2] Public Origin: Google Infrastructure (209.85.220.41)');
    const rawEmail2 = [
      'Received: from mail-relay.google.com (mail-relay.google.com [209.85.220.41]) by mx.targetcorp.com with ESMTP id g01; Thu, 03 Sep 2026 10:00:00 -0000',
      'From: "Corporate IT" <support@google.com>',
      'To: user@targetcorp.com',
      'Subject: Scheduled Maintenance Window',
      '',
      'Routine maintenance tonight.'
    ].join('\r\n');

    const c2 = await runAnalysisPipeline(rawEmail2);
    const origin2 = c2.observedOriginRelay;

    const c2Passed =
      c2.hops.length === 1 &&
      origin2?.ip === '209.85.220.41' &&
      origin2?.geo?.country === 'United States' &&
      typeof origin2?.geo?.lat === 'number' &&
      typeof origin2?.geo?.lon === 'number' &&
      origin2?.isPrivate === false;

    results.push({
      caseName: 'CASE 2: Single-Hop Public Origin (Google US)',
      passed: c2Passed,
      details: {
        ip: origin2?.ip,
        country: origin2?.geo?.country,
        city: origin2?.geo?.city,
        lat: origin2?.geo?.lat,
        lon: origin2?.geo?.lon,
      }
    });
    console.log(`  -> ${c2Passed ? 'PASSED' : 'FAILED'}\n`);
  } catch (err: any) {
    results.push({ caseName: 'CASE 2', passed: false, details: {}, error: String(err) });
  }

  // CASE 3: European Public Origin (France)
  try {
    console.log('[CASE 3] European Origin: France (185.190.140.12)');
    const rawEmail3 = [
      'Received: from relay-france.cloud-share.biz ([185.190.140.12]) by mx.targetcorp.com with ESMTP id fr01; Thu, 03 Sep 2026 11:00:00 -0000',
      'From: "Billing Dept" <billing@secure-exchange.xyz>',
      'To: finance@targetcorp.com',
      'Subject: Invoice #44019 Attached',
      '',
      'Please find invoice attached.'
    ].join('\r\n');

    const c3 = await runAnalysisPipeline(rawEmail3);
    const origin3 = c3.observedOriginRelay;

    const c3Passed =
      origin3?.ip === '185.190.140.12' &&
      origin3?.geo?.country === 'France' &&
      typeof origin3?.geo?.lat === 'number' &&
      origin3?.isPrivate === false;

    results.push({
      caseName: 'CASE 3: European Public Origin (France)',
      passed: c3Passed,
      details: {
        ip: origin3?.ip,
        country: origin3?.geo?.country,
        city: origin3?.geo?.city,
        lat: origin3?.geo?.lat,
        lon: origin3?.geo?.lon,
      }
    });
    console.log(`  -> ${c3Passed ? 'PASSED' : 'FAILED'}\n`);
  } catch (err: any) {
    results.push({ caseName: 'CASE 3', passed: false, details: {}, error: String(err) });
  }

  // CASE 4: Purely Private RFC 1918
  try {
    console.log('[CASE 4] Purely Private RFC 1918 Internal Transmission');
    const rawEmail4 = [
      'Received: from server.lan (server.lan [10.0.0.1]) by gateway.lan id priv02; Thu, 03 Sep 2026 09:00:00 -0000',
      'Received: from client.lan (client.lan [192.168.1.100]) by server.lan id priv01; Thu, 03 Sep 2026 08:59:00 -0000',
      'From: "Admin" <admin@corp.internal>',
      'To: dev@corp.internal',
      'Subject: Internal Network Test',
      '',
      'Testing internal subnet routing.'
    ].join('\r\n');

    const c4 = await runAnalysisPipeline(rawEmail4);
    const allHopsPrivate = c4.hops.every((h) => h.isPrivate === true);
    const noCoordinatesInvented = c4.hops.every((h) => h.geo?.lat === undefined && h.geo?.lon === undefined);
    const hasPrivateMessage = c4.hops.every((h) => (h.geo?.statusMessage || '').includes('private/internal IP'));

    const c4Passed = c4.hops.length === 2 && allHopsPrivate && noCoordinatesInvented && hasPrivateMessage;

    results.push({
      caseName: 'CASE 4: Purely Private RFC 1918 (Zero Fake Coordinates)',
      passed: c4Passed,
      details: {
        totalHops: c4.hops.length,
        allHopsPrivate,
        noCoordinatesInvented,
      }
    });
    console.log(`  -> ${c4Passed ? 'PASSED' : 'FAILED'}\n`);
  } catch (err: any) {
    results.push({ caseName: 'CASE 4', passed: false, details: {}, error: String(err) });
  }

  // CASE 5: Email Without Transport Headers
  try {
    console.log('[CASE 5] Email Without Received Headers (MIME Body Only)');
    const rawEmail5 = [
      'From: "HR" <hr@company.com>',
      'To: employee@company.com',
      'Subject: Open Enrollment Notification',
      '',
      'Open enrollment begins next Monday.'
    ].join('\r\n');

    const c5 = await runAnalysisPipeline(rawEmail5);
    const c5Passed = c5.hops.length === 0 && c5.observedOriginRelay === undefined;

    results.push({
      caseName: 'CASE 5: Email Without Received Headers (Graceful Empty Route)',
      passed: c5Passed,
      details: { totalHops: c5.hops.length }
    });
    console.log(`  -> ${c5Passed ? 'PASSED' : 'FAILED'}\n`);
  } catch (err: any) {
    results.push({ caseName: 'CASE 5', passed: false, details: {}, error: String(err) });
  }

  // CASE 6: Test Case A IP (198.51.100.42)
  try {
    console.log('[CASE 6] Benchmark Suite Case A (198.51.100.42)');
    const rawEmail6 = [
      'Received: from mail-relay.hostile-net.org ([198.51.100.42]) by mx.targetcorp.com with ESMTP id m365_001; Thu, 03 Sep 2026 09:12:00 +0000',
      'From: "Microsoft 365 Security Team" <security-update@m365-verify-portal.top>',
      'To: target.user@targetcorp.com',
      'Subject: URGENT: Your Microsoft 365 Account Will Be Suspended Within 24 Hours',
      '',
      'Verify credentials immediately.'
    ].join('\r\n');

    const c6 = await runAnalysisPipeline(rawEmail6);
    const origin6 = c6.observedOriginRelay;

    const c6Passed =
      origin6?.ip === '198.51.100.42' &&
      Boolean(origin6?.geo?.country) &&
      typeof origin6?.geo?.lat === 'number' &&
      origin6?.isPrivate === false;

    results.push({
      caseName: 'CASE 6: Benchmark Suite Case A (198.51.100.42)',
      passed: c6Passed,
      details: {
        ip: origin6?.ip,
        country: origin6?.geo?.country,
        city: origin6?.geo?.city,
        lat: origin6?.geo?.lat,
        lon: origin6?.geo?.lon,
      }
    });
    console.log(`  -> ${c6Passed ? 'PASSED' : 'FAILED'}\n`);
  } catch (err: any) {
    results.push({ caseName: 'CASE 6', passed: false, details: {}, error: String(err) });
  }

  // CASE 7: Threat Map Database Filter Integrity
  try {
    console.log('[CASE 7] Threat Map Database Filter Integrity');
    const threatMapData = DatabaseService.getThreatMapData();

    const noPrivateInMap = threatMapData.nodes.every((n) => {
      const isPriv = GeoLocationProvider.isPrivateOrReserved(n.ip).isPrivate;
      return !isPriv;
    });

    const hasValidCoordinates = threatMapData.nodes.every((n) => {
      return typeof n.lat === 'number' && typeof n.lon === 'number' && !(n.lat === 0 && n.lon === 0);
    });

    const c7Passed = threatMapData.nodes.length > 0 && noPrivateInMap && hasValidCoordinates;

    results.push({
      caseName: 'CASE 7: Threat Map Database Filter Integrity',
      passed: c7Passed,
      details: {
        totalNodes: threatMapData.nodes.length,
        autonomousSystems: threatMapData.stats.autonomousSystems,
        geolocatedJurisdictions: threatMapData.stats.geolocatedJurisdictions,
        localLoopbackFiltered: threatMapData.stats.localLoopbackFiltered,
        noPrivateInMap,
        hasValidCoordinates,
      }
    });
    console.log(`  -> ${c7Passed ? 'PASSED' : 'FAILED'}\n`);
  } catch (err: any) {
    results.push({ caseName: 'CASE 7', passed: false, details: {}, error: String(err) });
  }

  // SUMMARY
  console.log('================================================================================');
  console.log(' MULTI-CASE GEOLOCATION VERIFICATION SUMMARY');
  console.log('================================================================================');

  let passedCount = 0;
  for (const r of results) {
    const status = r.passed ? 'PASS' : 'FAIL';
    if (r.passed) passedCount++;
    console.log(`${status} | ${r.caseName}`);
    if (!r.passed) {
      console.log('   Details:', JSON.stringify(r.details));
      if (r.error) console.log('   Error:', r.error);
    }
  }

  console.log(`\nResult: ${passedCount}/${results.length} cases passed (${Math.round((passedCount / results.length) * 100)}%)\n`);

  if (passedCount !== results.length) {
    process.exit(1);
  }
}

verifyMultipleCases();
