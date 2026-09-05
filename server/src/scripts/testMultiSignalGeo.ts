import assert from 'node:assert';
import { GeoLocationProvider } from '../services/geoLocationProvider.js';
import { NetworkClassifier } from '../services/networkClassifier.js';
import { LocationProfiler } from '../services/locationProfiler.js';
import { LocationEvidenceFusion, GEO_ATTRIBUTION_WEIGHTS } from '../services/locationEvidenceFusion.js';
import { TrackingService } from '../services/trackingService.js';
import { DatabaseService } from '../db/database.js';
import { runAnalysisPipeline } from '../routes/api.js';

console.log('================================================================');
console.log('  MULTI-SIGNAL EMAIL GEOLOCATION & ATTRIBUTION REGRESSION SUITE  ');
console.log('================================================================\n');

let passedTests = 0;
let totalTests = 0;

function test(name: string, fn: () => void) {
  totalTests++;
  try {
    fn();
    console.log(`[PASS] #${totalTests.toString().padStart(2, '0')}: ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`[FAIL] #${totalTests.toString().padStart(2, '0')}: ${name}`);
    console.error(err);
  }
}

async function testAsync(name: string, fn: () => Promise<void>) {
  totalTests++;
  try {
    await fn();
    console.log(`[PASS] #${totalTests.toString().padStart(2, '0')}: ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`[FAIL] #${totalTests.toString().padStart(2, '0')}: ${name}`);
    console.error(err);
  }
}

// -----------------------------------------------------------------------------
// Scenario 1: RFC 1918 Private IP Classification & Non-routable handling
// -----------------------------------------------------------------------------
test('RFC 1918 Private IP: Strictly classified as PRIVATE, no public geo', () => {
  const c10 = GeoLocationProvider.isPrivateOrReserved('10.20.30.40');
  const c192 = GeoLocationProvider.isPrivateOrReserved('192.168.1.50');
  const c172 = GeoLocationProvider.isPrivateOrReserved('172.16.5.10');
  assert.strictEqual(c10.type, 'PRIVATE');
  assert.strictEqual(c192.type, 'PRIVATE');
  assert.strictEqual(c172.type, 'PRIVATE');
});

// -----------------------------------------------------------------------------
// Scenario 2: Loopback, CGNAT, and Link-Local Classification
// -----------------------------------------------------------------------------
test('Loopback, CGNAT & Link-Local: Correct RFC standard classification', () => {
  const loopback = GeoLocationProvider.isPrivateOrReserved('127.0.0.1');
  const cgnat = GeoLocationProvider.isPrivateOrReserved('100.64.10.1');
  const linkLocal = GeoLocationProvider.isPrivateOrReserved('169.254.1.1');
  assert.strictEqual(loopback.type, 'LOOPBACK');
  assert.strictEqual(cgnat.type, 'PRIVATE');
  assert.strictEqual(linkLocal.type, 'LINK_LOCAL');
});

// -----------------------------------------------------------------------------
// Scenario 3: Cloud Infrastructure Classification (AWS)
// -----------------------------------------------------------------------------
test('Cloud Classifier (AWS): Identified as CLOUD with server radius and low user confidence ceiling', () => {
  const res = NetworkClassifier.classify({
    asn: 'AS16509',
    org: 'Amazon.com, Inc.',
    isp: 'AWS',
  });
  assert.strictEqual(res.networkType, 'CLOUD');
  assert.strictEqual(res.isCloudOrHosting, true);
  assert.strictEqual(res.maxUserLocationConfidence, 15);
  assert.strictEqual(res.accuracyEstimateKm, 1500);
});

// -----------------------------------------------------------------------------
// Scenario 4: Cloud Infrastructure Classification (GCP & Azure)
// -----------------------------------------------------------------------------
test('Cloud Classifier (GCP & Azure): Categorized as Public Datacenter hosting', () => {
  const gcp = NetworkClassifier.classify({ asn: 'AS396982', org: 'Google Cloud' });
  const azure = NetworkClassifier.classify({ asn: 'AS8075', org: 'Microsoft Corporation', isp: 'Microsoft Azure' });
  assert.strictEqual(gcp.networkType, 'CLOUD');
  assert.strictEqual(azure.networkType, 'CLOUD');
});

// -----------------------------------------------------------------------------
// Scenario 5: Apple Mail Privacy Protection (MPP) / iCloud Private Relay
// -----------------------------------------------------------------------------
test('Intermediary Classifier (Apple MPP): Labeled as PRIVACY_RELAY with 5000km radius', () => {
  const mpp = NetworkClassifier.classify({
    asn: 'AS54113',
    org: 'Apple Private Relay',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
  });
  assert.strictEqual(mpp.networkType, 'PRIVACY_RELAY');
  assert.strictEqual(mpp.isPrivacyRelayOrProxy, true);
  assert.strictEqual(mpp.detectedIntermediary, 'Apple MPP Proxy');
  assert.strictEqual(mpp.accuracyEstimateKm, 5000);
});

// -----------------------------------------------------------------------------
// Scenario 6: Google Image Proxy
// -----------------------------------------------------------------------------
test('Intermediary Classifier (Google Image Proxy): Labeled as PROXY', () => {
  const gproxy = NetworkClassifier.classify({
    asn: 'AS15169',
    org: 'Google LLC',
    userAgent: 'GoogleImageProxy',
  });
  assert.strictEqual(gproxy.networkType, 'PROXY');
  assert.strictEqual(gproxy.isPrivacyRelayOrProxy, true);
  assert.strictEqual(gproxy.detectedIntermediary, 'Google Image Proxy');
});

// -----------------------------------------------------------------------------
// Scenario 7: Enterprise Email Security Gateway (Proofpoint / Mimecast)
// -----------------------------------------------------------------------------
test('Intermediary Classifier (Email Security Sandbox): Labeled as SECURITY_SCANNER', () => {
  const proofpoint = NetworkClassifier.classify({ asn: 'AS33047', org: 'Proofpoint, Inc.' });
  const mimecast = NetworkClassifier.classify({ asn: 'AS32780', org: 'Mimecast Services Limited' });
  assert.strictEqual(proofpoint.networkType, 'SECURITY_SCANNER');
  assert.strictEqual(mimecast.networkType, 'SECURITY_SCANNER');
  assert.strictEqual(proofpoint.isSecurityScanner, true);
});

// -----------------------------------------------------------------------------
// Scenario 8: Commercial VPN & Tor Exit Nodes
// -----------------------------------------------------------------------------
test('Anonymizer Classifier (VPN & Tor): Labeled as VPN / TOR with proxy flags', () => {
  const tor = NetworkClassifier.classify({ org: 'Tor Exit Relay Node' });
  const vpn = NetworkClassifier.classify({ org: 'NordVPN / Tefincom S.A.' });
  assert.strictEqual(tor.networkType, 'TOR');
  assert.strictEqual(tor.isVpnOrTor, true);
  assert.strictEqual(vpn.networkType, 'VPN');
  assert.strictEqual(vpn.isVpnOrTor, true);
});

// -----------------------------------------------------------------------------
// Scenario 9: Consumer Residential Broadband & Mobile Telecom
// -----------------------------------------------------------------------------
test('Consumer Classifier: Residential broadband & mobile carrier subnets', () => {
  const residential = NetworkClassifier.classify({ org: 'Comcast Cable Communications', isp: 'Comcast Broadband' });
  const jioMobile = NetworkClassifier.classify({ org: 'Reliance Jio Infocomm', isp: 'Jio Mobile 5G' });
  assert.strictEqual(residential.networkType, 'RESIDENTIAL');
  assert.strictEqual(residential.isResidentialOrMobile, true);
  assert.strictEqual(residential.accuracyEstimateKm, 40);
  assert.strictEqual(jioMobile.networkType, 'MOBILE');
  assert.strictEqual(jioMobile.isResidentialOrMobile, true);
});

// -----------------------------------------------------------------------------
// Scenario 10: Haversine Distance Calculation
// -----------------------------------------------------------------------------
test('Haversine Distance: Accurate great-circle distance between London & New York', () => {
  const dist = LocationProfiler.haversineDistanceKm(51.5074, -0.1278, 40.7128, -74.0060);
  assert.ok(dist >= 5500 && dist <= 5650, `Expected ~5570 km, got ${dist}`);
});

// -----------------------------------------------------------------------------
// Scenario 11: Impossible Travel Detection (> 900 km/h)
// -----------------------------------------------------------------------------
test('Impossible Travel: Detects impossible speed across distant locations in short interval', () => {
  const loc1 = {
    latitude: 51.5074,
    longitude: -0.1278,
    timestamp: '2026-09-05T12:00:00Z',
    label: 'London Relay',
  };
  const loc2 = {
    latitude: 1.3521,
    longitude: 103.8198,
    timestamp: '2026-09-05T12:20:00Z',
    label: 'Singapore Interaction',
  };
  const res = LocationProfiler.checkImpossibleTravel(loc1, loc2);
  assert.strictEqual(res.isImpossibleTravel, true);
  assert.ok(res.speedKmPerHour > 900, `Speed should exceed 900 km/h: ${res.speedKmPerHour}`);
  assert.ok(res.reason?.includes('impossible travel detected'));
});

// -----------------------------------------------------------------------------
// Scenario 12: Realistic Travel (< 900 km/h or < 250 km metro area)
// -----------------------------------------------------------------------------
test('Realistic Travel: Metro area jitter (< 250 km) is NOT flagged as impossible travel', () => {
  const loc1 = {
    latitude: 40.7128,
    longitude: -74.0060,
    timestamp: '2026-09-05T12:00:00Z',
  };
  const loc2 = {
    latitude: 40.7306,
    longitude: -73.9352,
    timestamp: '2026-09-05T12:02:00Z',
  };
  const res = LocationProfiler.checkImpossibleTravel(loc1, loc2);
  assert.strictEqual(res.isImpossibleTravel, false);
});

// -----------------------------------------------------------------------------
// Scenario 13: Timezone Discrepancy Detection
// -----------------------------------------------------------------------------
test('Timezone Discrepancy: Flags mismatch between client Date header and relay longitude', () => {
  const dateHeader = 'Sat, 05 Sep 2026 14:00:00 +0900';
  const res = LocationProfiler.checkTimezoneDiscrepancy(dateHeader, undefined, -0.12);
  assert.strictEqual(res.hasTimezoneMismatch, true);
  assert.ok(res.timezoneDiscrepancyHours >= 8);
  assert.ok(res.anomalyDescription?.includes('Timezone discrepancy'));
});

// -----------------------------------------------------------------------------
// Scenario 14: Consistent Timezone (No Anomaly)
// -----------------------------------------------------------------------------
test('Consistent Timezone: No anomaly when Date timezone matches solar longitude', () => {
  const dateHeader = 'Sat, 05 Sep 2026 14:00:00 +0530';
  const res = LocationProfiler.checkTimezoneDiscrepancy(dateHeader, undefined, 77.2);
  assert.strictEqual(res.hasTimezoneMismatch, false);
});

// -----------------------------------------------------------------------------
// Scenario 15: Multi-Signal Fusion on Cloud Mail Relay (AWS)
// -----------------------------------------------------------------------------
test('Fusion on Cloud Relay: Decouples server location from user estimate, returns Inconclusive user location', () => {
  const attribution = LocationEvidenceFusion.synthesize({
    originRelay: {
      hopNumber: 1,
      ip: '54.240.0.1',
      country: 'United States',
      city: 'Seattle',
      latitude: 47.6062,
      longitude: -122.3321,
      asn: 'AS16509',
      org: 'Amazon.com, Inc.',
      isp: 'Amazon Technologies Inc.',
      isPrivate: false,
      isPublic: true,
      geoAvailable: true,
    },
    hops: [],
    trackingEvents: [],
    senderAddress: 'notifications@aws-client.com',
    dateHeader: 'Sat, 05 Sep 2026 10:00:00 -0700',
  });

  assert.strictEqual(attribution.sendingInfrastructure?.country, 'United States');
  assert.strictEqual(attribution.sendingInfrastructure?.confidence, 85);
  assert.strictEqual(attribution.sendingInfrastructure?.networkType, 'CLOUD');

  assert.ok(attribution.estimatedUserLocation?.country?.includes('Inconclusive'));
  assert.ok((attribution.estimatedUserLocation?.confidence ?? 100) <= 25);
  assert.ok(attribution.estimatedUserLocation?.limitations.some((l) => l.includes('Public cloud hosting provider')));
});

// -----------------------------------------------------------------------------
// Scenario 16: Multi-Signal Fusion on Consumer Residential Connection
// -----------------------------------------------------------------------------
test('Fusion on Residential Connection: Returns HIGH confidence user estimate with local radius', () => {
  const attribution = LocationEvidenceFusion.synthesize({
    originRelay: {
      hopNumber: 1,
      ip: '49.36.10.20',
      country: 'India',
      city: 'Mumbai',
      latitude: 19.0760,
      longitude: 72.8777,
      asn: 'AS55836',
      org: 'Reliance Jio Infocomm Limited',
      isp: 'Jio Broadband',
      isPrivate: false,
      isPublic: true,
      geoAvailable: true,
    },
    hops: [],
    trackingEvents: [],
    senderAddress: 'arjun@example.in',
    dateHeader: 'Sat, 05 Sep 2026 14:00:00 +0530',
  });

  assert.strictEqual(attribution.estimatedUserLocation?.country, 'India');
  assert.strictEqual(attribution.estimatedUserLocation?.city, 'Mumbai');
  assert.ok((attribution.estimatedUserLocation?.confidence ?? 0) >= 75);
  assert.strictEqual(attribution.estimatedUserLocation?.accuracyRadiusKm, 40);
  assert.ok(attribution.estimatedUserLocation?.confidenceLevel === 'HIGH' || attribution.estimatedUserLocation?.confidenceLevel === 'VERY_HIGH');
});

// -----------------------------------------------------------------------------
// Scenario 17: Multi-Signal Fusion on VPN Egress
// -----------------------------------------------------------------------------
test('Fusion on VPN Egress: Masks user location, returns VPN/Proxy Egress with low confidence', () => {
  const attribution = LocationEvidenceFusion.synthesize({
    originRelay: {
      hopNumber: 1,
      ip: '185.220.101.5',
      country: 'Germany',
      city: 'Frankfurt',
      latitude: 50.1109,
      longitude: 8.6821,
      asn: 'AS208272',
      org: 'Mullvad VPN / Datacenter Egress',
      isp: 'Mullvad',
      isPrivate: false,
      isPublic: true,
      geoAvailable: true,
    },
    hops: [],
    trackingEvents: [],
    senderAddress: 'anonymous@protonmail.com',
    dateHeader: 'Sat, 05 Sep 2026 10:00:00 +0200',
  });

  assert.ok(attribution.estimatedUserLocation?.country?.includes('VPN/Proxy Egress'));
  assert.ok((attribution.estimatedUserLocation?.confidence ?? 100) <= 25);
  assert.ok(attribution.estimatedUserLocation?.limitations.some((l) => l.includes('anonymizing proxy/VPN tunnel')));
});

// -----------------------------------------------------------------------------
// Scenario 18: Tracking Event Integration (Apple MPP vs Genuine Client)
// -----------------------------------------------------------------------------
test('Tracking Telemetry: Apple MPP open does NOT pollute user location, marked proxy', () => {
  const trackingEvents = [
    {
      id: 'trk_01',
      caseId: 'case_test',
      eventType: 'open' as const,
      ip: '17.241.75.1',
      userAgent: 'Mozilla/5.0 AppleWebKit/605.1.15 (KHTML, like Gecko)',
      timestamp: '2026-09-05T12:00:00Z',
      isPrefetchOrProxy: true,
      proxyType: 'APPLE_MPP' as const,
      geo: {
        country: 'United States',
        city: 'Cupertino',
        latitude: 37.3229,
        longitude: -122.0322,
        accuracyRadiusKm: 5000,
        confidence: 10,
        confidenceLevel: 'VERY_LOW' as const,
        networkType: 'PRIVACY_RELAY' as const,
        evidence: ['Apple MPP proxy'],
        limitations: ['Prefetch cache'],
        sourceSignals: ['Interaction'],
        hypothesisType: 'INTERACTION' as const,
      },
    },
  ];

  const attribution = LocationEvidenceFusion.synthesize({
    originRelay: {
      hopNumber: 1,
      ip: '49.36.10.20',
      country: 'India',
      latitude: 19.0760,
      longitude: 72.8777,
      org: 'Reliance Jio',
      isPrivate: false,
      isPublic: true,
      geoAvailable: true,
    },
    hops: [],
    trackingEvents,
    senderAddress: 'arjun@example.in',
    dateHeader: 'Sat, 05 Sep 2026 14:00:00 +0530',
  });

  assert.strictEqual(attribution.interactionLocation?.networkType, 'PRIVACY_RELAY');
  assert.strictEqual(attribution.interactionLocation?.confidence, 10);
  assert.strictEqual(attribution.estimatedUserLocation?.country, 'India');
});

// -----------------------------------------------------------------------------
// Scenario 19: Full End-to-End Pipeline Execution with Multi-Signal Attribution
// -----------------------------------------------------------------------------
await testAsync('Full Pipeline: Parses RFC email, synthesizes attribution, attaches to CaseRecord', async () => {
  const rawEmail = `From: Priya Sharma <priya@singapore-tech.sg>
To: SOC Team <security@mailtrace.ai>
Subject: Project Alpha Deployment Update
Date: Sat, 05 Sep 2026 14:05:00 +0800
Message-ID: <test-geo-sg-001@example.sg>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Received: from mail.singapore-tech.sg (relay.singapore-tech.sg [103.24.180.1])
        by mx.mailtrace.ai with ESMTP;
        Sat, 05 Sep 2026 06:05:00 +0000

Hi Team,

The Singapore deployment is progressing as expected.

Regards,
Priya`;

  const caseRecord = await runAnalysisPipeline(rawEmail);

  assert.ok(caseRecord.id, 'Case ID should be defined');
  assert.ok(caseRecord.geoAttribution, 'geoAttribution should be attached to CaseRecord');
  assert.ok(caseRecord.geoAttribution.sendingInfrastructure, 'sendingInfrastructure should be defined');
  assert.ok(caseRecord.geoAttribution.estimatedUserLocation, 'estimatedUserLocation should be defined');
  assert.ok(Array.isArray(caseRecord.geoAttribution.limitations), 'limitations should be an array');
  assert.ok(Array.isArray(caseRecord.geoAttribution.competingHypotheses), 'competingHypotheses should be an array');
  assert.strictEqual(caseRecord.geoAttribution.trackingEventsCount, 0);
  console.log(`       Pipeline output Case #${caseRecord.caseNumber}:`);
  console.log(`       Sending Infra:  ${caseRecord.geoAttribution.sendingInfrastructure?.country || 'N/A'} (Confidence: ${caseRecord.geoAttribution.sendingInfrastructure?.confidence}%)`);
  console.log(`       Estimated User: ${caseRecord.geoAttribution.estimatedUserLocation?.country || 'N/A'} (Confidence: ${caseRecord.geoAttribution.estimatedUserLocation?.confidence}%)`);
});

// -----------------------------------------------------------------------------
// Scenario 20: Tracking Event Lifecycle & Attribution Update
// -----------------------------------------------------------------------------
await testAsync('Tracking Lifecycle: Records genuine interaction event and updates attribution', async () => {
  const testCaseId = `case_test_track_${Date.now()}`;
  const fakeReq = {
    headers: {
      'x-forwarded-for': '122.161.40.10',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36',
    },
    socket: { remoteAddress: '122.161.40.10' },
  } as any;

  const event = await TrackingService.recordEvent({
    caseId: testCaseId,
    eventType: 'open',
    req: fakeReq,
  });

  assert.strictEqual(event.caseId, testCaseId);
  assert.strictEqual(event.eventType, 'open');
  assert.strictEqual(event.isPrefetchOrProxy, false);
  assert.strictEqual(event.proxyType, 'GENUINE_CLIENT');

  const retrieved = DatabaseService.getTrackingEventsForCase(testCaseId);
  assert.strictEqual(retrieved.length, 1);
  assert.strictEqual(retrieved[0].id, event.id);
});

// -----------------------------------------------------------------------------
// Scenario 21: Competing Hypotheses on Divergent Signals
// -----------------------------------------------------------------------------
test('Competing Hypotheses: Generates multiple hypotheses when relay is in US but timezone is +0900 (Asia)', () => {
  const attribution = LocationEvidenceFusion.synthesize({
    originRelay: {
      hopNumber: 1,
      ip: '3.80.0.1',
      country: 'United States',
      city: 'Ashburn',
      latitude: 39.0438,
      longitude: -77.4874,
      asn: 'AS16509',
      org: 'Amazon.com',
      isPrivate: false,
      isPublic: true,
      geoAvailable: true,
    },
    hops: [],
    senderAddress: 'sales@tokyo-import.jp',
    dateHeader: 'Sat, 05 Sep 2026 21:00:00 +0900',
  });

  assert.ok((attribution.competingHypotheses?.length ?? 0) >= 2, `Expected >= 2 competing hypotheses, got ${attribution.competingHypotheses?.length}`);
  assert.ok(attribution.anomalies.some((a) => a.includes('Timezone discrepancy')));
  console.log(`       Competing Hypotheses: ${attribution.competingHypotheses.map((h) => h.country).join(' vs ')}`);
});

// -----------------------------------------------------------------------------
// Scenario 22: Zero Evidence / All-Private Fallback
// -----------------------------------------------------------------------------
test('Zero Evidence Fallback: All-private hops return Unknown with 0% confidence without throwing', () => {
  const attribution = LocationEvidenceFusion.synthesize({
    hops: [
      { hopNumber: 1, ip: '10.0.0.1', isPrivate: true },
      { hopNumber: 2, ip: '192.168.1.1', isPrivate: true },
    ],
    trackingEvents: [],
  });

  assert.strictEqual(attribution.overallConfidence, 0);
  assert.strictEqual(attribution.overallConfidenceLevel, 'VERY_LOW');
  assert.strictEqual(attribution.estimatedUserLocation?.country, null);
  assert.ok((attribution.limitations?.length ?? 0) > 0);
});

console.log('\n================================================================');
console.log(`RESULTS: ${passedTests} / ${totalTests} TESTS PASSED (${Math.round((passedTests / totalTests) * 100)}%)`);
console.log('================================================================');

if (passedTests === totalTests) {
  process.exit(0);
} else {
  process.exit(1);
}
