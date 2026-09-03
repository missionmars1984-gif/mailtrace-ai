import { TEST_SUITE } from '../fixtures/testSuite.js';
import { runAnalysisPipeline } from '../routes/api.js';

interface CaseAuditRecord {
  id: string;
  name: string;
  category: string;
  expectedClassification: string;
  expectedRiskRange: string;
  // 10 Requested Dimensions
  riskScore: number;
  classification: string;
  threatTypes: string[];
  confidence: number;
  indicators: string[];
  urlsDomainsIps: { urls: string[]; domains: string[]; ips: string[] };
  identityMismatch: { claimed: string; observed: string; consistency: number };
  attachmentDetection: { count: number; dangerousCount: number; filenames: string[] };
  campaignCorrelation: string[];
  quarantineResult: boolean;
  // QA Discrepancy Flags
  isFalsePositive: boolean;
  isFalseNegative: boolean;
  isScoreOutOfRange: boolean;
  isClassificationMismatch: boolean;
  passed: boolean;
  failureNotes: string[];
}

async function runSuite() {
  console.log('================================================================================');
  console.log(' MAILTRACE AI — SENIOR CYBERSECURITY QA/ML 30-CASE VALIDATION SUITE (A - DD)');
  console.log('================================================================================\n');

  const auditRecords: CaseAuditRecord[] = [];
  let totalPass = 0;
  let totalFp = 0;
  let totalFn = 0;
  let totalRangeFails = 0;

  for (const testCase of TEST_SUITE) {
    const caseRecord = await runAnalysisPipeline(testCase.rawEmail);

    const actualRisk = caseRecord.riskScore;
    const actualClass = caseRecord.classification;
    const confidence = caseRecord.confidence;
    const threatTypes = caseRecord.threatTypes || [];
    const isCleanExpected = testCase.expectedClassification === 'Clean' || testCase.expectedClassification === 'Low Risk';

    // False Positive: Legitimate email flagged as Suspicious, High Risk, or Critical (risk >= 41)
    const isFalsePositive = isCleanExpected && actualRisk >= 41;

    // False Negative: Threat email flagged as Clean or Low Risk (risk <= 40)
    const isFalseNegative = !isCleanExpected && actualRisk <= 40;

    const riskInRange = actualRisk >= testCase.expectedMinRisk && actualRisk <= testCase.expectedMaxRisk;
    const isClassificationMismatch = !isCleanExpected
      ? (actualClass === 'Clean' || actualClass === 'Low Risk')
      : (actualClass !== 'Clean' && actualClass !== 'Low Risk');

    const failureNotes: string[] = [];
    if (isFalsePositive) failureNotes.push(`False Positive: Expected clean, got ${actualRisk}/100 (${actualClass})`);
    if (isFalseNegative) failureNotes.push(`False Negative: Expected threat, got ${actualRisk}/100 (${actualClass})`);
    if (!riskInRange) failureNotes.push(`Risk ${actualRisk} out of expected range [${testCase.expectedMinRisk}–${testCase.expectedMaxRisk}]`);

    const passed = !isFalsePositive && !isFalseNegative && riskInRange;

    if (passed) totalPass++;
    if (isFalsePositive) totalFp++;
    if (isFalseNegative) totalFn++;
    if (!riskInRange) totalRangeFails++;

    // Extract Dimensions
    const urls = caseRecord.extractedIOCs.filter((ioc) => ioc.type === 'URL').map((i) => i.value);
    const domains = caseRecord.extractedIOCs.filter((ioc) => ioc.type === 'DOMAIN').map((i) => i.value);
    const ips = caseRecord.extractedIOCs.filter((ioc) => ioc.type === 'IP').map((i) => i.value);

    const attachments = caseRecord.parsedEmail?.attachments || [];
    const dangerousAttachments = attachments.filter((a: any) =>
      /\.(exe|scr|vbs|hta|js|ps1|bat|cmd|docm|xlsm)$/i.test(a.filename)
    );

    const record: CaseAuditRecord = {
      id: testCase.id,
      name: testCase.name,
      category: testCase.category,
      expectedClassification: testCase.expectedClassification,
      expectedRiskRange: `${testCase.expectedMinRisk}–${testCase.expectedMaxRisk}`,
      riskScore: actualRisk,
      classification: actualClass,
      threatTypes,
      confidence,
      indicators: caseRecord.indicators || [],
      urlsDomainsIps: { urls, domains, ips },
      identityMismatch: {
        claimed: caseRecord.claimedIdentity || 'Unknown',
        observed: caseRecord.observedIdentity || 'Unknown',
        consistency: caseRecord.identityConsistency ?? 100,
      },
      attachmentDetection: {
        count: attachments.length,
        dangerousCount: dangerousAttachments.length,
        filenames: attachments.map((a: any) => a.filename),
      },
      campaignCorrelation: caseRecord.campaignIndicators || [],
      quarantineResult: caseRecord.quarantineRecommendation ?? false,
      isFalsePositive,
      isFalseNegative,
      isScoreOutOfRange: !riskInRange,
      isClassificationMismatch,
      passed,
      failureNotes,
    };

    auditRecords.push(record);

    const badge = passed ? '✓ PASS' : '✗ FAIL';
    console.log(`[TEST ${testCase.id}] ${testCase.name}`);
    console.log(`  Expected: ${testCase.expectedClassification} (Target Range: ${testCase.expectedMinRisk}–${testCase.expectedMaxRisk}) | Status: ${badge}`);
    console.log(`  1. Risk Score:            ${actualRisk} / 100 (Expected: ${testCase.expectedMinRisk}–${testCase.expectedMaxRisk})`);
    console.log(`  2. Classification:        ${actualClass} (Expected: ${testCase.expectedClassification})`);
    console.log(`  3. Threat Types:          ${threatTypes.length > 0 ? threatTypes.join(', ') : 'None'}`);
    console.log(`  4. Confidence:            ${confidence}%`);
    console.log(`  5. Detected Indicators:   ${(record.indicators).slice(0, 3).join('; ') || 'None'}`);
    console.log(`  6. Network Entities:      URLs=${urls.length}, Domains=${domains.length}, IPs=${ips.length}`);
    console.log(`  7. Identity Mismatch:     Claimed: "${record.identityMismatch.claimed}" | Observed: "${record.identityMismatch.observed}" | Consistency: ${record.identityMismatch.consistency}/100`);
    console.log(`  8. Attachment Payload:    Total: ${record.attachmentDetection.count}, Dangerous: ${record.attachmentDetection.dangerousCount} [${record.attachmentDetection.filenames.join(', ') || 'None'}]`);
    console.log(`  9. Campaign Identifiers:  ${record.campaignCorrelation.slice(0, 3).join(', ') || 'None'}`);
    console.log(`  10. Quarantine Result:    ${record.quarantineResult ? 'QUARANTINE ENFORCED' : 'DELIVER (No Quarantine)'}`);
    if (failureNotes.length > 0) {
      console.log(`  ⚠️ DEFECTS IDENTIFIED:    ${failureNotes.join(' | ')}`);
    }
    console.log('--------------------------------------------------------------------------------');
  }

  // Structured QA Summary & Failure Matrix
  console.log('\n================================================================================');
  console.log('                      30-CASE QA VALIDATION FAILURE MATRIX');
  console.log('================================================================================');
  console.log(`Total Cases Evaluated:      ${TEST_SUITE.length}`);
  console.log(`Passed Assertions:          ${totalPass} / ${TEST_SUITE.length} (${Math.round((totalPass / TEST_SUITE.length) * 100)}%)`);
  console.log(`False Positives:            ${totalFp} (Target: 0)`);
  console.log(`False Negatives:            ${totalFn} (Target: 0)`);
  console.log(`Score Out-of-Range:         ${totalRangeFails} (Target: 0)`);

  const failures = auditRecords.filter((r) => !r.passed);
  if (failures.length > 0) {
    console.log('\n-------------------------- FAILED CASE BREAKDOWN --------------------------');
    for (const f of failures) {
      console.log(`Case ${f.id} [${f.name}]:`);
      console.log(`  Expected: ${f.expectedClassification} (${f.expectedRiskRange})`);
      console.log(`  Actual:   ${f.classification} (${f.riskScore}/100)`);
      console.log(`  Defects:  ${f.failureNotes.join(', ')}`);
    }
    console.log('---------------------------------------------------------------------------');
  } else {
    console.log('\n✓ ALL 30 CASES PASSED GROUND TRUTH EVALUATION — ZERO FALSE POSITIVES & ZERO FALSE NEGATIVES!');
  }
  console.log('================================================================================\n');

  if (failures.length > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runSuite().catch((err) => {
  console.error('Test runner encountered unhandled exception:', err);
  process.exit(1);
});
