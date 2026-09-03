import { TEST_SUITE } from '../fixtures/testSuite.js';
import { runAnalysisPipeline } from '../routes/api.js';

interface TestResult {
  id: string;
  name: string;
  category: string;
  expectedClassification: string;
  actualClassification: string;
  expectedRiskRange: string;
  actualRiskScore: number;
  confidence: number;
  isFalsePositive: boolean;
  isFalseNegative: boolean;
  passed: boolean;
  componentScores: any;
  indicators: string[];
}

async function runSuite() {
  console.log('================================================================================');
  console.log('       MAILTRACE AI — RIGOROUS 17-SCENARIO BENCHMARK TEST SUITE (A - Q)');
  console.log('================================================================================\n');

  const results: TestResult[] = [];
  let totalPass = 0;
  let totalFp = 0;
  let totalFn = 0;

  for (const testCase of TEST_SUITE) {
    const caseRecord = await runAnalysisPipeline(testCase.rawEmail);

    const actualRisk = caseRecord.riskScore;
    const actualClass = caseRecord.classification;
    const confidence = caseRecord.confidence;
    const isCleanExpected = testCase.expectedClassification === 'Clean' || testCase.expectedClassification === 'Low Risk';

    // False Positive: Legitimate email flagged as Suspicious, High Risk, or Critical (risk >= 41)
    const isFalsePositive = isCleanExpected && actualRisk >= 41;

    // False Negative: Threat email flagged as Clean or Low Risk (risk <= 40)
    const isFalseNegative = !isCleanExpected && actualRisk <= 40;

    const riskInRange = actualRisk >= testCase.expectedMinRisk && actualRisk <= testCase.expectedMaxRisk;
    const classMatches = actualClass === testCase.expectedClassification || (!isFalsePositive && !isFalseNegative && riskInRange);
    const passed = !isFalsePositive && !isFalseNegative && riskInRange;

    if (passed) totalPass++;
    if (isFalsePositive) totalFp++;
    if (isFalseNegative) totalFn++;

    results.push({
      id: testCase.id,
      name: testCase.name,
      category: testCase.category,
      expectedClassification: testCase.expectedClassification,
      actualClassification: actualClass,
      expectedRiskRange: `${testCase.expectedMinRisk}–${testCase.expectedMaxRisk}`,
      actualRiskScore: actualRisk,
      confidence,
      isFalsePositive,
      isFalseNegative,
      passed,
      componentScores: caseRecord.componentScores,
      indicators: caseRecord.indicators || [],
    });

    const statusBadge = passed ? '✓ PASS' : '✗ FAIL';
    console.log(`[TEST ${testCase.id}] ${testCase.name}`);
    console.log(`  Expected: ${testCase.expectedClassification} (Range: ${testCase.expectedMinRisk}–${testCase.expectedMaxRisk}) | Result: ${statusBadge}`);
    console.log(`  Actual Risk Score: ${actualRisk}/100 | Confidence: ${confidence}% | Classification: ${actualClass}`);
    console.log(
      `  Components: NLP=${caseRecord.componentScores?.nlpRisk} URL=${caseRecord.componentScores?.urlRisk} Identity=${caseRecord.componentScores?.identityRisk} BEC=${caseRecord.componentScores?.becRisk} Auth=${caseRecord.componentScores?.headerRisk ?? caseRecord.componentScores?.authenticationRisk} Att=${caseRecord.componentScores?.attachmentRisk ?? 'null'}`
    );
    console.log(`  Key Indicators: ${(caseRecord.indicators || []).slice(0, 3).join('; ') || 'None'}`);
    if (isFalsePositive) console.log(`  ⚠️ ALERT: False Positive Detected!`);
    if (isFalseNegative) console.log(`  🚨 CRITICAL: False Negative Detected!`);
    console.log('--------------------------------------------------------------------------------');
  }

  console.log('\n================================================================================');
  console.log('                              FINAL BENCHMARK SUMMARY');
  console.log('================================================================================');
  console.log(`Total Test Scenarios:       ${TEST_SUITE.length}`);
  console.log(`Passed Assertions:          ${totalPass} / ${TEST_SUITE.length} (${Math.round((totalPass / TEST_SUITE.length) * 100)}%)`);
  console.log(`False Positives:            ${totalFp} (Target: 0)`);
  console.log(`False Negatives:            ${totalFn} (Target: 0)`);

  const obviousPhishA = results.find((r) => r.id === 'A');
  if (obviousPhishA) {
    console.log(`\nVerification of The 18/100 Bug:`);
    console.log(`  Test Case A (Obvious Phishing): Scored ${obviousPhishA.actualRiskScore}/100 (${obviousPhishA.actualClassification})`);
    if (obviousPhishA.actualRiskScore >= 85) {
      console.log(`  ✓ VERIFIED: The 18/100 defect is completely resolved. Hard escalation floor triggered properly.`);
    } else {
      console.log(`  ✗ FAILED: Score remains deflated (${obviousPhishA.actualRiskScore}/100)!`);
    }
  }

  console.log('================================================================================\n');

  if (totalFp > 0 || totalFn > 0 || totalPass < TEST_SUITE.length) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runSuite().catch((err) => {
  console.error('Test runner encountered unhandled exception:', err);
  process.exit(1);
});
