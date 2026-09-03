export class CalibrationEngine {
  /**
   * Applies Platt Scaling (logistic calibration) to map a raw heuristic score to a calibrated probability.
   * Parameterized sigmoid: P(threat) = 1 / (1 + exp(-(A * s + B)))
   */
  static plattScale(rawScore: number, A = 0.08, B = -4.0): number {
    // Normalizes raw 0-100 score to 0-1 probability
    const logit = A * rawScore + B;
    const prob = 1 / (1 + Math.exp(-logit));
    return Number(prob.toFixed(3));
  }

  /**
   * Inverse Platt scale to map calibrated probability back to 0-100 risk score
   */
  static probToScore(probability: number): number {
    return Math.min(100, Math.max(0, Math.round(probability * 100)));
  }

  /**
   * Calculates independent Diagnostic Confidence (60–98%) based on Cross-Model Agreement.
   * NOTE: riskScore != confidence!
   * - Strong cross-model agreement (all models agree on threat OR all agree on clean) -> High Confidence (88-98%)
   * - Conflicting signals (one model high, others zero) -> Lower Confidence (60-78%)
   */
  static calculateConfidence(models: {
    nlpRisk: number;
    urlRisk: number;
    identityRisk: number;
    headerRisk: number;
    attachmentRisk: number | null;
    becRisk: number;
    authPresent: boolean;
    hopCount: number;
  }): { confidence: number; agreementRatio: number } {
    const activeScores: number[] = [
      models.nlpRisk,
      models.urlRisk,
      models.identityRisk,
      models.headerRisk,
      models.becRisk,
    ];
    if (models.attachmentRisk !== null) {
      activeScores.push(models.attachmentRisk);
    }

    const highThreatCount = activeScores.filter((s) => s >= 65).length;
    const moderateCount = activeScores.filter((s) => s >= 35 && s < 65).length;
    const lowThreatCount = activeScores.filter((s) => s < 35).length;
    const totalModels = activeScores.length;

    let agreementRatio = 0;
    let confidence = 75;

    // Consensus 1: Unanimous or strong agreement on High Threat
    if (highThreatCount >= 3) {
      agreementRatio = highThreatCount / totalModels;
      confidence = Math.round(88 + agreementRatio * 10);
    }
    // Consensus 2: Unanimous or strong agreement on Clean / Low Threat
    else if (lowThreatCount >= totalModels - 1 && highThreatCount === 0) {
      agreementRatio = lowThreatCount / totalModels;
      confidence = Math.round(86 + agreementRatio * 10);
    }
    // Consensus 3: Two high threat signals with zero strong contradiction
    else if (highThreatCount === 2 && moderateCount >= 1) {
      agreementRatio = 0.75;
      confidence = 84;
    }
    // Conflicting Evidence: One model screams high threat, but all others are zero
    else if (highThreatCount === 1 && lowThreatCount >= 3) {
      agreementRatio = 0.35;
      confidence = 68; // Lower confidence due to conflicting evidence
    }
    // Ambiguous / Split
    else {
      agreementRatio = 0.50;
      confidence = 72;
    }

    // Boost confidence if technical telemetry is complete
    if (models.authPresent) confidence += 4;
    if (models.hopCount >= 2) confidence += 3;

    confidence = Math.min(98, Math.max(60, confidence));

    return { confidence, agreementRatio };
  }
}
