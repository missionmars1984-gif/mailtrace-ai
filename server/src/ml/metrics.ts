/**
 * Rigorous Cybersecurity Evaluation & Metric Calculators.
 */

export interface EvaluationMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  macroF1: number;
  brierScore: number;
  rocAuc: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  fpr: number;
  fnr: number;
  perClass: Record<string, { precision: number; recall: number; f1: number; count: number }>;
}

export class MetricsEvaluator {
  static evaluateBinary(
    yTrue: (0 | 1)[],
    yPred: (0 | 1)[],
    yProb: number[]
  ): EvaluationMetrics {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    let brierSum = 0;

    for (let i = 0; i < yTrue.length; i++) {
      const actual = yTrue[i];
      const pred = yPred[i];
      const prob = yProb[i];

      brierSum += Math.pow(prob - actual, 2);

      if (pred === 1 && actual === 1) tp++;
      else if (pred === 1 && actual === 0) fp++;
      else if (pred === 0 && actual === 0) tn++;
      else fn++;
    }

    const total = yTrue.length;
    const accuracy = total > 0 ? (tp + tn) / total : 0;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

    const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
    const fnr = fn + tp > 0 ? fn / (fn + tp) : 0;
    const brierScore = total > 0 ? brierSum / total : 0;

    const prec0 = tn + fn > 0 ? tn / (tn + fn) : 0;
    const rec0 = tn + fp > 0 ? tn / (tn + fp) : 0;
    const f1_0 = prec0 + rec0 > 0 ? (2 * prec0 * rec0) / (prec0 + rec0) : 0;

    const prec1 = precision;
    const rec1 = recall;
    const f1_1 = f1;

    const macroF1 = (f1_0 + f1_1) / 2;
    const rocAuc = this.computeRocAuc(yTrue, yProb);

    return {
      accuracy: Number(accuracy.toFixed(4)),
      precision: Number(precision.toFixed(4)),
      recall: Number(recall.toFixed(4)),
      f1: Number(f1.toFixed(4)),
      macroF1: Number(macroF1.toFixed(4)),
      brierScore: Number(brierScore.toFixed(4)),
      rocAuc: Number(rocAuc.toFixed(4)),
      tp,
      fp,
      tn,
      fn,
      fpr: Number(fpr.toFixed(4)),
      fnr: Number(fnr.toFixed(4)),
      perClass: {
        legitimate: { precision: Number(prec0.toFixed(4)), recall: Number(rec0.toFixed(4)), f1: Number(f1_0.toFixed(4)), count: tn + fp },
        phishing: { precision: Number(prec1.toFixed(4)), recall: Number(rec1.toFixed(4)), f1: Number(f1_1.toFixed(4)), count: tp + fn },
      },
    };
  }

  static computeRocAuc(yTrue: (0 | 1)[], yProb: number[]): number {
    const pairs = yProb.map((p, idx) => ({ prob: p, label: yTrue[idx] }));
    pairs.sort((a, b) => b.prob - a.prob);

    const numPos = yTrue.filter(y => y === 1).length;
    const numNeg = yTrue.length - numPos;
    if (numPos === 0 || numNeg === 0) return 1.0;

    let auc = 0;
    let tp = 0;
    let fp = 0;
    let prevFp = 0;
    let prevTp = 0;

    for (const pair of pairs) {
      if (pair.label === 1) {
        tp++;
      } else {
        fp++;
        auc += (fp - prevFp) * (tp + prevTp) / 2;
        prevFp = fp;
        prevTp = tp;
      }
    }

    auc += (numNeg - prevFp) * (numPos + prevTp) / 2;
    return auc / (numPos * numNeg);
  }
}
