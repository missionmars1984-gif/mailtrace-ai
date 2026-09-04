/**
 * Calibrated L2-regularized Logistic Regression and One-vs-Rest Threat Classifier.
 * Supports temperature scaling calibration and JSON serialization.
 */

export interface LogisticRegressionModelData {
  weights: number[];
  bias: number;
  temperature: number;
  threshold: number;
}

export interface MultiClassModelData {
  classes: string[];
  models: Record<string, LogisticRegressionModelData>;
}

export class LogisticRegression {
  public weights: Float64Array;
  public bias = 0;
  public temperature = 1.0;
  public threshold = 0.50;

  constructor(numFeatures = 0) {
    this.weights = new Float64Array(numFeatures);
  }

  private sigmoid(z: number): number {
    if (z >= 40) return 1.0;
    if (z <= -40) return 0.0;
    return 1.0 / (1.0 + Math.exp(-z));
  }

  public fit(
    X: Float64Array[],
    y: (0 | 1)[],
    options: {
      epochs?: number;
      learningRate?: number;
      l2Lambda?: number;
      batchSize?: number;
      posWeight?: number;
    } = {}
  ): this {
    const epochs = options.epochs ?? 250;
    let lr = options.learningRate ?? 0.15;
    const lambda = options.l2Lambda ?? 0.005;
    const batchSize = Math.min(options.batchSize ?? 16, X.length);
    const posWeight = options.posWeight ?? 1.0;

    const numFeatures = X[0].length;
    this.weights = new Float64Array(numFeatures);
    this.bias = 0;

    const vW = new Float64Array(numFeatures);
    let vB = 0;
    const momentum = 0.85;

    const m = X.length;
    const indices = Array.from({ length: m }, (_, i) => i);

    for (let epoch = 0; epoch < epochs; epoch++) {
      for (let i = m - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [indices[i], indices[j]] = [indices[j], indices[i]];
      }

      for (let start = 0; start < m; start += batchSize) {
        const batchIndices = indices.slice(start, start + batchSize);
        const gradW = new Float64Array(numFeatures);
        let gradB = 0;

        for (const idx of batchIndices) {
          const x = X[idx];
          const target = y[idx];

          let z = this.bias;
          for (let f = 0; f < numFeatures; f++) {
            z += this.weights[f] * x[f];
          }
          const p = this.sigmoid(z);
          const weight = target === 1 ? posWeight : 1.0;
          const error = (p - target) * weight;

          for (let f = 0; f < numFeatures; f++) {
            gradW[f] += error * x[f];
          }
          gradB += error;
        }

        const bLen = batchIndices.length;
        for (let f = 0; f < numFeatures; f++) {
          const g = gradW[f] / bLen + lambda * this.weights[f];
          vW[f] = momentum * vW[f] + (1 - momentum) * g;
          this.weights[f] -= lr * vW[f];
        }

        const gb = gradB / bLen;
        vB = momentum * vB + (1 - momentum) * gb;
        this.bias -= lr * vB;
      }

      lr *= 0.992;
    }

    return this;
  }

  public logit(x: Float64Array): number {
    let z = this.bias;
    for (let i = 0; i < this.weights.length; i++) {
      z += this.weights[i] * x[i];
    }
    return z;
  }

  public predictProbability(x: Float64Array): number {
    const z = this.logit(x);
    return this.sigmoid(z / this.temperature);
  }

  public predict(x: Float64Array): 0 | 1 {
    return this.predictProbability(x) >= this.threshold ? 1 : 0;
  }

  public calibrateTemperature(X_val: Float64Array[], y_val: (0 | 1)[]): void {
    let bestT = 1.0;
    let minNll = Infinity;

    for (let t = 0.5; t <= 3.0; t += 0.05) {
      let nll = 0;
      for (let i = 0; i < X_val.length; i++) {
        const z = this.logit(X_val[i]);
        const p = Math.max(1e-7, Math.min(1 - 1e-7, this.sigmoid(z / t)));
        const y = y_val[i];
        nll -= y === 1 ? Math.log(p) : Math.log(1 - p);
      }
      if (nll < minNll) {
        minNll = nll;
        bestT = t;
      }
    }

    this.temperature = Number(bestT.toFixed(2));
  }

  public tuneThreshold(X_val: Float64Array[], y_val: (0 | 1)[]): void {
    let bestThreshold = 0.50;
    let bestF1 = -1;

    for (let th = 0.20; th <= 0.80; th += 0.02) {
      let tp = 0, fp = 0, fn = 0, tn = 0;
      for (let i = 0; i < X_val.length; i++) {
        const p = this.predictProbability(X_val[i]);
        const pred = p >= th ? 1 : 0;
        const actual = y_val[i];
        if (pred === 1 && actual === 1) tp++;
        else if (pred === 1 && actual === 0) fp++;
        else if (pred === 0 && actual === 1) fn++;
        else tn++;
      }

      const prec = tp + fp > 0 ? tp / (tp + fp) : 0;
      const rec = tp + fn > 0 ? tp / (tp + fn) : 0;
      const f1 = prec + rec > 0 ? (2 * prec * rec) / (prec + rec) : 0;
      const score = f1 - (fn * 0.05);

      if (score > bestF1) {
        bestF1 = score;
        bestThreshold = th;
      }
    }

    this.threshold = Number(bestThreshold.toFixed(2));
  }

  public toJSON(): LogisticRegressionModelData {
    return {
      weights: Array.from(this.weights),
      bias: this.bias,
      temperature: this.temperature,
      threshold: this.threshold,
    };
  }

  public static fromJSON(data: LogisticRegressionModelData): LogisticRegression {
    const lr = new LogisticRegression(data.weights.length);
    lr.weights = new Float64Array(data.weights);
    lr.bias = data.bias;
    lr.temperature = data.temperature;
    lr.threshold = data.threshold;
    return lr;
  }
}

export class OneVsRestThreatClassifier {
  public classes: string[] = [];
  public models: Map<string, LogisticRegression> = new Map();

  constructor(classes: string[] = []) {
    this.classes = classes;
  }

  public fit(X: Float64Array[], labels: string[]): this {
    this.classes = Array.from(new Set(labels)).sort();
    this.models.clear();

    for (const cls of this.classes) {
      const yBinary = labels.map(l => (l === cls ? 1 : 0) as 0 | 1);
      const posCount = yBinary.filter(v => v === 1).length;
      const negCount = yBinary.length - posCount;
      const posWeight = negCount > 0 && posCount > 0 ? Math.min(4.0, negCount / posCount) : 1.0;

      const lr = new LogisticRegression(X[0].length);
      lr.fit(X, yBinary, { epochs: 200, l2Lambda: 0.008, posWeight });
      this.models.set(cls, lr);
    }

    return this;
  }

  public predictProbabilities(x: Float64Array): Record<string, number> {
    const probs: Record<string, number> = {};
    for (const [cls, model] of this.models.entries()) {
      probs[cls] = Number(model.predictProbability(x).toFixed(3));
    }
    return probs;
  }

  public predict(x: Float64Array): { topClass: string; score: number } {
    let topClass = 'generic_phishing';
    let topScore = -1;

    for (const [cls, model] of this.models.entries()) {
      const score = model.predictProbability(x);
      if (score > topScore) {
        topScore = score;
        topClass = cls;
      }
    }

    return { topClass, score: Number(topScore.toFixed(3)) };
  }

  public toJSON(): MultiClassModelData {
    const modelsObj: Record<string, LogisticRegressionModelData> = {};
    for (const [cls, model] of this.models.entries()) {
      modelsObj[cls] = model.toJSON();
    }
    return {
      classes: this.classes,
      models: modelsObj,
    };
  }

  public static fromJSON(data: MultiClassModelData): OneVsRestThreatClassifier {
    const ovr = new OneVsRestThreatClassifier(data.classes);
    for (const [cls, modelData] of Object.entries(data.models)) {
      ovr.models.set(cls, LogisticRegression.fromJSON(modelData));
    }
    return ovr;
  }
}
