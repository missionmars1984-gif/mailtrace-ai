/**
 * Automated Training, Hyperparameter Tuning & Evaluation Pipeline for MailTrace AI.
 * Trains TF-IDF + Logistic Regression on server/data/dataset.csv,
 * evaluates on strictly unseen test data, and exports trainedNlpModel.json.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatasetLoader, DatasetSample } from './dataset.js';
import { Tokenizer } from './tokenizer.js';
import { TfIdfVectorizer, TfIdfModelData } from './tfidf.js';
import { LogisticRegression, OneVsRestThreatClassifier, LogisticRegressionModelData, MultiClassModelData } from './logisticRegression.js';
import { MetricsEvaluator, EvaluationMetrics } from './metrics.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface ExportedNlpModel {
  modelVersion: string;
  architecture: string;
  datasetVersion: string;
  trainedAt: string;
  datasetMetrics: {
    totalSamples: number;
    trainSamples: number;
    valSamples: number;
    testSamples: number;
    classes: Record<string, number>;
  };
  tfidf: TfIdfModelData;
  binaryClassifier: LogisticRegressionModelData;
  threatClassifier: MultiClassModelData;
  evaluation: {
    beforeBaseline: EvaluationMetrics;
    afterTrainedTest: EvaluationMetrics;
    afterTrainedTrain: EvaluationMetrics;
    afterTrainedVal: EvaluationMetrics;
  };
}

export async function runTrainingPipeline(): Promise<ExportedNlpModel> {
  console.log('================================================================================');
  console.log(' MAILTRACE AI — MACHINE LEARNING THREAT MODEL TRAINING & EVALUATION PIPELINE');
  console.log('================================================================================\n');

  const datasetPath = path.resolve(__dirname, '../../data/dataset.csv');
  if (!fs.existsSync(datasetPath)) {
    throw new Error(`Dataset not found at ${datasetPath}`);
  }

  // 1. Load Dataset
  const samples = DatasetLoader.loadCsv(datasetPath);
  console.log(`[DATASET] Loaded ${samples.length} valid samples from dataset.csv`);

  const legitCount = samples.filter(s => s.label === 0).length;
  const phishCount = samples.filter(s => s.label === 1).length;
  console.log(`[DISTRIBUTION] Legitimate: ${legitCount} | Malicious/Phishing: ${phishCount}`);

  const categoryCounts: Record<string, number> = {};
  samples.forEach(s => {
    categoryCounts[s.phishingType] = (categoryCounts[s.phishingType] || 0) + 1;
  });
  console.log('[CATEGORIES]', categoryCounts);

  // 2. Stratified Split (70% Train / 15% Val / 15% Test)
  const { train, val, test } = DatasetLoader.stratifiedSplit(samples, 42);
  console.log(`\n[SPLIT] Train: ${train.length} samples (70%) | Val: ${val.length} samples (15%) | Test: ${test.length} samples (15%)`);

  // 3. Leakage Verification
  const leakageTest = DatasetLoader.checkLeakage(train, test);
  const leakageVal = DatasetLoader.checkLeakage(train, val);
  console.log(`[LEAKAGE CHECK] Train <-> Test exact duplicates: ${leakageTest.leakedCount}, max token Jaccard: ${leakageTest.maxJaccard.toFixed(3)}`);
  console.log(`[LEAKAGE CHECK] Train <-> Val  exact duplicates: ${leakageVal.leakedCount}, max token Jaccard: ${leakageVal.maxJaccard.toFixed(3)}`);
  if (leakageTest.leakedCount > 0) {
    throw new Error('Data leakage detected: exact duplicate found between train and test!');
  }

  // 4. Baseline Evaluation (BEFORE) on Unseen Test Set
  // Baseline: standard heuristic / unweighted keyword matching without trained weights
  console.log('\n--------------------------------------------------------------------------------');
  console.log(' 1. BASELINE EVALUATION (BEFORE TRAINING) ON UNSEEN TEST SET');
  console.log('--------------------------------------------------------------------------------');
  const baselinePreds: (0 | 1)[] = [];
  const baselineProbs: number[] = [];
  const yTestTrue = test.map(s => s.label);

  const baselineMaliciousKeywords = /(verify|password|urgent|account|pin|wire|transfer|suspended|locked|credit card|gift card|ssn|contest|refund)/i;

  for (const s of test) {
    const hasKeyword = baselineMaliciousKeywords.test(s.text);
    // Baseline raw heuristic: 0.70 if keyword, 0.30 if clean
    const prob = hasKeyword ? 0.70 : 0.30;
    baselineProbs.push(prob);
    baselinePreds.push(prob >= 0.50 ? 1 : 0);
  }

  const beforeMetrics = MetricsEvaluator.evaluateBinary(yTestTrue, baselinePreds, baselineProbs);
  console.log(`[BEFORE] Accuracy:   ${(beforeMetrics.accuracy * 100).toFixed(1)}%`);
  console.log(`[BEFORE] Precision:  ${(beforeMetrics.precision * 100).toFixed(1)}%`);
  console.log(`[BEFORE] Recall:     ${(beforeMetrics.recall * 100).toFixed(1)}%`);
  console.log(`[BEFORE] F1 Score:   ${(beforeMetrics.f1 * 100).toFixed(1)}%`);
  console.log(`[BEFORE] Macro F1:   ${(beforeMetrics.macroF1 * 100).toFixed(1)}%`);
  console.log(`[BEFORE] Brier Score: ${beforeMetrics.brierScore.toFixed(4)}`);
  console.log(`[BEFORE] Confusion:  TP=${beforeMetrics.tp}, FP=${beforeMetrics.fp}, TN=${beforeMetrics.tn}, FN=${beforeMetrics.fn}`);
  console.log(`[BEFORE] FPR:        ${(beforeMetrics.fpr * 100).toFixed(1)}% | FNR: ${(beforeMetrics.fnr * 100).toFixed(1)}%`);

  // 5. Fit Feature Extractor (TF-IDF) on Train Set ONLY
  console.log('\n--------------------------------------------------------------------------------');
  console.log(' 2. TRAINING TF-IDF + CALIBRATED LOGISTIC REGRESSION (AFTER)');
  console.log('--------------------------------------------------------------------------------');
  const tokenizer = new Tokenizer({ ngramRange: [1, 2], removeStopwords: false });
  const vectorizer = new TfIdfVectorizer(tokenizer, 400, 1);

  const trainDocs = train.map(s => s.text);
  vectorizer.fit(trainDocs);
  console.log(`[FEATURE EXTRACTION] Vocabulary fitted on Train set: ${vectorizer.getFeatureCount()} features (unigrams & bigrams)`);

  const X_train = train.map(s => vectorizer.transform(s.text));
  const y_train = train.map(s => s.label);

  const X_val = val.map(s => vectorizer.transform(s.text));
  const y_val = val.map(s => s.label);

  const X_test = test.map(s => vectorizer.transform(s.text));
  const y_test = test.map(s => s.label);

  // Train Binary Logistic Regression with L2 Regularization
  const binaryModel = new LogisticRegression(vectorizer.getFeatureCount());
  binaryModel.fit(X_train, y_train, {
    epochs: 300,
    learningRate: 0.18,
    l2Lambda: 0.006,
    batchSize: 16,
    posWeight: phishCount > 0 ? legitCount / phishCount : 1.0,
  });

  // Calibrate temperature and threshold on Validation Set
  binaryModel.calibrateTemperature(X_val, y_val);
  binaryModel.tuneThreshold(X_val, y_val);
  console.log(`[CALIBRATION] Optimized Temperature T=${binaryModel.temperature} | Decision Threshold=${binaryModel.threshold}`);

  // Train Multi-class Threat Subtype Classifier (One-vs-Rest)
  const threatLabelsTrain = train.map(s => s.phishingType);
  const threatClassifier = new OneVsRestThreatClassifier();
  threatClassifier.fit(X_train, threatLabelsTrain);
  console.log(`[THREAT CLASSIFIER] Trained One-vs-Rest model across ${threatClassifier.classes.length} attack types:`, threatClassifier.classes);

  // 6. Evaluate Model on Train, Val, and Unseen Test Splits
  const evaluateSplit = (X_split: Float64Array[], y_split: (0 | 1)[], name: string): EvaluationMetrics => {
    const preds: (0 | 1)[] = [];
    const probs: number[] = [];
    for (const x of X_split) {
      const p = binaryModel.predictProbability(x);
      probs.push(p);
      preds.push(p >= binaryModel.threshold ? 1 : 0);
    }
    return MetricsEvaluator.evaluateBinary(y_split, preds, probs);
  };

  const afterTrainMetrics = evaluateSplit(X_train, y_train, 'Train');
  const afterValMetrics = evaluateSplit(X_val, y_val, 'Validation');
  const afterTestMetrics = evaluateSplit(X_test, y_test, 'Unseen Test');

  console.log('\n--------------------------------------------------------------------------------');
  console.log(' 3. EMPIRICAL EVALUATION RESULTS ON STRICTLY UNSEEN TEST SET');
  console.log('--------------------------------------------------------------------------------');
  console.log(`[AFTER TEST] Accuracy:    ${(afterTestMetrics.accuracy * 100).toFixed(1)}% (Delta: ${((afterTestMetrics.accuracy - beforeMetrics.accuracy) * 100).toFixed(1)}%)`);
  console.log(`[AFTER TEST] Precision:   ${(afterTestMetrics.precision * 100).toFixed(1)}% (Delta: ${((afterTestMetrics.precision - beforeMetrics.precision) * 100).toFixed(1)}%)`);
  console.log(`[AFTER TEST] Recall:      ${(afterTestMetrics.recall * 100).toFixed(1)}% (Delta: ${((afterTestMetrics.recall - beforeMetrics.recall) * 100).toFixed(1)}%)`);
  console.log(`[AFTER TEST] F1 Score:    ${(afterTestMetrics.f1 * 100).toFixed(1)}% (Delta: ${((afterTestMetrics.f1 - beforeMetrics.f1) * 100).toFixed(1)}%)`);
  console.log(`[AFTER TEST] Macro F1:    ${(afterTestMetrics.macroF1 * 100).toFixed(1)}% (Delta: ${((afterTestMetrics.macroF1 - beforeMetrics.macroF1) * 100).toFixed(1)}%)`);
  console.log(`[AFTER TEST] ROC-AUC:     ${afterTestMetrics.rocAuc.toFixed(4)}`);
  console.log(`[AFTER TEST] Brier Score: ${afterTestMetrics.brierScore.toFixed(4)} (Calibration Error drop: ${(beforeMetrics.brierScore - afterTestMetrics.brierScore).toFixed(4)})`);
  console.log(`[AFTER TEST] Confusion:   TP=${afterTestMetrics.tp}, FP=${afterTestMetrics.fp}, TN=${afterTestMetrics.tn}, FN=${afterTestMetrics.fn}`);
  console.log(`[AFTER TEST] FPR:         ${(afterTestMetrics.fpr * 100).toFixed(1)}% | FNR: ${(afterTestMetrics.fnr * 100).toFixed(1)}%`);

  console.log('\n[GENERALIZATION AUDIT across splits]');
  console.log(`  Train Split (n=${train.length}):  Acc=${(afterTrainMetrics.accuracy * 100).toFixed(1)}%, F1=${(afterTrainMetrics.f1 * 100).toFixed(1)}%, Brier=${afterTrainMetrics.brierScore.toFixed(4)}`);
  console.log(`  Val Split   (n=${val.length}):    Acc=${(afterValMetrics.accuracy * 100).toFixed(1)}%, F1=${(afterValMetrics.f1 * 100).toFixed(1)}%, Brier=${afterValMetrics.brierScore.toFixed(4)}`);
  console.log(`  Test Split  (n=${test.length}):   Acc=${(afterTestMetrics.accuracy * 100).toFixed(1)}%, F1=${(afterTestMetrics.f1 * 100).toFixed(1)}%, Brier=${afterTestMetrics.brierScore.toFixed(4)}`);

  // 7. Export Model Artifact
  const modelArtifact: ExportedNlpModel = {
    modelVersion: 'mailtrace-nlp-v1.0.0-tfidf-lr',
    architecture: 'TF-IDF (Unigrams+Bigrams, L2 normalized) + Calibrated L2-Logistic Regression + One-vs-Rest Subtypes',
    datasetVersion: 'dataset-2026-09-04',
    trainedAt: new Date().toISOString(),
    datasetMetrics: {
      totalSamples: samples.length,
      trainSamples: train.length,
      valSamples: val.length,
      testSamples: test.length,
      classes: categoryCounts,
    },
    tfidf: vectorizer.toJSON(),
    binaryClassifier: binaryModel.toJSON(),
    threatClassifier: threatClassifier.toJSON(),
    evaluation: {
      beforeBaseline: beforeMetrics,
      afterTrainedTest: afterTestMetrics,
      afterTrainedTrain: afterTrainMetrics,
      afterTrainedVal: afterValMetrics,
    },
  };

  const outputPath = path.resolve(__dirname, '../models/trainedNlpModel.json');
  fs.writeFileSync(outputPath, JSON.stringify(modelArtifact, null, 2), 'utf-8');
  console.log(`\n[ARTIFACT] Exported model artifact to ${outputPath}`);
  console.log('================================================================================\n');

  return modelArtifact;
}

if (process.argv[1] && process.argv[1].endsWith('trainPipeline.ts')) {
  runTrainingPipeline().catch(err => {
    console.error('Training failed:', err);
    process.exit(1);
  });
}
