/**
 * Dataset loader, validator, and stratified splitter for MailTrace AI.
 * Parses server/data/dataset.csv with zero external dependencies.
 */
import fs from 'node:fs';
import path from 'node:path';

export interface DatasetSample {
  id: number;
  text: string;
  label: 0 | 1; // 0 = legitimate, 1 = phishing
  phishingType: string;
  severity: string;
  confidence: number;
}

export interface SplitResult {
  train: DatasetSample[];
  val: DatasetSample[];
  test: DatasetSample[];
}

export class DatasetLoader {
  /**
   * RFC 4180 compliant CSV parser for dataset.csv
   */
  static loadCsv(filePath: string): DatasetSample[] {
    const content = fs.readFileSync(filePath, 'utf-8');
    const records: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < content.length; i++) {
      const c = content[i];
      if (c === '"') {
        if (inQuotes && content[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (c === '\n' && !inQuotes) {
        if (current.trim()) records.push(current.trim());
        current = '';
      } else {
        current += c;
      }
    }
    if (current.trim()) records.push(current.trim());

    const samples: DatasetSample[] = [];

    // Skip header line (index 0)
    for (let i = 1; i < records.length; i++) {
      const line = records[i];
      const lastCommaIdx4 = line.lastIndexOf(',');
      const confidenceStr = line.substring(lastCommaIdx4 + 1).trim();

      const sub3 = line.substring(0, lastCommaIdx4);
      const lastCommaIdx3 = sub3.lastIndexOf(',');
      const severityStr = sub3.substring(lastCommaIdx3 + 1).trim();

      const sub2 = sub3.substring(0, lastCommaIdx3);
      const lastCommaIdx2 = sub2.lastIndexOf(',');
      const typeStr = sub2.substring(lastCommaIdx2 + 1).trim();

      const sub1 = sub2.substring(0, lastCommaIdx2);
      const lastCommaIdx1 = sub1.lastIndexOf(',');
      const labelStr = sub1.substring(lastCommaIdx1 + 1).trim();

      let text = sub1.substring(0, lastCommaIdx1).trim();
      if (text.startsWith('"') && text.endsWith('"')) {
        text = text.substring(1, text.length - 1).replace(/""/g, '"');
      }

      const label = parseInt(labelStr, 10) as 0 | 1;
      const confidence = parseFloat(confidenceStr);

      samples.push({
        id: i,
        text,
        label,
        phishingType: typeStr,
        severity: severityStr,
        confidence,
      });
    }

    return samples;
  }

  /**
   * Deterministic Mulberry32 PRNG for reproducible stratified splits.
   */
  private static mulberry32(seed: number): () => number {
    return () => {
      let t = (seed += 0x6d2b79f5);
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  /**
   * Performs stratified splitting by phishingType (and label).
   * 70% Train, 15% Validation, 15% Test.
   */
  static stratifiedSplit(samples: DatasetSample[], seed = 42): SplitResult {
    const rng = this.mulberry32(seed);

    // Group samples by phishingType
    const groups = new Map<string, DatasetSample[]>();
    for (const s of samples) {
      if (!groups.has(s.phishingType)) {
        groups.set(s.phishingType, []);
      }
      groups.get(s.phishingType)!.push(s);
    }

    // Shuffle within each group with deterministic seed
    for (const [key, group] of groups.entries()) {
      for (let i = group.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        [group[i], group[j]] = [group[j], group[i]];
      }
    }

    const train: DatasetSample[] = [];
    const val: DatasetSample[] = [];
    const test: DatasetSample[] = [];

    // Allocate 70% train, 15% val, 15% test per group
    for (const [key, group] of groups.entries()) {
      const n = group.length;
      if (n === 1) {
        train.push(group[0]);
      } else if (n === 2) {
        train.push(group[0]);
        test.push(group[1]);
      } else if (n === 3) {
        train.push(group[0]);
        val.push(group[1]);
        test.push(group[2]);
      } else {
        const nTest = Math.max(1, Math.round(n * 0.15));
        const nVal = Math.max(1, Math.round(n * 0.15));
        const nTrain = n - nVal - nTest;

        const gTrain = group.slice(0, nTrain);
        const gVal = group.slice(nTrain, nTrain + nVal);
        const gTest = group.slice(nTrain + nVal);

        train.push(...gTrain);
        val.push(...gVal);
        test.push(...gTest);
      }
    }

    return { train, val, test };
  }

  /**
   * Verifies absence of data leakage (exact and near duplicates) between train and test.
   */
  static checkLeakage(train: DatasetSample[], test: DatasetSample[]): { leakedCount: number; maxJaccard: number } {
    let leakedCount = 0;
    let maxJaccard = 0;

    const tokenize = (s: string) => new Set(s.toLowerCase().replace(/[^\w\s]/g, '').split(/\s+/).filter(Boolean));

    for (const te of test) {
      const teTokens = tokenize(te.text);
      for (const tr of train) {
        if (te.text.trim().toLowerCase() === tr.text.trim().toLowerCase()) {
          leakedCount++;
        }
        const trTokens = tokenize(tr.text);
        let intersection = 0;
        for (const t of teTokens) {
          if (trTokens.has(t)) intersection++;
        }
        const union = new Set([...teTokens, ...trTokens]).size;
        const jaccard = union > 0 ? intersection / union : 0;
        if (jaccard > maxJaccard) {
          maxJaccard = jaccard;
        }
      }
    }

    return { leakedCount, maxJaccard };
  }
}
