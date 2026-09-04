/**
 * TF-IDF Vectorizer with smooth IDF, sublinear term frequency, and L2 normalization.
 * Fully serializable to JSON.
 */
import { Tokenizer } from './tokenizer.js';

export interface TfIdfModelData {
  vocabulary: Record<string, number>; // token -> featureIndex
  idf: number[];                      // featureIndex -> idf value
  numDocs: number;
  featureCount: number;
}

export class TfIdfVectorizer {
  private tokenizer: Tokenizer;
  private vocabulary: Map<string, number> = new Map();
  private idf: number[] = [];
  private numDocs = 0;
  private minDocFreq = 1;
  private maxFeatures = 500;

  constructor(tokenizer?: Tokenizer, maxFeatures = 500, minDocFreq = 1) {
    this.tokenizer = tokenizer || new Tokenizer({ ngramRange: [1, 2], removeStopwords: false });
    this.maxFeatures = maxFeatures;
    this.minDocFreq = minDocFreq;
  }

  public fit(documents: string[]): this {
    this.numDocs = documents.length;
    const docFreq = new Map<string, number>();

    for (const doc of documents) {
      const ngrams = this.tokenizer.extractNgrams(doc);
      const uniqueInDoc = new Set(ngrams);
      for (const token of uniqueInDoc) {
        docFreq.set(token, (docFreq.get(token) || 0) + 1);
      }
    }

    const candidates = Array.from(docFreq.entries())
      .filter(([_, df]) => df >= this.minDocFreq)
      .sort((a, b) => b[1] - a[1]);

    const selected = candidates.slice(0, this.maxFeatures);

    this.vocabulary.clear();
    this.idf = new Array(selected.length);

    selected.forEach(([token, df], index) => {
      this.vocabulary.set(token, index);
      this.idf[index] = Math.log((1 + this.numDocs) / (1 + df)) + 1;
    });

    return this;
  }

  public transform(document: string): Float64Array {
    const vector = new Float64Array(this.vocabulary.size);
    const tf = this.tokenizer.getTermFrequencies(document);

    let sumSquares = 0;

    for (const [token, count] of tf.entries()) {
      const idx = this.vocabulary.get(token);
      if (idx !== undefined) {
        const sublinearTf = 1 + Math.log(count);
        const weight = sublinearTf * this.idf[idx];
        vector[idx] = weight;
        sumSquares += weight * weight;
      }
    }

    if (sumSquares > 0) {
      const norm = Math.sqrt(sumSquares);
      for (let i = 0; i < vector.length; i++) {
        vector[i] /= norm;
      }
    }

    return vector;
  }

  public toJSON(): TfIdfModelData {
    const vocabObj: Record<string, number> = {};
    for (const [tok, idx] of this.vocabulary.entries()) {
      vocabObj[tok] = idx;
    }
    return {
      vocabulary: vocabObj,
      idf: this.idf,
      numDocs: this.numDocs,
      featureCount: this.vocabulary.size,
    };
  }

  public static fromJSON(data: TfIdfModelData): TfIdfVectorizer {
    const vectorizer = new TfIdfVectorizer();
    vectorizer.vocabulary = new Map(Object.entries(data.vocabulary));
    vectorizer.idf = data.idf;
    vectorizer.numDocs = data.numDocs;
    vectorizer.maxFeatures = data.featureCount;
    return vectorizer;
  }

  public getFeatureCount(): number {
    return this.vocabulary.size;
  }
}
