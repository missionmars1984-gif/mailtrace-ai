/**
 * Canonical NLP Tokenizer & N-gram Extractor for MailTrace AI.
 * Shared identically between offline training and online real-time inference.
 */

const STOPWORDS = new Set([
  'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any', 'are', 'as', 'at',
  'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by',
  'did', 'do', 'does', 'doing', 'down', 'during',
  'each', 'few', 'for', 'from', 'further',
  'had', 'has', 'have', 'having', 'he', 'her', 'here', 'hers', 'herself', 'him', 'himself', 'his', 'how',
  'i', 'if', 'in', 'into', 'is', 'it', 'its', 'itself',
  'just',
  'me', 'more', 'most', 'my', 'myself',
  'no', 'nor', 'not',
  'of', 'off', 'on', 'once', 'only', 'or', 'other', 'our', 'ours', 'ourselves', 'out', 'over', 'own',
  'same', 'she', 'should', 'so', 'some', 'such',
  'than', 'that', 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there', 'these', 'they', 'this', 'those', 'through', 'to', 'too',
  'under', 'until', 'up',
  'very',
  'was', 'we', 'were', 'what', 'when', 'where', 'which', 'while', 'who', 'whom', 'why', 'with',
  'you', 'your', 'yours', 'yourself', 'yourselves'
]);

export interface TokenizerOptions {
  minTokenLength?: number;
  removeStopwords?: boolean;
  ngramRange?: [number, number]; // [1, 2] for unigrams + bigrams
}

export class Tokenizer {
  private minLen: number;
  private removeStopwords: boolean;
  private ngramRange: [number, number];

  constructor(options: TokenizerOptions = {}) {
    this.minLen = options.minTokenLength ?? 2;
    this.removeStopwords = options.removeStopwords ?? false;
    this.ngramRange = options.ngramRange ?? [1, 2];
  }

  public cleanText(text: string): string {
    if (!text) return '';
    return text
      .toLowerCase()
      .replace(/[\r\n\t]+/g, ' ')
      .replace(/[^\w\s\-@#\$%]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  public tokenizeWords(text: string): string[] {
    const cleaned = this.cleanText(text);
    if (!cleaned) return [];

    const words = cleaned.split(/\s+/);
    const tokens: string[] = [];

    for (const w of words) {
      const stripped = w.replace(/^[^a-z0-9]+|[^a-z0-9]+$/g, '');
      if (stripped.length >= this.minLen) {
        if (!this.removeStopwords || !STOPWORDS.has(stripped)) {
          tokens.push(stripped);
        }
      }
    }

    return tokens;
  }

  public extractNgrams(text: string): string[] {
    const words = this.tokenizeWords(text);
    const [minN, maxN] = this.ngramRange;
    const ngrams: string[] = [];

    for (let n = minN; n <= maxN; n++) {
      if (n === 1) {
        for (const word of words) {
          ngrams.push(word);
        }
      } else {
        for (let i = 0; i <= words.length - n; i++) {
          const slice = words.slice(i, i + n);
          ngrams.push(slice.join('_'));
        }
      }
    }

    return ngrams;
  }

  public getTermFrequencies(text: string): Map<string, number> {
    const ngrams = this.extractNgrams(text);
    const tf = new Map<string, number>();

    for (const token of ngrams) {
      tf.set(token, (tf.get(token) || 0) + 1);
    }

    return tf;
  }
}
