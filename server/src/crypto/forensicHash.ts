import { createHash } from 'node:crypto';

export class ForensicHashService {
  /**
   * Generates a deterministic SHA-256 hash for raw content or structured payloads.
   */
  static sha256(data: string | Buffer | object): string {
    const hash = createHash('sha256');
    if (typeof data === 'string' || Buffer.isBuffer(data)) {
      hash.update(data);
    } else {
      // Deterministic JSON serialization with sorted keys
      hash.update(this.canonicalStringify(data));
    }
    return hash.digest('hex');
  }

  /**
   * Sorts object keys recursively to guarantee deterministic JSON output regardless of key insertion order.
   */
  private static canonicalStringify(obj: any): string {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map(this.canonicalStringify.bind(this)).join(',') + ']';
    }
    const sortedKeys = Object.keys(obj).sort();
    const pairs = sortedKeys.map((key) => `${JSON.stringify(key)}:${this.canonicalStringify(obj[key])}`);
    return '{' + pairs.join(',') + '}';
  }
}
