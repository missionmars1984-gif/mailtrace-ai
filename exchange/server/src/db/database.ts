import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { ExchangeMessage, ExchangeAttachment, MailFolder, FolderSummary } from '../types/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbDir = path.resolve(__dirname, '../../../../server/data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, 'mailtrace.db');
const db = new DatabaseSync(dbPath);

// Enable WAL mode & busy timeout for concurrent access
try {
  db.exec(`PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;`);
} catch {}

// Initialize Canonical Exchange Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    message_id TEXT,
    provider_message_id TEXT,
    thread_id TEXT,
    folder TEXT NOT NULL,
    from_name TEXT,
    from_addr TEXT NOT NULL,
    to_json TEXT NOT NULL,
    cc_json TEXT,
    bcc_json TEXT,
    reply_to TEXT,
    subject TEXT,
    snippet TEXT,
    body_text TEXT,
    body_html TEXT,
    date TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    is_starred INTEGER DEFAULT 0,
    has_attachments INTEGER DEFAULT 0,
    raw_source TEXT,
    source TEXT DEFAULT 'mailpit',
    delivery_status TEXT DEFAULT 'DELIVERED TO MAILBOX',
    risk_score INTEGER,
    risk_level TEXT,
    threat_classification TEXT,
    case_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_messages_folder ON messages(folder);
  CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date DESC);
  CREATE INDEX IF NOT EXISTS idx_messages_msg_id ON messages(message_id);
  CREATE INDEX IF NOT EXISTS idx_messages_provider_id ON messages(provider_message_id);
  CREATE INDEX IF NOT EXISTS idx_messages_thread_id ON messages(thread_id);
  CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(from_addr);
  CREATE INDEX IF NOT EXISTS idx_messages_risk ON messages(risk_score);

  CREATE TABLE IF NOT EXISTS message_attachments (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    data BLOB,
    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS exchange_sync_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);


export class ExchangeDatabase {
  static getMessages(options: {
    folder?: MailFolder;
    search?: string;
    page?: number;
    limit?: number;
  }): { messages: ExchangeMessage[]; total: number; page: number; totalPages: number } {
    const folder = options.folder || 'inbox';
    const page = Math.max(1, options.page || 1);
    const limit = Math.min(100, Math.max(1, options.limit || 30));
    const offset = (page - 1) * limit;

    let whereClause = 'WHERE folder = ?';
    const params: any[] = [folder];

    if (options.search && options.search.trim()) {
      const q = `%${options.search.trim()}%`;
      whereClause += ' AND (subject LIKE ? OR from_addr LIKE ? OR from_name LIKE ? OR snippet LIKE ? OR body_text LIKE ?)';
      params.push(q, q, q, q, q);
    }

    const countStmt = db.prepare(`SELECT COUNT(*) as count FROM messages ${whereClause}`);
    const countRow: any = countStmt.get(...params);
    const total = countRow ? Number(countRow.count) : 0;

    const queryStmt = db.prepare(`
      SELECT * FROM messages
      ${whereClause}
      ORDER BY date DESC
      LIMIT ? OFFSET ?
    `);
    const rows = queryStmt.all(...params, limit, offset);

    const messages: ExchangeMessage[] = rows.map((r: any) => ({
      id: r.id,
      messageId: r.message_id || r.id,
      providerMessageId: r.provider_message_id || undefined,
      threadId: r.thread_id || undefined,
      folder: r.folder as MailFolder,
      from: { name: r.from_name || '', address: r.from_addr },
      to: JSON.parse(r.to_json || '[]'),
      cc: r.cc_json ? JSON.parse(r.cc_json) : undefined,
      bcc: r.bcc_json ? JSON.parse(r.bcc_json) : undefined,
      replyTo: r.reply_to || undefined,
      subject: r.subject || '(No Subject)',
      snippet: r.snippet || '',
      text: r.body_text || '',
      html: r.body_html || undefined,
      date: r.date,
      isRead: Boolean(r.is_read),
      isStarred: Boolean(r.is_starred),
      hasAttachments: Boolean(r.has_attachments),
      rawSource: r.raw_source || undefined,
      source: r.source || 'mailpit',
      deliveryStatus: r.delivery_status || 'DELIVERED TO MAILBOX',
      riskScore: typeof r.risk_score === 'number' ? r.risk_score : undefined,
      riskLevel: r.risk_level || undefined,
      threatClassification: r.threat_classification || undefined,
      caseId: r.case_id || undefined,
    }));

    return {
      messages,
      total,
      page,
      totalPages: Math.ceil(total / limit) || 1,
    };
  }

  static getMessageById(id: string): ExchangeMessage | null {
    const stmt = db.prepare('SELECT * FROM messages WHERE id = ? OR message_id = ? OR provider_message_id = ? LIMIT 1');
    const r: any = stmt.get(id, id, id);
    if (!r) return null;

    const attStmt = db.prepare('SELECT id, message_id, filename, content_type, size FROM message_attachments WHERE message_id = ?');
    const attRows = attStmt.all(r.id) as any[];

    return {
      id: r.id,
      messageId: r.message_id || r.id,
      providerMessageId: r.provider_message_id || undefined,
      threadId: r.thread_id || undefined,
      folder: r.folder as MailFolder,
      from: { name: r.from_name || '', address: r.from_addr },
      to: JSON.parse(r.to_json || '[]'),
      cc: r.cc_json ? JSON.parse(r.cc_json) : undefined,
      bcc: r.bcc_json ? JSON.parse(r.bcc_json) : undefined,
      replyTo: r.reply_to || undefined,
      subject: r.subject || '(No Subject)',
      snippet: r.snippet || '',
      text: r.body_text || '',
      html: r.body_html || undefined,
      date: r.date,
      isRead: Boolean(r.is_read),
      isStarred: Boolean(r.is_starred),
      hasAttachments: Boolean(r.has_attachments),
      attachments: attRows.map((a) => ({
        id: a.id,
        messageId: a.message_id,
        filename: a.filename,
        contentType: a.content_type,
        size: a.size,
      })),
      rawSource: r.raw_source || undefined,
      source: r.source || 'mailpit',
      deliveryStatus: r.delivery_status || 'DELIVERED TO MAILBOX',
      riskScore: typeof r.risk_score === 'number' ? r.risk_score : undefined,
      riskLevel: r.risk_level || undefined,
      threatClassification: r.threat_classification || undefined,
      caseId: r.case_id || undefined,
    };
  }

  static findByMessageId(messageId: string): ExchangeMessage | null {
    if (!messageId) return null;
    return this.getMessageById(messageId);
  }

  static findByProviderId(providerId: string): ExchangeMessage | null {
    if (!providerId) return null;
    return this.getMessageById(providerId);
  }

  static getRawSource(id: string): string | null {
    const stmt = db.prepare('SELECT raw_source FROM messages WHERE id = ? OR message_id = ? LIMIT 1');
    const r: any = stmt.get(id, id);
    return r?.raw_source || null;
  }

  static saveMessage(msg: ExchangeMessage, attachmentsList?: Array<{ filename: string; contentType: string; size: number; data?: Buffer }>): void {
    const now = new Date().toISOString();
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO messages (
        id, message_id, provider_message_id, thread_id, folder,
        from_name, from_addr, to_json, cc_json, bcc_json,
        reply_to, subject, snippet, body_text, body_html,
        date, is_read, is_starred, has_attachments, raw_source,
        source, delivery_status, risk_score, risk_level, threat_classification,
        case_id, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?
      )
    `);

    stmt.run(
      msg.id,
      msg.messageId,
      msg.providerMessageId || null,
      msg.threadId || null,
      msg.folder,
      msg.from.name || '',
      msg.from.address,
      JSON.stringify(msg.to || []),
      msg.cc ? JSON.stringify(msg.cc) : null,
      msg.bcc ? JSON.stringify(msg.bcc) : null,
      msg.replyTo || null,
      msg.subject || '(No Subject)',
      msg.snippet || '',
      msg.text || '',
      msg.html || null,
      msg.date || now,
      msg.isRead ? 1 : 0,
      msg.isStarred ? 1 : 0,
      msg.hasAttachments ? 1 : 0,
      msg.rawSource || null,
      msg.source || 'mailpit',
      msg.deliveryStatus || 'DELIVERED TO MAILBOX',
      typeof msg.riskScore === 'number' ? msg.riskScore : null,
      msg.riskLevel || null,
      msg.threatClassification || null,
      msg.caseId || null,
      now,
      now
    );

    if (attachmentsList && attachmentsList.length > 0) {
      const attStmt = db.prepare(`
        INSERT OR REPLACE INTO message_attachments (id, message_id, filename, content_type, size, data)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      for (const a of attachmentsList) {
        const attId = `att_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
        attStmt.run(attId, msg.id, a.filename, a.contentType, a.size, a.data || null);
      }
    }
  }

  static updateDeliveryStatus(id: string, deliveryStatus: string): boolean {
    const stmt = db.prepare('UPDATE messages SET delivery_status = ?, updated_at = ? WHERE id = ? OR message_id = ?');
    stmt.run(deliveryStatus, new Date().toISOString(), id, id);
    return true;
  }

  static updateThreatScore(id: string, riskScore: number, riskLevel: string, threatClassification: string, caseId?: string): boolean {
    const stmt = db.prepare('UPDATE messages SET risk_score = ?, risk_level = ?, threat_classification = ?, case_id = ?, updated_at = ? WHERE id = ? OR message_id = ?');
    stmt.run(riskScore, riskLevel, threatClassification, caseId || null, new Date().toISOString(), id, id);
    return true;
  }

  static getAttachment(id: string): { filename: string; contentType: string; data: Buffer } | null {
    const stmt = db.prepare('SELECT filename, content_type, data FROM message_attachments WHERE id = ?');
    const r: any = stmt.get(id);
    if (!r || !r.data) return null;
    return {
      filename: r.filename,
      contentType: r.content_type,
      data: Buffer.from(r.data),
    };
  }

  static updateFlags(id: string, updates: { isRead?: boolean; isStarred?: boolean; folder?: MailFolder; deliveryStatus?: string }): boolean {
    const sets: string[] = ['updated_at = ?'];
    const params: any[] = [new Date().toISOString()];

    if (updates.isRead !== undefined) {
      sets.push('is_read = ?');
      params.push(updates.isRead ? 1 : 0);
    }
    if (updates.isStarred !== undefined) {
      sets.push('is_starred = ?');
      params.push(updates.isStarred ? 1 : 0);
    }
    if (updates.folder !== undefined) {
      sets.push('folder = ?');
      params.push(updates.folder);
    }
    if (updates.deliveryStatus !== undefined) {
      sets.push('delivery_status = ?');
      params.push(updates.deliveryStatus);
    }

    params.push(id);
    const stmt = db.prepare(`UPDATE messages SET ${sets.join(', ')} WHERE id = ?`);
    stmt.run(...params);
    return true;
  }

  static deleteMessage(id: string): boolean {
    const msg = this.getMessageById(id);
    if (!msg) return false;

    if (msg.folder !== 'trash') {
      return this.updateFlags(id, { folder: 'trash' });
    } else {
      const stmt = db.prepare('DELETE FROM messages WHERE id = ?');
      stmt.run(id);
      return true;
    }
  }

  static getFolderSummaries(): FolderSummary[] {
    const folders: MailFolder[] = ['inbox', 'sent', 'drafts', 'trash', 'spam'];
    const results: FolderSummary[] = [];

    for (const f of folders) {
      const totalStmt = db.prepare('SELECT COUNT(*) as count FROM messages WHERE folder = ?');
      const unreadStmt = db.prepare('SELECT COUNT(*) as count FROM messages WHERE folder = ? AND is_read = 0');
      const totalRow: any = totalStmt.get(f);
      const unreadRow: any = unreadStmt.get(f);

      results.push({
        folder: f,
        total: totalRow ? Number(totalRow.count) : 0,
        unread: unreadRow ? Number(unreadRow.count) : 0,
      });
    }

    return results;
  }

  static getSyncState(key: string): string | null {
    const stmt = db.prepare('SELECT value FROM exchange_sync_state WHERE key = ?');
    const r: any = stmt.get(key);
    return r?.value || null;
  }

  static setSyncState(key: string, value: string): void {
    const stmt = db.prepare('INSERT OR REPLACE INTO exchange_sync_state (key, value, updated_at) VALUES (?, ?, ?)');
    stmt.run(key, value, new Date().toISOString());
  }
}
