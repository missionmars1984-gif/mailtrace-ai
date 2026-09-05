import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { ExchangeMessage, ExchangeAttachment, MailFolder, FolderSummary } from '../types/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbDir = path.resolve(__dirname, '../../../data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, 'exchange.sqlite');
const db = new DatabaseSync(dbPath);

// Initialize Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    message_id TEXT,
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
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_messages_folder ON messages(folder);
  CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date);
  CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(is_read);

  CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    data BLOB,
    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS sync_state (
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
    }));

    return {
      messages,
      total,
      page,
      totalPages: Math.ceil(total / limit) || 1,
    };
  }

  static getMessageById(id: string): ExchangeMessage | null {
    const stmt = db.prepare('SELECT * FROM messages WHERE id = ?');
    const r: any = stmt.get(id);
    if (!r) return null;

    const attStmt = db.prepare('SELECT id, message_id, filename, content_type, size FROM attachments WHERE message_id = ?');
    const attRows = attStmt.all(id) as any[];

    return {
      id: r.id,
      messageId: r.message_id || r.id,
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
    };
  }

  static getRawSource(id: string): string | null {
    const stmt = db.prepare('SELECT raw_source FROM messages WHERE id = ?');
    const r: any = stmt.get(id);
    return r?.raw_source || null;
  }

  static saveMessage(msg: ExchangeMessage, attachmentsList?: Array<{ filename: string; contentType: string; size: number; data?: Buffer }>): void {
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO messages (
        id, message_id, folder, from_name, from_addr,
        to_json, cc_json, bcc_json, reply_to, subject,
        snippet, body_text, body_html, date, is_read,
        is_starred, has_attachments, raw_source, created_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?
      )
    `);

    stmt.run(
      msg.id,
      msg.messageId,
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
      msg.date || new Date().toISOString(),
      msg.isRead ? 1 : 0,
      msg.isStarred ? 1 : 0,
      msg.hasAttachments ? 1 : 0,
      msg.rawSource || null,
      new Date().toISOString()
    );

    if (attachmentsList && attachmentsList.length > 0) {
      const attStmt = db.prepare(`
        INSERT OR REPLACE INTO attachments (id, message_id, filename, content_type, size, data)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      for (const a of attachmentsList) {
        const attId = `att_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
        attStmt.run(attId, msg.id, a.filename, a.contentType, a.size, a.data || null);
      }
    }
  }

  static getAttachment(id: string): { filename: string; contentType: string; data: Buffer } | null {
    const stmt = db.prepare('SELECT filename, content_type, data FROM attachments WHERE id = ?');
    const r: any = stmt.get(id);
    if (!r || !r.data) return null;
    return {
      filename: r.filename,
      contentType: r.content_type,
      data: Buffer.from(r.data),
    };
  }

  static updateFlags(id: string, updates: { isRead?: boolean; isStarred?: boolean; folder?: MailFolder }): boolean {
    const sets: string[] = [];
    const params: any[] = [];

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

    if (sets.length === 0) return false;
    params.push(id);

    const stmt = db.prepare(`UPDATE messages SET ${sets.join(', ')} WHERE id = ?`);
    stmt.run(...params);
    return true;
  }

  static deleteMessage(id: string): boolean {
    const msg = this.getMessageById(id);
    if (!msg) return false;

    if (msg.folder !== 'trash') {
      // Move to trash first
      return this.updateFlags(id, { folder: 'trash' });
    } else {
      // Hard delete if already in trash
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
    const stmt = db.prepare('SELECT value FROM sync_state WHERE key = ?');
    const r: any = stmt.get(key);
    return r?.value || null;
  }

  static setSyncState(key: string, value: string): void {
    const stmt = db.prepare('INSERT OR REPLACE INTO sync_state (key, value, updated_at) VALUES (?, ?, ?)');
    stmt.run(key, value, new Date().toISOString());
  }
}
