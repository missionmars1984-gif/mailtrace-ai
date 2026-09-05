import { simpleParser } from 'mailparser';
import { ExchangeDatabase } from '../db/database.js';
import type { ExchangeMessage, ExchangeAddress } from '../types/index.js';

export class MailboxService {
  private static isSyncing = false;

  static isConfigured(): boolean {
    return Boolean(process.env.MAILPIT_API_URL?.trim() || process.env.IMAP_HOST?.trim());
  }

  static getMode(): string {
    if (process.env.MAILPIT_API_URL?.trim()) return 'Mailpit REST Sync';
    if (process.env.IMAP_HOST?.trim()) return 'IMAP Protocol Sync';
    return 'Unconfigured';
  }

  static async verifyConnection(): Promise<{ success: boolean; message: string }> {
    if (!this.isConfigured()) {
      return { success: false, message: 'Mailbox connection not configured (neither MAILPIT_API_URL nor IMAP_HOST provided).' };
    }

    if (process.env.MAILPIT_API_URL?.trim()) {
      const url = process.env.MAILPIT_API_URL.replace(/\/$/, '');
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3000);
        const res = await fetch(`${url}/api/v1/info`, { signal: controller.signal });
        clearTimeout(timeout);
        if (res.ok) {
          return { success: true, message: `Connected to Mailpit server at ${url}` };
        }
        return { success: false, message: `Mailpit returned status HTTP ${res.status}` };
      } catch (err: any) {
        return { success: false, message: `Mail server unavailable at ${url}: ${err.message}` };
      }
    }

    // IMAP Connection verify
    return { success: true, message: `Configured for IMAP host ${process.env.IMAP_HOST}` };
  }

  /**
   * Synchronizes remote incoming messages into the local SQLite store.
   * Preserves raw RFC 822 source and forwards to MailTrace SOC background ingestion.
   */
  static async sync(): Promise<{ newCount: number; error?: string }> {
    if (this.isSyncing) return { newCount: 0 };
    this.isSyncing = true;

    try {
      if (process.env.MAILPIT_API_URL?.trim()) {
        const newCount = await this.syncFromMailpit();
        ExchangeDatabase.setSyncState('last_synced_at', new Date().toISOString());
        return { newCount };
      }
      return { newCount: 0 };
    } catch (err: any) {
      console.warn('[Exchange Mailbox Sync Warning]', err.message);
      return { newCount: 0, error: err.message };
    } finally {
      this.isSyncing = false;
    }
  }

  private static async syncFromMailpit(): Promise<number> {
    const baseUrl = process.env.MAILPIT_API_URL!.replace(/\/$/, '');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);

    const res = await fetch(`${baseUrl}/api/v1/messages?limit=50`, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) return 0;

    const data: any = await res.json();
    const messages = data?.messages || [];
    let imported = 0;

    for (const item of messages) {
      const mailpitId = item.ID;
      const existing = ExchangeDatabase.getMessageById(mailpitId);
      if (existing) continue; // Already ingested

      try {
        // Fetch original raw RFC822 MIME from Mailpit
        const rawRes = await fetch(`${baseUrl}/api/v1/message/${mailpitId}/raw`);
        const rawMime = rawRes.ok ? await rawRes.text() : '';

        // Parse with mailparser
        const parsed = await simpleParser(rawMime || (item.Snippet || ''));

        const fromAddr: ExchangeAddress = {
          name: parsed.from?.value?.[0]?.name || item.From?.Name || '',
          address: parsed.from?.value?.[0]?.address || item.From?.Address || 'unknown@remote.local',
        };

        const toAddrs: ExchangeAddress[] = (parsed.to ? (Array.isArray(parsed.to) ? parsed.to : [parsed.to]) : []).flatMap(t =>
          (t.value || []).map(v => ({ name: v.name || '', address: v.address || '' }))
        );
        if (toAddrs.length === 0 && item.To) {
          toAddrs.push(...item.To.map((t: any) => ({ name: t.Name || '', address: t.Address || '' })));
        }

        const msgRecord: ExchangeMessage = {
          id: mailpitId,
          messageId: parsed.messageId || item.MessageID || `<${mailpitId}@mailpit.local>`,
          folder: 'inbox',
          from: fromAddr,
          to: toAddrs,
          replyTo: parsed.replyTo?.value?.[0]?.address,
          subject: parsed.subject || item.Subject || '(No Subject)',
          snippet: (parsed.text || item.Snippet || '').substring(0, 150),
          text: parsed.text || '',
          html: typeof parsed.html === 'string' ? parsed.html : undefined,
          date: parsed.date ? parsed.date.toISOString() : (item.Created || new Date().toISOString()),
          isRead: false,
          isStarred: false,
          hasAttachments: Boolean(parsed.attachments && parsed.attachments.length > 0),
          rawSource: rawMime || undefined,
        };

        const attachments = (parsed.attachments || []).map(att => ({
          filename: att.filename || 'attachment.dat',
          contentType: att.contentType || 'application/octet-stream',
          size: att.size || att.content.length,
          data: att.content,
        }));

        ExchangeDatabase.saveMessage(msgRecord, attachments);
        imported++;

        // SOC Ingestion Bridge: Send raw RFC822 email to MailTrace SOC in the background
        if (rawMime && process.env.SOC_BACKEND_URL) {
          this.forwardToSoc(rawMime);
        }
      } catch (itemErr) {
        console.warn(`[Exchange Sync] Failed to parse message ${mailpitId}:`, itemErr);
      }
    }

    return imported;
  }

  /**
   * Ingests a raw RFC 822 MIME string directly into the database.
   * Parses MIME headers, extracts text/html/attachments, stores raw source byte-for-byte,
   * and asynchronously forwards to MailTrace SOC.
   */
  static async ingestRawEmail(rawMime: string, folder: 'inbox' | 'sent' | 'drafts' | 'trash' | 'spam' = 'inbox'): Promise<ExchangeMessage> {
    const parsed = await simpleParser(rawMime);
    const id = `msg_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

    const fromAddr: ExchangeAddress = {
      name: parsed.from?.value?.[0]?.name || '',
      address: parsed.from?.value?.[0]?.address || 'unknown@exchange.local',
    };

    const toAddrs: ExchangeAddress[] = (parsed.to ? (Array.isArray(parsed.to) ? parsed.to : [parsed.to]) : []).flatMap(t =>
      (t.value || []).map(v => ({ name: v.name || '', address: v.address || '' }))
    );

    const ccAddrs: ExchangeAddress[] = (parsed.cc ? (Array.isArray(parsed.cc) ? parsed.cc : [parsed.cc]) : []).flatMap(t =>
      (t.value || []).map(v => ({ name: v.name || '', address: v.address || '' }))
    );

    const bccAddrs: ExchangeAddress[] = (parsed.bcc ? (Array.isArray(parsed.bcc) ? parsed.bcc : [parsed.bcc]) : []).flatMap(t =>
      (t.value || []).map(v => ({ name: v.name || '', address: v.address || '' }))
    );

    const msgRecord: ExchangeMessage = {
      id,
      messageId: parsed.messageId || `<${id}@exchange.local>`,
      folder,
      from: fromAddr,
      to: toAddrs.length > 0 ? toAddrs : [{ name: '', address: 'undisclosed-recipients' }],
      cc: ccAddrs.length > 0 ? ccAddrs : undefined,
      bcc: bccAddrs.length > 0 ? bccAddrs : undefined,
      replyTo: parsed.replyTo?.value?.[0]?.address,
      subject: parsed.subject || '(No Subject)',
      snippet: (parsed.text || '').substring(0, 150),
      text: parsed.text || '',
      html: typeof parsed.html === 'string' ? parsed.html : undefined,
      date: parsed.date ? parsed.date.toISOString() : new Date().toISOString(),
      isRead: false,
      isStarred: false,
      hasAttachments: Boolean(parsed.attachments && parsed.attachments.length > 0),
      rawSource: rawMime,
    };

    const attachments = (parsed.attachments || []).map(att => ({
      filename: att.filename || 'attachment.dat',
      contentType: att.contentType || 'application/octet-stream',
      size: att.size || att.content.length,
      data: att.content,
    }));

    ExchangeDatabase.saveMessage(msgRecord, attachments);

    // SOC Ingestion Bridge: Send raw RFC822 email to MailTrace SOC in the background
    if (process.env.SOC_BACKEND_URL) {
      this.forwardToSoc(rawMime);
    }

    return msgRecord;
  }

  /**
   * Forwards the unedited raw RFC822 email to the MailTrace SOC backend for automatic AI analysis.
   * Completely asynchronous; failures do not disrupt the Exchange client.
   */
  private static async forwardToSoc(rawEmail: string): Promise<void> {
    const socUrl = process.env.SOC_BACKEND_URL?.trim();
    if (!socUrl) return;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      await fetch(socUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawEmail }),
        signal: controller.signal,
      });
      clearTimeout(timeout);
    } catch {
      // Gracefully ignore SOC transmission interruptions
    }
  }
}
