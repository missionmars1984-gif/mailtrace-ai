import { simpleParser } from 'mailparser';
import { ExchangeDatabase } from '../db/database.js';
import type { ExchangeMessage, ExchangeAddress } from '../types/index.js';

export class MailboxService {
  private static isSyncing = false;
  private static wsClient: any = null;
  private static reconnectTimer: any = null;
  private static reconnectDelay = 1000;
  private static isStreamActive = false;

  static isConfigured(): boolean {
    return Boolean(process.env.MAILPIT_API_URL?.trim() || process.env.IMAP_HOST?.trim());
  }

  static getMode(): string {
    if (process.env.MAILPIT_API_URL?.trim()) return 'Mailpit REST Sync';
    if (process.env.IMAP_HOST?.trim()) return 'IMAP Protocol Sync';
    return 'Unconfigured';
  }

  static async verifyConnection(): Promise<{ success: boolean; message: string; latencyMs?: number }> {
    if (!this.isConfigured()) {
      return { success: false, message: 'Mailbox connection not configured (neither MAILPIT_API_URL nor IMAP_HOST provided).' };
    }

    if (process.env.MAILPIT_API_URL?.trim()) {
      const url = process.env.MAILPIT_API_URL.replace(/\/$/, '');
      const startTime = Date.now();
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3000);
        const res = await fetch(`${url}/api/v1/info`, { signal: controller.signal });
        clearTimeout(timeout);
        const latencyMs = Date.now() - startTime;
        if (res.ok) {
          ExchangeDatabase.setSyncState('last_connected_at', new Date().toISOString());
          return { success: true, message: `Connected to Mailpit server at ${url}`, latencyMs };
        }
        return { success: false, message: `Mailpit returned status HTTP ${res.status}` };
      } catch (err: any) {
        return { success: false, message: `Mail server unavailable at ${url}: ${err.message}` };
      }
    }

    return { success: true, message: `Configured for IMAP host ${process.env.IMAP_HOST}` };
  }

  /**
   * Initializes real-time WebSocket connection to Mailpit event stream (/api/events).
   * Automatically reconnects with exponential backoff on disconnect.
   */
  static startEventStream(): void {
    if (this.isStreamActive) return;
    this.isStreamActive = true;
    this.connectWebSocket();
  }

  private static connectWebSocket(): void {
    const rawUrl = process.env.MAILPIT_API_URL?.trim();
    if (!rawUrl) return;

    try {
      const wsUrl = rawUrl.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:').replace(/\/$/, '') + '/api/events';
      const ws = new (globalThis as any).WebSocket(wsUrl);
      this.wsClient = ws;

      ws.onopen = () => {
        console.log(`[MailboxService] Real-time WebSocket connected to Mailpit: ${wsUrl}`);
        this.reconnectDelay = 1000;
        ExchangeDatabase.setSyncState('last_connected_at', new Date().toISOString());
      };

      ws.onmessage = async (event: any) => {
        try {
          const payload = typeof event.data === 'string' ? JSON.parse(event.data) : null;
          if (payload && payload.Type === 'new' && payload.Data?.ID) {
            console.log(`[MailboxService] Real-time new email event received: ${payload.Data.ID} ("${payload.Data.Subject || ''}")`);
            await this.ingestMailpitMessage(payload.Data.ID);
          }
        } catch (err) {
          console.warn('[MailboxService] Error processing WebSocket event:', err);
        }
      };

      ws.onclose = () => {
        this.scheduleReconnect();
      };

      ws.onerror = (err: any) => {
        console.warn('[MailboxService] WebSocket connection error:', err.message || err);
        try { ws.close(); } catch {}
        this.scheduleReconnect();
      };
    } catch (err) {
      console.warn('[MailboxService] Could not establish WebSocket:', err);
      this.scheduleReconnect();
    }
  }

  private static scheduleReconnect(): void {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectDelay = Math.min(30000, this.reconnectDelay * 1.5);
      this.connectWebSocket();
    }, this.reconnectDelay);
  }

  /**
   * Ingests a single message from Mailpit by ID.
   * Performs deduplication by Message-ID and Mailpit ID.
   * Triggers automatic threat analysis in MailTrace SOC.
   */
  static async ingestMailpitMessage(mailpitId: string): Promise<{ isNew: boolean; message: ExchangeMessage | null }> {
    const baseUrl = (process.env.MAILPIT_API_URL || 'http://localhost:8025').replace(/\/$/, '');

    // Check existing by provider ID
    const existingByProvider = ExchangeDatabase.findByProviderId(mailpitId);
    if (existingByProvider) {
      return { isNew: false, message: existingByProvider };
    }

    try {
      // 1. Fetch raw RFC 822 MIME
      const rawRes = await fetch(`${baseUrl}/api/v1/message/${mailpitId}/raw`);
      const rawMime = rawRes.ok ? await rawRes.text() : '';

      // 2. Fetch JSON metadata
      const metaRes = await fetch(`${baseUrl}/api/v1/message/${mailpitId}`);
      const meta = metaRes.ok ? await metaRes.json() : null;

      // 3. Parse with mailparser
      const parsed = await simpleParser(rawMime || meta?.Snippet || '');

      const rfcMessageId = parsed.messageId || meta?.MessageID || `<mailpit-${mailpitId}@corp.local>`;

      // Check existing by RFC messageId
      const existingByRfc = ExchangeDatabase.findByMessageId(rfcMessageId);
      if (existingByRfc) {
        return { isNew: false, message: existingByRfc };
      }

      const fromAddr: ExchangeAddress = {
        name: parsed.from?.value?.[0]?.name || meta?.From?.Name || '',
        address: parsed.from?.value?.[0]?.address || meta?.From?.Address || 'unknown@remote.local',
      };

      const toAddrs: ExchangeAddress[] = (parsed.to ? (Array.isArray(parsed.to) ? parsed.to : [parsed.to]) : []).flatMap((t: any) =>
        (t.value || []).map((v: any) => ({ name: v.name || '', address: v.address || '' }))
      );
      if (toAddrs.length === 0 && meta?.To) {
        toAddrs.push(...meta.To.map((t: any) => ({ name: t.Name || '', address: t.Address || '' })));
      }

      const ccAddrs: ExchangeAddress[] = (parsed.cc ? (Array.isArray(parsed.cc) ? parsed.cc : [parsed.cc]) : []).flatMap((c: any) =>
        (c.value || []).map((v: any) => ({ name: v.name || '', address: v.address || '' }))
      );

      const bccAddrs: ExchangeAddress[] = (parsed.bcc ? (Array.isArray(parsed.bcc) ? parsed.bcc : [parsed.bcc]) : []).flatMap((b: any) =>
        (b.value || []).map((v: any) => ({ name: v.name || '', address: v.address || '' }))
      );

      const msgRecord: ExchangeMessage = {
        id: mailpitId,
        messageId: rfcMessageId,
        providerMessageId: mailpitId,
        folder: 'inbox',
        from: fromAddr,
        to: toAddrs.length > 0 ? toAddrs : [{ name: '', address: 'undisclosed-recipients' }],
        cc: ccAddrs.length > 0 ? ccAddrs : undefined,
        bcc: bccAddrs.length > 0 ? bccAddrs : undefined,
        replyTo: parsed.replyTo?.value?.[0]?.address,
        subject: parsed.subject || meta?.Subject || '(No Subject)',
        snippet: (parsed.text || meta?.Snippet || '').substring(0, 150),
        text: parsed.text || '',
        html: typeof parsed.html === 'string' ? parsed.html : undefined,
        date: parsed.date ? parsed.date.toISOString() : (meta?.Created || new Date().toISOString()),
        isRead: false,
        isStarred: false,
        hasAttachments: Boolean(parsed.attachments && parsed.attachments.length > 0),
        rawSource: rawMime || undefined,
        source: 'mailpit',
        deliveryStatus: 'DELIVERED TO MAILBOX',
      };

      const attachments = (parsed.attachments || []).map((att: any) => ({
        filename: att.filename || 'attachment.dat',
        contentType: att.contentType || 'application/octet-stream',
        size: att.size || att.content?.length || 0,
        data: att.content,
      }));

      ExchangeDatabase.saveMessage(msgRecord, attachments);

      // Trigger automatic threat analysis in MailTrace SOC
      if (rawMime) {
        this.forwardToSocAndEnrich(rawMime, msgRecord.id);
      }

      return { isNew: true, message: msgRecord };
    } catch (err) {
      console.warn(`[MailboxService] Failed to ingest message ${mailpitId}:`, err);
      return { isNew: false, message: null };
    }
  }

  /**
   * Synchronizes remote incoming messages into the local SQLite store.
   * Compares message IDs, inserts missing, updates changed, triggers threat analysis.
   */
  static async sync(): Promise<{
    status: string;
    checked: number;
    new: number;
    updated: number;
    duplicates: number;
    failed: number;
  }> {
    if (this.isSyncing) {
      return { status: 'busy', checked: 0, new: 0, updated: 0, duplicates: 0, failed: 0 };
    }
    this.isSyncing = true;

    let checked = 0;
    let newCount = 0;
    let updatedCount = 0;
    let duplicateCount = 0;
    let failedCount = 0;

    try {
      if (process.env.MAILPIT_API_URL?.trim()) {
        const baseUrl = process.env.MAILPIT_API_URL.replace(/\/$/, '');
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);

        const res = await fetch(`${baseUrl}/api/v1/messages?limit=100`, { signal: controller.signal });
        clearTimeout(timeout);

        if (res.ok) {
          const data: any = await res.json();
          const messages = data?.messages || [];
          checked = messages.length;

          for (const item of messages) {
            const mailpitId = item.ID;
            const existing = ExchangeDatabase.findByProviderId(mailpitId) || (item.MessageID ? ExchangeDatabase.findByMessageId(item.MessageID) : null);

            if (existing) {
              duplicateCount++;
              // Check if read flag changed
              if (item.Read !== undefined && Boolean(item.Read) !== existing.isRead) {
                ExchangeDatabase.updateFlags(existing.id, { isRead: Boolean(item.Read) });
                updatedCount++;
              }
              continue;
            }

            const result = await this.ingestMailpitMessage(mailpitId);
            if (result.isNew) {
              newCount++;
            } else {
              duplicateCount++;
            }
          }

          ExchangeDatabase.setSyncState('last_synced_at', new Date().toISOString());
        } else {
          failedCount++;
        }
      }

      return {
        status: 'success',
        checked,
        new: newCount,
        updated: updatedCount,
        duplicates: duplicateCount,
        failed: failedCount,
      };
    } catch (err: any) {
      console.warn('[MailboxService Sync Error]', err.message);
      return {
        status: 'error',
        checked,
        new: newCount,
        updated: updatedCount,
        duplicates: duplicateCount,
        failed: failedCount + 1,
      };
    } finally {
      this.isSyncing = false;
    }
  }

  /**
   * Ingests a raw RFC 822 MIME string directly into the database.
   * Performs deduplication and forwards to MailTrace SOC for analysis.
   */
  static async ingestRawEmail(rawMime: string, folder: 'inbox' | 'sent' | 'drafts' | 'trash' | 'spam' = 'inbox'): Promise<ExchangeMessage> {
    const parsed = await simpleParser(rawMime);
    const rfcMessageId = parsed.messageId || `<msg_${Date.now()}@exchange.local>`;

    // Check existing by RFC messageId
    const existing = ExchangeDatabase.findByMessageId(rfcMessageId);
    if (existing) {
      return existing;
    }

    const id = `msg_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

    const fromAddr: ExchangeAddress = {
      name: parsed.from?.value?.[0]?.name || '',
      address: parsed.from?.value?.[0]?.address || 'unknown@exchange.local',
    };

    const toAddrs: ExchangeAddress[] = (parsed.to ? (Array.isArray(parsed.to) ? parsed.to : [parsed.to]) : []).flatMap((t: any) =>
      (t.value || []).map((v: any) => ({ name: v.name || '', address: v.address || '' }))
    );

    const ccAddrs: ExchangeAddress[] = (parsed.cc ? (Array.isArray(parsed.cc) ? parsed.cc : [parsed.cc]) : []).flatMap((c: any) =>
      (c.value || []).map((v: any) => ({ name: v.name || '', address: v.address || '' }))
    );

    const bccAddrs: ExchangeAddress[] = (parsed.bcc ? (Array.isArray(parsed.bcc) ? parsed.bcc : [parsed.bcc]) : []).flatMap((b: any) =>
      (b.value || []).map((v: any) => ({ name: v.name || '', address: v.address || '' }))
    );

    const msgRecord: ExchangeMessage = {
      id,
      messageId: rfcMessageId,
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
      source: 'ingest',
      deliveryStatus: 'DELIVERED TO MAILBOX',
    };

    const attachments = (parsed.attachments || []).map((att: any) => ({
      filename: att.filename || 'attachment.dat',
      contentType: att.contentType || 'application/octet-stream',
      size: att.size || att.content?.length || 0,
      data: att.content,
    }));

    ExchangeDatabase.saveMessage(msgRecord, attachments);

    // Forward to SOC and enrich message record with threat classification
    this.forwardToSocAndEnrich(rawMime, id);

    return msgRecord;
  }

  /**
   * Forwards the unedited raw RFC822 email to the MailTrace SOC backend for automatic AI analysis.
   * Updates the canonical message record with risk score, risk level, classification, and caseId.
   */
  static async forwardToSocAndEnrich(rawEmail: string, localId: string): Promise<void> {
    const socUrl = (process.env.SOC_BACKEND_URL || 'http://localhost:5000/api/ingest/email').trim();

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 6000);
      const res = await fetch(socUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawEmail }),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (res.ok) {
        const data: any = await res.json();
        if (data.success && typeof data.riskScore === 'number') {
          ExchangeDatabase.updateThreatScore(
            localId,
            data.riskScore,
            data.riskLevel || 'Clean',
            data.classification || 'Clean',
            data.caseId || data.caseNumber
          );
        }
      }
    } catch {
      // SOC failures do not disrupt mail client flow
    }
  }

  /**
   * Deletes a message in Mailpit by ID when requested.
   */
  static async deleteMailpitMessage(mailpitId: string): Promise<boolean> {
    const baseUrl = (process.env.MAILPIT_API_URL || 'http://localhost:8025').replace(/\/$/, '');
    try {
      const res = await fetch(`${baseUrl}/api/v1/messages`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ID: mailpitId }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}

