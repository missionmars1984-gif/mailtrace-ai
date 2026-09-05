import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';
import { ExchangeDatabase } from '../db/database.js';
import { MailboxService } from './mailboxService.js';
import type { ExchangeMessage } from '../types/index.js';

export class EmbeddedSmtpServer {
  private static server: SMTPServer | null = null;
  private static isRunning = false;

  static isServerRunning(): boolean {
    return this.isRunning;
  }

  static start(port = 1025): Promise<boolean> {
    if (this.isRunning) return Promise.resolve(true);

    return new Promise((resolve) => {
      try {
        const server = new SMTPServer({
          authOptional: true,
          disabledCommands: ['STARTTLS'], // local plaintext delivery
          onAuth(_auth, _session, callback) {
            return callback(null, { user: 'local' });
          },
          onData(stream, _session, callback) {
            const chunks: Buffer[] = [];
            stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
            stream.on('end', async () => {
              try {
                const fullBuffer = Buffer.concat(chunks);
                const rawSource = fullBuffer.toString('utf-8');
                const parsed = await simpleParser(fullBuffer);

                const msgId = parsed.messageId || `<inbox_${Date.now()}@exchange.local>`;
                const id = `inbox_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;

                const fromAddr = {
                  name: parsed.from?.value?.[0]?.name || parsed.from?.text || 'Unknown',
                  address: parsed.from?.value?.[0]?.address || parsed.from?.text || 'unknown@exchange.local',
                };

                const toList = (parsed.to ? (Array.isArray(parsed.to) ? parsed.to : [parsed.to]) : [])
                  .flatMap((t: any) => t.value || [{ name: t.text || '', address: t.text || '' }])
                  .map((a: any) => ({ name: a.name || '', address: a.address || '' }));

                const ccList = (parsed.cc ? (Array.isArray(parsed.cc) ? parsed.cc : [parsed.cc]) : [])
                  .flatMap((c: any) => c.value || [{ name: c.text || '', address: c.text || '' }])
                  .map((a: any) => ({ name: a.name || '', address: a.address || '' }));

                const message: ExchangeMessage = {
                  id,
                  messageId: msgId,
                  folder: 'inbox',
                  from: fromAddr,
                  to: toList.length > 0 ? toList : [{ name: 'Me', address: 'user@corp.local' }],
                  cc: ccList,
                  subject: parsed.subject || '(No Subject)',
                  snippet: (parsed.text || '').substring(0, 150),
                  text: parsed.text || '',
                  html: typeof parsed.html === 'string' ? parsed.html : undefined,
                  date: parsed.date ? parsed.date.toISOString() : new Date().toISOString(),
                  isRead: false,
                  isStarred: false,
                  hasAttachments: Boolean(parsed.attachments && parsed.attachments.length > 0),
                  deliveryStatus: 'DELIVERED TO MAILBOX',
                  source: 'smtp',
                  rawSource,
                };

                const attachments = (parsed.attachments || []).map((att) => ({
                  filename: att.filename || 'attachment.dat',
                  contentType: att.contentType || 'application/octet-stream',
                  size: att.size || att.content.length,
                  data: att.content,
                }));

                ExchangeDatabase.saveMessage(message, attachments);
                console.log(`[Embedded SMTP] Successfully accepted and saved message "${message.subject}" into Inbox`);

                // Automatically forward to SOC threat analysis backend & enrich with risk score
                MailboxService.forwardToSocAndEnrich(rawSource, message.id);

                callback(null); // Accept message with 250 OK
              } catch (err: any) {
                console.error('[Embedded SMTP Parse Error]', err);
                callback(null);
              }
            });
          },
        });

        server.on('error', (err: any) => {
          if (err.code === 'EADDRINUSE') {
            console.log(`[Embedded SMTP] Port ${port} is already in use (e.g. Mailpit running); deferring to existing relay.`);
            this.isRunning = true;
            resolve(true);
          } else {
            console.warn('[Embedded SMTP Server Error]', err.message);
            resolve(false);
          }
        });

        server.listen(port, '127.0.0.1', () => {
          console.log(`=======================================================`);
          console.log(` 📨 Embedded SMTP Server active on 127.0.0.1:${port}`);
          console.log(`=======================================================`);
          this.server = server;
          this.isRunning = true;
          resolve(true);
        });
      } catch (err: any) {
        console.warn('[Embedded SMTP Server Init]', err.message);
        resolve(false);
      }
    });
  }

  static stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.isRunning = false;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}
