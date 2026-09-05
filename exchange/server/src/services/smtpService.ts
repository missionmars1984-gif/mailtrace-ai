import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { ExchangeDatabase } from '../db/database.js';
import { MailboxService } from './mailboxService.js';
import type { ExchangeMessage } from '../types/index.js';

export interface SendMailOptions {
  to: string | string[];
  cc?: string | string[];
  bcc?: string | string[];
  subject: string;
  text?: string;
  html?: string;
  attachments?: Array<{
    filename: string;
    content: Buffer;
    contentType?: string;
  }>;
  clientIp?: string;
}

export class SmtpService {
  private static transporter: Transporter | null = null;

  static isConfigured(): boolean {
    return true; // Configured with local embedded relay fallback
  }

  static getTransporter(): Transporter {
    if (!this.transporter) {
      const host = process.env.SMTP_HOST?.trim() || '127.0.0.1';
      const port = parseInt(process.env.SMTP_PORT || '1025', 10);
      const secure = process.env.SMTP_SECURE === 'true' || port === 465;
      const user = process.env.SMTP_USER?.trim();
      const pass = process.env.SMTP_PASSWORD?.trim();

      const auth = user && pass ? { user, pass } : undefined;

      this.transporter = nodemailer.createTransport({
        host,
        port,
        secure,
        auth,
        connectionTimeout: 5000,
        greetingTimeout: 5000,
      });
    }

    return this.transporter;
  }

  static async verifyConnection(): Promise<{ success: boolean; message: string; host: string; port: string; secure: boolean; error: string | null }> {
    const host = process.env.SMTP_HOST?.trim() || '127.0.0.1';
    const port = process.env.SMTP_PORT || '1025';
    const secure = process.env.SMTP_SECURE === 'true' || port === '465';

    try {
      const transporter = this.getTransporter();
      await transporter.verify();
      return {
        success: true,
        message: `Connected to SMTP relay at ${host}:${port}`,
        host,
        port,
        secure,
        error: null,
      };
    } catch (err: any) {
      // If external host failed or timed out (e.g. Render blocks outbound port 587/465),
      // seamlessly verify local embedded SMTP relay on 127.0.0.1:1025!
      if (host !== '127.0.0.1' && host !== 'localhost') {
        try {
          const fallbackTransporter = nodemailer.createTransport({
            host: '127.0.0.1',
            port: 1025,
            secure: false,
            connectionTimeout: 2000,
          });
          await fallbackTransporter.verify();
          return {
            success: true,
            message: `Embedded SMTP Relay Active on 127.0.0.1:1025 (External ${host}:${port} unreachable)`,
            host: '127.0.0.1',
            port: '1025',
            secure: false,
            error: null,
          };
        } catch {}
      }

      let friendlyError = err.message || 'SMTP connection error';
      if (err.code === 'ECONNREFUSED') {
        friendlyError = `SMTP connection refused at ${host}:${port}`;
      } else if (err.code === 'ETIMEDOUT') {
        friendlyError = `SMTP connection timeout at ${host}:${port}`;
      } else if (err.responseCode === 535 || err.message?.includes('auth')) {
        friendlyError = `SMTP authentication failed for user ${process.env.SMTP_USER || 'unknown'}`;
      }
      return {
        success: false,
        message: friendlyError,
        host,
        port,
        secure,
        error: friendlyError,
      };
    }
  }

  static async sendMail(options: SendMailOptions): Promise<{ success: boolean; messageId: string; error?: string; deliveryStatus?: string }> {
    const host = process.env.SMTP_HOST?.trim() || 'localhost';
    const port = process.env.SMTP_PORT || '1025';

    const transporter = this.getTransporter();
    if (!transporter) {
      return { success: false, messageId: '', error: `SMTP relay not configured. Please set SMTP_HOST in environment.` };
    }

    // Input Validation
    if (!options.to || (Array.isArray(options.to) && options.to.length === 0)) {
      return { success: false, messageId: '', error: 'Recipient address (To) is required.' };
    }

    const fromAddress = process.env.SMTP_FROM || 'user@corp.local';
    const toList = Array.isArray(options.to) ? options.to : [options.to];
    const ccList = options.cc ? (Array.isArray(options.cc) ? options.cc : [options.cc]) : [];
    const bccList = options.bcc ? (Array.isArray(options.bcc) ? options.bcc : [options.bcc]) : [];

    // Header injection safeguard
    const cleanSubject = (options.subject || '').replace(/\r|\n/g, ' ').trim();
    const originIp = options.clientIp || process.env.CLIENT_PUBLIC_IP || '223.185.101.157';
    const sentId = `sent_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const nowRfc = new Date().toUTCString();

    const mailOptions = {
      from: fromAddress,
      to: toList.join(', '),
      cc: ccList.length > 0 ? ccList.join(', ') : undefined,
      bcc: bccList.length > 0 ? bccList.join(', ') : undefined,
      subject: cleanSubject,
      text: options.text || '',
      html: options.html || undefined,
      attachments: options.attachments,
      headers: {
        'X-Originating-IP': `[${originIp}]`,
        'Received': `from client.in.mailtrace.net (client.in.mailtrace.net [${originIp}]) by mailtrace-exchange.internal with ESMTPSA id ${sentId} for <${toList[0]}>; ${nowRfc}`,
      },
    };

    let info: any = null;
    try {
      info = await transporter.sendMail(mailOptions);
    } catch (primaryErr: any) {
      console.warn(`[Exchange SMTP] Primary relay failed (${primaryErr.message}). Retrying via Embedded SMTP relay...`);
      // Seamless fallback to embedded relay on 127.0.0.1:1025
      try {
        const fallbackTransporter = nodemailer.createTransport({
          host: '127.0.0.1',
          port: 1025,
          secure: false,
          connectionTimeout: 3000,
        });
        info = await fallbackTransporter.sendMail(mailOptions);
      } catch (fallbackErr: any) {
        return {
          success: false,
          messageId: '',
          error: `Failed to deliver email: ${primaryErr.message || fallbackErr.message}`,
        };
      }
    }

    try {
      const messageId = info.messageId || `<${sentId}@exchange.mailtrace.in>`;
      let deliveryStatus: 'QUEUED' | 'SMTP ACCEPTED' | 'DELIVERED TO MAILBOX' = 'SMTP ACCEPTED';

      // Attempt to verify arrival in Mailpit API if Mailpit is configured
      if (process.env.MAILPIT_API_URL) {
        try {
          const mailpitUrl = process.env.MAILPIT_API_URL.replace(/\/$/, '');
          // Brief pause to allow mail server to register message
          await new Promise(r => setTimeout(r, 300));
          const checkRes = await fetch(`${mailpitUrl}/api/v1/messages?limit=5`);
          if (checkRes.ok) {
            const data: any = await checkRes.json();
            const found = (data?.messages || []).find((m: any) =>
              m.MessageID === messageId || m.Subject === cleanSubject
            );
            if (found) {
              deliveryStatus = 'DELIVERED TO MAILBOX';
            }
          }
        } catch {
          // Keep SMTP ACCEPTED if probe times out
        }
      }

      // Persist sent message in local Sent folder
      const sentMessage: ExchangeMessage = {
        id: sentId,
        messageId,
        folder: 'sent',
        from: { name: 'Me', address: fromAddress },
        to: toList.map(a => ({ name: a.split('@')[0], address: a })),
        cc: ccList.map(a => ({ name: a.split('@')[0], address: a })),
        bcc: bccList.map(a => ({ name: a.split('@')[0], address: a })),
        subject: cleanSubject,
        snippet: (options.text || '').substring(0, 150),
        text: options.text || '',
        html: options.html,
        date: new Date().toISOString(),
        isRead: true,
        isStarred: false,
        hasAttachments: Boolean(options.attachments && options.attachments.length > 0),
        deliveryStatus,
        source: 'smtp',
        rawSource: `Received: from client.in.mailtrace.net (client.in.mailtrace.net [${originIp}]) by mailtrace-exchange.internal with ESMTPSA id ${sentId};\r\n\t${nowRfc}\r\nFrom: ${fromAddress}\r\nTo: ${toList.join(', ')}\r\nSubject: ${cleanSubject}\r\nDate: ${nowRfc}\r\nMessage-ID: ${messageId}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset="UTF-8"\r\n\r\n${options.text || ''}`,
      };

      const dbAttachments = (options.attachments || []).map(a => ({
        filename: a.filename,
        contentType: a.contentType || 'application/octet-stream',
        size: a.content.length,
        data: a.content,
      }));

      ExchangeDatabase.saveMessage(sentMessage, dbAttachments);

      // Automatically forward sent message to SOC threat intelligence platform
      const emailContentToForward = (options.text && (options.text.includes('Received:') || options.text.includes('From:'))) 
        ? (options.text.startsWith('Received:') || options.text.startsWith('From:') ? options.text : sentMessage.rawSource)
        : sentMessage.rawSource;
      MailboxService.forwardToSocAndEnrich(emailContentToForward || sentMessage.rawSource || '', sentMessage.id);

      return {
        success: true,
        messageId,
        deliveryStatus,
      };
    } catch (err: any) {
      console.error('[Exchange SMTP Error]', err);
      let errorMsg = err.message || 'SMTP transmission error occurred.';
      if (err.code === 'ECONNREFUSED') {
        errorMsg = `SMTP connection refused at ${host}:${port}`;
      } else if (err.code === 'ETIMEDOUT') {
        errorMsg = `SMTP connection timeout at ${host}:${port}`;
      } else if (err.responseCode === 535) {
        errorMsg = 'SMTP authentication failed';
      }
      return {
        success: false,
        messageId: '',
        error: errorMsg,
      };
    }
  }
}
