import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { ExchangeDatabase } from '../db/database.js';
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
}

export class SmtpService {
  private static transporter: Transporter | null = null;

  static isConfigured(): boolean {
    return Boolean(process.env.SMTP_HOST?.trim());
  }

  static getTransporter(): Transporter | null {
    if (!this.isConfigured()) return null;

    if (!this.transporter) {
      const host = process.env.SMTP_HOST!.trim();
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

  static async verifyConnection(): Promise<{ success: boolean; message: string }> {
    if (!this.isConfigured()) {
      return { success: false, message: 'SMTP not configured (SMTP_HOST is empty).' };
    }

    try {
      const transporter = this.getTransporter();
      if (!transporter) {
        return { success: false, message: 'Unable to initialize SMTP transport.' };
      }
      await transporter.verify();
      return { success: true, message: `Connected to SMTP relay at ${process.env.SMTP_HOST}:${process.env.SMTP_PORT || '1025'}` };
    } catch (err: any) {
      return { success: false, message: `SMTP connection failed: ${err.message}` };
    }
  }

  static async sendMail(options: SendMailOptions): Promise<{ success: boolean; messageId: string; error?: string }> {
    const transporter = this.getTransporter();
    if (!transporter) {
      return { success: false, messageId: '', error: 'SMTP relay not configured. Please set SMTP_HOST in environment.' };
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

    try {
      const info = await transporter.sendMail({
        from: fromAddress,
        to: toList.join(', '),
        cc: ccList.length > 0 ? ccList.join(', ') : undefined,
        bcc: bccList.length > 0 ? bccList.join(', ') : undefined,
        subject: cleanSubject,
        text: options.text || '',
        html: options.html || undefined,
        attachments: options.attachments,
      });

      // Persist sent message in local Sent folder
      const sentId = `sent_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      const sentMessage: ExchangeMessage = {
        id: sentId,
        messageId: info.messageId || `<${sentId}@exchange.local>`,
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
        rawSource: info.response ? `From: ${fromAddress}\r\nTo: ${toList.join(', ')}\r\nSubject: ${cleanSubject}\r\n\r\n${options.text || ''}` : undefined,
      };

      const dbAttachments = (options.attachments || []).map(a => ({
        filename: a.filename,
        contentType: a.contentType || 'application/octet-stream',
        size: a.content.length,
        data: a.content,
      }));

      ExchangeDatabase.saveMessage(sentMessage, dbAttachments);

      return {
        success: true,
        messageId: info.messageId || sentId,
      };
    } catch (err: any) {
      console.error('[Exchange SMTP Error]', err);
      return {
        success: false,
        messageId: '',
        error: err.message || 'SMTP transmission error occurred.',
      };
    }
  }
}
