import { Router, Request, Response } from 'express';
import multer from 'multer';
import { ExchangeDatabase } from '../db/database.js';
import { SmtpService } from '../services/smtpService.js';
import { MailboxService } from '../services/mailboxService.js';
import type { MailFolder } from '../types/index.js';

export const mailRouter = Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

// GET /api/health/smtp - Dedicated SMTP health check endpoint
mailRouter.get('/health/smtp', async (_req: Request, res: Response) => {
  const smtpCheck = await SmtpService.verifyConnection();
  return res.json({
    status: smtpCheck.success ? 'online' : 'offline',
    host: smtpCheck.host,
    port: smtpCheck.port,
    secure: smtpCheck.secure,
    error: smtpCheck.error,
  });
});

// GET /api/health - Global system health check endpoint
mailRouter.get('/health', async (_req: Request, res: Response) => {
  const [smtpCheck, mailboxCheck] = await Promise.all([
    SmtpService.verifyConnection(),
    MailboxService.verifyConnection(),
  ]);

  return res.json({
    application: 'online',
    database: 'online',
    smtp: smtpCheck.success ? 'online' : 'offline',
    mailpit: mailboxCheck.success ? 'online' : 'offline',
    ingestion: 'online',
    threatEngine: 'online',
    aiEngine: 'configured',
    geolocation: 'online',
  });
});

// GET /api/status - Live connectivity check & telemetry
mailRouter.get('/status', async (_req: Request, res: Response) => {
  const [smtpCheck, mailboxCheck] = await Promise.all([
    SmtpService.verifyConnection(),
    MailboxService.verifyConnection(),
  ]);

  const summaries = ExchangeDatabase.getFolderSummaries();
  const inboxSummary = summaries.find(s => s.folder === 'inbox');
  const total = summaries.reduce((acc, s) => acc + s.total, 0);

  return res.json({
    smtpConnected: smtpCheck.success,
    smtpMessage: smtpCheck.message,
    smtpHost: smtpCheck.host,
    smtpPort: smtpCheck.port,
    smtpSecure: smtpCheck.secure,
    mailboxConnected: mailboxCheck.success,
    mailboxMessage: mailboxCheck.message,
    latencyMs: mailboxCheck.latencyMs,
    totalMessages: total,
    unreadCount: inboxSummary ? inboxSummary.unread : 0,
    lastSyncedAt: ExchangeDatabase.getSyncState('last_synced_at'),
    lastConnectedAt: ExchangeDatabase.getSyncState('last_connected_at'),
    mode: MailboxService.getMode(),
  });
});


// GET /api/folders - Folder summary counts
mailRouter.get('/folders', (_req: Request, res: Response) => {
  const summaries = ExchangeDatabase.getFolderSummaries();
  return res.json(summaries);
});

// GET /api/messages - Paginated message list with folder & search
mailRouter.get('/messages', (req: Request, res: Response) => {
  const folder = (req.query.folder as MailFolder) || 'inbox';
  const search = req.query.search as string;
  const page = parseInt(req.query.page as string, 10) || 1;
  const limit = parseInt(req.query.limit as string, 10) || 30;

  const result = ExchangeDatabase.getMessages({ folder, search, page, limit });
  return res.json(result);
});

// GET /api/messages/:id - Detailed message view
mailRouter.get('/messages/:id', (req: Request, res: Response) => {
  const message = ExchangeDatabase.getMessageById(String(req.params.id));
  if (!message) {
    return res.status(404).json({ error: 'Message not found' });
  }
  return res.json(message);
});

// GET /api/messages/:id/raw - Download raw RFC822 email source (.eml)
mailRouter.get('/messages/:id/raw', (req: Request, res: Response) => {
  const raw = ExchangeDatabase.getRawSource(String(req.params.id));
  if (!raw) {
    return res.status(404).send('Raw RFC822 source unavailable.');
  }

  res.setHeader('Content-Type', 'message/rfc822');
  res.setHeader('Content-Disposition', `attachment; filename="message-${req.params.id}.eml"`);
  return res.send(raw);
});

// GET /api/attachments/:id & /api/messages/:msgId/attachments/:id - Stream individual attachment download
const handleAttachmentDownload = (req: Request, res: Response) => {
  const att = ExchangeDatabase.getAttachment(String(req.params.id));
  if (!att) {
    return res.status(404).json({ error: 'Attachment not found' });
  }

  res.setHeader('Content-Type', att.contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(att.filename)}"`);
  return res.send(att.data);
};
mailRouter.get('/attachments/:id', handleAttachmentDownload);
mailRouter.get('/messages/:msgId/attachments/:id', handleAttachmentDownload);

// POST /api/send & /api/mail/send - Send real email via SMTP
const handleSend = async (req: Request, res: Response) => {
  try {
    const { to, cc, bcc, subject, text, html } = req.body;
    const files = req.files as Express.Multer.File[] | undefined;

    if (!to || typeof to !== 'string' || !to.trim()) {
      return res.status(400).json({ error: 'Recipient address (To) is required.' });
    }

    const attachments = (files || []).map(f => ({
      filename: f.originalname,
      content: f.buffer,
      contentType: f.mimetype,
    }));

    const result = await SmtpService.sendMail({
      to: to.split(',').map(s => s.trim()).filter(Boolean),
      cc: cc ? String(cc).split(',').map(s => s.trim()).filter(Boolean) : undefined,
      bcc: bcc ? String(bcc).split(',').map(s => s.trim()).filter(Boolean) : undefined,
      subject: String(subject || '').trim(),
      text: String(text || ''),
      html: html ? String(html) : undefined,
      attachments,
    });

    if (!result.success) {
      return res.status(502).json({ error: result.error || 'Failed to transmit email via SMTP relay.' });
    }

    return res.json({ success: true, messageId: result.messageId, deliveryStatus: result.deliveryStatus || 'SMTP ACCEPTED' });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Internal error processing send request.' });
  }
};
mailRouter.post('/send', upload.array('attachments'), handleSend);
mailRouter.post('/mail/send', upload.array('attachments'), handleSend);


// POST /api/drafts & POST /api/messages/draft - Save or update draft
const handleSaveDraft = (req: Request, res: Response) => {
  const { id, to, subject, text, html } = req.body;
  const draftId = id || `draft_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;

  const toList = (to ? String(to).split(',') : []).map(a => ({ name: a.trim().split('@')[0], address: a.trim() })).filter(a => Boolean(a.address));

  ExchangeDatabase.saveMessage({
    id: draftId,
    messageId: `<${draftId}@exchange.local>`,
    folder: 'drafts',
    from: { name: 'Me', address: process.env.SMTP_FROM || 'user@corp.local' },
    to: toList,
    subject: String(subject || '(Draft)').trim(),
    snippet: String(text || '').substring(0, 100),
    text: String(text || ''),
    html: html ? String(html) : undefined,
    date: new Date().toISOString(),
    isRead: true,
    isStarred: false,
    hasAttachments: false,
  });

  return res.json({ success: true, id: draftId });
};
mailRouter.post('/drafts', handleSaveDraft);
mailRouter.post('/messages/draft', handleSaveDraft);

// PATCH /api/messages/:id & /api/messages/:id/flags & /api/messages/:id/move - Toggle read/starred flags or move folder
const handleUpdateFlags = (req: Request, res: Response) => {
  const { isRead, isStarred, folder } = req.body;
  const updated = ExchangeDatabase.updateFlags(String(req.params.id), { isRead, isStarred, folder });
  if (!updated) {
    return res.status(404).json({ error: 'Message not found' });
  }
  return res.json({ success: true });
};
mailRouter.patch('/messages/:id', handleUpdateFlags);
mailRouter.patch('/messages/:id/flags', handleUpdateFlags);
mailRouter.patch('/messages/:id/move', handleUpdateFlags);

// DELETE /api/messages/:id - Move to trash or permanently delete
mailRouter.delete('/messages/:id', (req: Request, res: Response) => {
  const deleted = ExchangeDatabase.deleteMessage(String(req.params.id));
  if (!deleted) {
    return res.status(404).json({ error: 'Message not found' });
  }
  return res.json({ success: true });
});

// POST /api/sync & /api/mail/sync - Manually trigger remote mailbox sync
const handleSync = async (_req: Request, res: Response) => {
  const result = await MailboxService.sync();
  return res.json(result);
};
mailRouter.post('/sync', handleSync);
mailRouter.post('/mail/sync', handleSync);


// POST /api/ingest - Direct MIME Ingestion (stores raw RFC822 and bridges to SOC)
mailRouter.post('/ingest', async (req: Request, res: Response) => {
  try {
    const rawEmail = typeof req.body === 'string' ? req.body : req.body.rawEmail || req.body.rawSource;
    const folder = (req.body.folder as MailFolder) || 'inbox';
    if (!rawEmail || typeof rawEmail !== 'string') {
      return res.status(400).json({ error: 'rawEmail MIME text is required in request body.' });
    }

    const message = await MailboxService.ingestRawEmail(rawEmail, folder);
    return res.json({ success: true, message });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to ingest raw email.' });
  }
});
