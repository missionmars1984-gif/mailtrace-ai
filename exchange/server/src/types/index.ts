export interface ExchangeAddress {
  name: string;
  address: string;
}

export interface ExchangeAttachment {
  id: string;
  messageId: string;
  filename: string;
  contentType: string;
  size: number;
}

export type MailFolder = 'inbox' | 'sent' | 'drafts' | 'trash' | 'spam';

export interface ExchangeMessage {
  id: string;
  messageId: string;
  providerMessageId?: string;
  threadId?: string;
  folder: MailFolder;
  from: ExchangeAddress;
  to: ExchangeAddress[];
  cc?: ExchangeAddress[];
  bcc?: ExchangeAddress[];
  replyTo?: string;
  subject: string;
  snippet: string;
  text: string;
  html?: string;
  date: string;
  isRead: boolean;
  isStarred: boolean;
  hasAttachments: boolean;
  attachments?: ExchangeAttachment[];
  rawSource?: string;
  source?: string;
  deliveryStatus?: 'QUEUED' | 'SMTP ACCEPTED' | 'DELIVERED TO MAILBOX' | 'DELIVERY FAILED';
  riskScore?: number;
  riskLevel?: string;
  threatClassification?: string;
  caseId?: string;
}

export interface FolderSummary {
  folder: MailFolder;
  total: number;
  unread: number;
}

export interface MailboxStatus {
  smtpConnected: boolean;
  smtpMessage: string;
  smtpHost?: string;
  smtpPort?: string;
  smtpSecure?: boolean;
  mailboxConnected: boolean;
  mailboxMessage: string;
  totalMessages: number;
  unreadCount: number;
  lastSyncedAt: string | null;
  lastConnectedAt?: string | null;
  mode: string;
  latencyMs?: number;
}

export interface SmtpHealthResponse {
  status: 'online' | 'offline';
  host: string;
  port: string;
  secure: boolean;
  error: string | null;
}

export interface GlobalHealthResponse {
  application: 'online' | 'degraded' | 'offline';
  database: 'online' | 'offline';
  smtp: 'online' | 'offline';
  mailpit: 'online' | 'offline';
  ingestion: 'online' | 'offline';
  threatEngine: 'online' | 'offline';
  aiEngine: 'configured' | 'fallback';
  geolocation: 'online' | 'offline';
}
