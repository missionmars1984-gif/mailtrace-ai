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
  deliveryStatus?: string;
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
  smtpPort?: string | number;
  smtpSecure?: boolean;
  mailboxConnected: boolean;
  mailboxMessage: string;
  latencyMs?: number;
  totalMessages: number;
  unreadCount: number;
  lastSyncedAt: string | null;
  lastConnectedAt?: string | null;
  mode: string;
}

export interface SendEmailPayload {
  from?: string;
  to: string;
  cc?: string;
  bcc?: string;
  replyTo?: string;
  subject: string;
  text?: string;
  html?: string;
  attachments?: File[];
}
