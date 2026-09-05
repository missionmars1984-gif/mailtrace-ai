import type { ExchangeMessage, FolderSummary, MailboxStatus, MailFolder } from './types';

const API_BASE = '/api';

export async function fetchStatus(): Promise<MailboxStatus> {
  const res = await fetch(`${API_BASE}/status`);
  if (!res.ok) throw new Error('Failed to fetch status');
  return res.json();
}

export async function fetchFolders(): Promise<FolderSummary[]> {
  const res = await fetch(`${API_BASE}/folders`);
  if (!res.ok) throw new Error('Failed to fetch folders');
  return res.json();
}

export async function fetchMessages(folder: MailFolder = 'inbox', search?: string): Promise<ExchangeMessage[]> {
  const params = new URLSearchParams({ folder });
  if (search && search.trim()) {
    params.set('search', search.trim());
  }
  const res = await fetch(`${API_BASE}/messages?${params.toString()}`);
  const data = await res.json();
  return Array.isArray(data) ? data : data.messages || [];
}

export async function fetchMessage(id: string): Promise<ExchangeMessage> {
  const res = await fetch(`${API_BASE}/messages/${id}`);
  if (!res.ok) throw new Error('Failed to fetch message details');
  return res.json();
}

export async function updateMessageFlags(id: string, updates: { isRead?: boolean; isStarred?: boolean }): Promise<void> {
  const res = await fetch(`${API_BASE}/messages/${id}/flags`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
  if (!res.ok) throw new Error('Failed to update message flags');
}

export async function moveMessage(id: string, folder: MailFolder): Promise<void> {
  const res = await fetch(`${API_BASE}/messages/${id}/move`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ folder }),
  });
  if (!res.ok) throw new Error('Failed to move message');
}

export async function deleteMessage(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/messages/${id}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Failed to delete message');
}

export interface SyncStats {
  status: string;
  checked: number;
  new: number;
  updated: number;
  duplicates: number;
  failed: number;
}

export interface SendResult {
  success: boolean;
  messageId: string;
  deliveryStatus?: string;
}

export async function syncMailbox(): Promise<SyncStats> {
  const res = await fetch(`${API_BASE}/mail/sync`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to sync mailbox');
  return res.json();
}

export async function sendMessage(formData: FormData): Promise<SendResult> {
  const res = await fetch(`${API_BASE}/mail/send`, {
    method: 'POST',
    body: formData,
  });
  const data = await res.json();
  if (!res.ok || !data.success) {
    throw new Error(data.error || 'Failed to send email');
  }
  return data;
}

export async function saveDraft(payload: { to?: string; subject?: string; text?: string; html?: string }): Promise<ExchangeMessage> {
  const res = await fetch(`${API_BASE}/messages/draft`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Failed to save draft');
  return res.json();
}
