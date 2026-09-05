import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { MessageList } from './components/MessageList';
import { MessageDetail } from './components/MessageDetail';
import { ComposeModal } from './components/ComposeModal';
import { SettingsModal } from './components/SettingsModal';
import type { ExchangeMessage, FolderSummary, MailboxStatus, MailFolder } from './types';
import { 
  fetchStatus, 
  fetchFolders, 
  fetchMessages, 
  fetchMessage, 
  updateMessageFlags, 
  deleteMessage, 
  syncMailbox 
} from './api';

export const App: React.FC = () => {
  const [currentFolder, setCurrentFolder] = useState<MailFolder>('inbox');
  const [messages, setMessages] = useState<ExchangeMessage[]>([]);
  const [selectedMessageId, setSelectedMessageId] = useState<string | null>(null);
  const [activeMessage, setActiveMessage] = useState<ExchangeMessage | null>(null);
  const [folderSummaries, setFolderSummaries] = useState<FolderSummary[]>([]);
  const [status, setStatus] = useState<MailboxStatus | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Filter toggles
  const [starredFilter, setStarredFilter] = useState(false);
  const [attachmentFilter, setAttachmentFilter] = useState(false);

  // Modals
  const [isComposeOpen, setIsComposeOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [composeDefaults, setComposeDefaults] = useState<{ to?: string; subject?: string; body?: string }>({});

  // Load Status and Folders
  const loadMetadata = useCallback(async () => {
    try {
      const [s, f] = await Promise.all([fetchStatus(), fetchFolders()]);
      setStatus(s);
      setFolderSummaries(f);
    } catch (err) {
      console.error('Failed to load metadata', err);
    }
  }, []);

  // Load Messages
  const loadMessages = useCallback(async () => {
    try {
      const list = await fetchMessages(currentFolder, searchQuery);
      let filtered = list;
      if (starredFilter) {
        filtered = filtered.filter((m) => m.isStarred);
      }
      if (attachmentFilter) {
        filtered = filtered.filter((m) => m.hasAttachments);
      }
      setMessages(filtered);

      // Auto-select first message if none selected or if selected message is no longer in list
      if (filtered.length > 0) {
        if (!selectedMessageId || !filtered.some((m) => m.id === selectedMessageId)) {
          setSelectedMessageId(filtered[0].id);
        }
      } else {
        setSelectedMessageId(null);
        setActiveMessage(null);
      }
    } catch (err) {
      console.error('Failed to load messages', err);
    }
  }, [currentFolder, searchQuery, starredFilter, attachmentFilter, selectedMessageId]);

  // Load Active Message Detail
  useEffect(() => {
    if (!selectedMessageId) {
      setActiveMessage(null);
      return;
    }
    let cancelled = false;
    fetchMessage(selectedMessageId)
      .then((detail) => {
        if (!cancelled) {
          setActiveMessage(detail);
          // Mark as read in local state
          if (!detail.isRead) {
            updateMessageFlags(detail.id, { isRead: true }).then(() => {
              loadMetadata();
              setMessages((prev) =>
                prev.map((m) => (m.id === detail.id ? { ...m, isRead: true } : m))
              );
            });
          }
        }
      })
      .catch((err) => console.error('Failed to load active message', err));

    return () => {
      cancelled = true;
    };
  }, [selectedMessageId, loadMetadata]);

  // Initial load
  useEffect(() => {
    loadMetadata();
  }, [loadMetadata]);

  useEffect(() => {
    loadMessages();
  }, [loadMessages]);

  // Periodic Background Sync (every 15 seconds)
  useEffect(() => {
    const timer = setInterval(() => {
      syncMailbox()
        .then(() => {
          loadMetadata();
          loadMessages();
        })
        .catch(() => {});
    }, 15000);
    return () => clearInterval(timer);
  }, [loadMetadata, loadMessages]);

  // Handlers
  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await syncMailbox();
      await Promise.all([loadMetadata(), loadMessages()]);
    } catch (err) {
      console.error('Refresh error', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleToggleSelectAll = () => {
    if (selectedIds.size === messages.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(messages.map((m) => m.id)));
    }
  };

  const handleToggleSelectId = (id: string) => {
    const next = new Set(selectedIds);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setSelectedIds(next);
  };

  const handleDeleteSelected = async () => {
    if (selectedIds.size === 0) return;
    try {
      await Promise.all(Array.from(selectedIds).map((id) => deleteMessage(id)));
      setSelectedIds(new Set());
      await Promise.all([loadMetadata(), loadMessages()]);
    } catch (err) {
      console.error('Failed to delete selected', err);
    }
  };

  const handleMarkReadSelected = async (isRead: boolean) => {
    if (selectedIds.size === 0) return;
    try {
      await Promise.all(
        Array.from(selectedIds).map((id) => updateMessageFlags(id, { isRead }))
      );
      await Promise.all([loadMetadata(), loadMessages()]);
    } catch (err) {
      console.error('Failed to update read status', err);
    }
  };

  const handleToggleStarred = async (id: string, current: boolean, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await updateMessageFlags(id, { isStarred: !current });
      setMessages((prev) =>
        prev.map((m) => (m.id === id ? { ...m, isStarred: !current } : m))
      );
      if (activeMessage && activeMessage.id === id) {
        setActiveMessage({ ...activeMessage, isStarred: !current });
      }
    } catch (err) {
      console.error('Failed to update starred status', err);
    }
  };

  const handleReply = (msg: ExchangeMessage) => {
    setComposeDefaults({
      to: msg.from.address,
      subject: msg.subject.startsWith('Re:') ? msg.subject : `Re: ${msg.subject}`,
      body: `\n\n--- Original Message ---\nFrom: ${msg.from.name || msg.from.address} <${msg.from.address}>\nDate: ${msg.date}\nSubject: ${msg.subject}\n\n${msg.text}`,
    });
    setIsComposeOpen(true);
  };

  const handleForward = (msg: ExchangeMessage) => {
    setComposeDefaults({
      to: '',
      subject: msg.subject.startsWith('Fwd:') ? msg.subject : `Fwd: ${msg.subject}`,
      body: `\n\n--- Forwarded Message ---\nFrom: ${msg.from.name || msg.from.address} <${msg.from.address}>\nDate: ${msg.date}\nSubject: ${msg.subject}\n\n${msg.text}`,
    });
    setIsComposeOpen(true);
  };

  const handleDeleteActive = async (id: string) => {
    try {
      await deleteMessage(id);
      setSelectedMessageId(null);
      setActiveMessage(null);
      await Promise.all([loadMetadata(), loadMessages()]);
    } catch (err) {
      console.error('Delete active failed', err);
    }
  };

  const handleMarkUnreadActive = async (id: string) => {
    try {
      await updateMessageFlags(id, { isRead: false });
      if (activeMessage && activeMessage.id === id) {
        setActiveMessage({ ...activeMessage, isRead: false });
      }
      setMessages((prev) =>
        prev.map((m) => (m.id === id ? { ...m, isRead: false } : m))
      );
      await loadMetadata();
    } catch (err) {
      console.error('Mark unread failed', err);
    }
  };

  return (
    <div className="flex flex-col h-screen w-screen bg-slate-100 overflow-hidden select-none">
      {/* Top Header */}
      <Header
        status={status}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        onRefresh={handleRefresh}
        isRefreshing={isRefreshing}
        onOpenSettings={() => setIsSettingsOpen(true)}
      />

      {/* Main Mail View (Sidebar + MessageList + MessageDetail) */}
      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          currentFolder={currentFolder}
          onSelectFolder={(folder) => {
            setCurrentFolder(folder);
            setSelectedIds(new Set());
          }}
          folderSummaries={folderSummaries}
          onOpenCompose={() => {
            setComposeDefaults({});
            setIsComposeOpen(true);
          }}
          starredFilter={starredFilter}
          onToggleStarredFilter={() => setStarredFilter(!starredFilter)}
          hasAttachmentFilter={attachmentFilter}
          onToggleAttachmentFilter={() => setAttachmentFilter(!attachmentFilter)}
        />

        <MessageList
          folder={currentFolder}
          messages={messages}
          selectedMessageId={selectedMessageId}
          onSelectMessage={setSelectedMessageId}
          selectedIds={selectedIds}
          onToggleSelectAll={handleToggleSelectAll}
          onToggleSelectId={handleToggleSelectId}
          onDeleteSelected={handleDeleteSelected}
          onMarkReadSelected={handleMarkReadSelected}
          onToggleStarred={handleToggleStarred}
          searchQuery={searchQuery}
        />

        <MessageDetail
          message={activeMessage}
          onReply={handleReply}
          onForward={handleForward}
          onDelete={handleDeleteActive}
          onMarkUnread={handleMarkUnreadActive}
        />
      </div>

      {/* Modals */}
      <ComposeModal
        isOpen={isComposeOpen}
        onClose={() => setIsComposeOpen(false)}
        onSent={() => {
          handleRefresh();
        }}
        initialTo={composeDefaults.to}
        initialSubject={composeDefaults.subject}
        initialBody={composeDefaults.body}
      />

      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        status={status}
      />
    </div>
  );
};
