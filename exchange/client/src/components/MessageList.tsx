import React from 'react';
import { 
  Star, 
  Paperclip, 
  Trash2, 
  Mail, 
  MailOpen, 
  CheckSquare, 
  Square,
  Inbox,
  Send,
  FileText,
  AlertOctagon,
  Search
} from 'lucide-react';
import type { ExchangeMessage, MailFolder } from '../types';

interface MessageListProps {
  folder: MailFolder;
  messages: ExchangeMessage[];
  selectedMessageId: string | null;
  onSelectMessage: (id: string) => void;
  selectedIds: Set<string>;
  onToggleSelectAll: () => void;
  onToggleSelectId: (id: string) => void;
  onDeleteSelected: () => void;
  onMarkReadSelected: (isRead: boolean) => void;
  onToggleStarred: (id: string, current: boolean, e: React.MouseEvent) => void;
  searchQuery?: string;
}

export const MessageList: React.FC<MessageListProps> = ({
  folder,
  messages,
  selectedMessageId,
  onSelectMessage,
  selectedIds,
  onToggleSelectAll,
  onToggleSelectId,
  onDeleteSelected,
  onMarkReadSelected,
  onToggleStarred,
  searchQuery,
}) => {
  const isAllSelected = messages.length > 0 && selectedIds.size === messages.length;
  const isSomeSelected = selectedIds.size > 0 && selectedIds.size < messages.length;

  const formatDate = (isoStr: string) => {
    try {
      const d = new Date(isoStr);
      const now = new Date();
      const isToday = d.toDateString() === now.toDateString();
      if (isToday) {
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }
      return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return isoStr;
    }
  };

  const getFolderTitle = () => {
    if (searchQuery) return `Search Results for "${searchQuery}"`;
    switch (folder) {
      case 'inbox': return 'Inbox';
      case 'sent': return 'Sent Items';
      case 'drafts': return 'Drafts';
      case 'trash': return 'Deleted Items';
      case 'spam': return 'Junk Email';
      default: return folder;
    }
  };

  const getEmptyState = () => {
    if (searchQuery) {
      return {
        icon: Search,
        title: 'No messages found',
        subtitle: `No emails match "${searchQuery}". Try different keywords.`,
      };
    }
    switch (folder) {
      case 'inbox':
        return {
          icon: Inbox,
          title: 'No messages in Inbox',
          subtitle: 'Your inbox is clear. Incoming messages will appear here.',
        };
      case 'sent':
        return {
          icon: Send,
          title: 'No sent messages',
          subtitle: 'Emails you send from this mailbox will be stored here.',
        };
      case 'drafts':
        return {
          icon: FileText,
          title: 'No drafts',
          subtitle: 'Unsent drafts will be saved here.',
        };
      case 'trash':
        return {
          icon: Trash2,
          title: 'Deleted Items is empty',
          subtitle: 'Deleted emails will be kept here before permanent removal.',
        };
      case 'spam':
        return {
          icon: AlertOctagon,
          title: 'No junk email',
          subtitle: 'Spam and quarantined items will appear here.',
        };
      default:
        return {
          icon: Inbox,
          title: 'No messages',
          subtitle: 'This folder is currently empty.',
        };
    }
  };

  const empty = getEmptyState();
  const EmptyIcon = empty.icon;

  return (
    <div className="w-80 md:w-96 border-r border-slate-200 bg-white flex flex-col h-full select-none shrink-0">
      {/* Top action / toolbar */}
      <div className="p-3 border-b border-slate-200 bg-slate-50/50">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-sm font-semibold text-slate-800 capitalize truncate">
            {getFolderTitle()}
          </h2>
          <span className="text-xs text-slate-400 font-normal">
            {messages.length} {messages.length === 1 ? 'item' : 'items'}
          </span>
        </div>

        <div className="flex items-center justify-between text-slate-600">
          <div className="flex items-center gap-2">
            <button
              onClick={onToggleSelectAll}
              className="text-slate-500 hover:text-slate-800 transition-colors"
              title={isAllSelected ? 'Deselect all' : 'Select all'}
            >
              {isAllSelected ? (
                <CheckSquare className="w-4 h-4 text-blue-700" />
              ) : isSomeSelected ? (
                <div className="w-4 h-4 rounded border-2 border-blue-700 bg-blue-100 flex items-center justify-center">
                  <div className="w-2 h-0.5 bg-blue-700 rounded-xs" />
                </div>
              ) : (
                <Square className="w-4 h-4 text-slate-400" />
              )}
            </button>
            <span className="text-xs text-slate-500 font-medium">
              {selectedIds.size > 0 ? `${selectedIds.size} selected` : 'Select'}
            </span>
          </div>

          {selectedIds.size > 0 && (
            <div className="flex items-center gap-1">
              <button
                onClick={() => onMarkReadSelected(true)}
                className="p-1 hover:bg-slate-200 rounded text-slate-600 transition-colors"
                title="Mark as read"
              >
                <MailOpen className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => onMarkReadSelected(false)}
                className="p-1 hover:bg-slate-200 rounded text-slate-600 transition-colors"
                title="Mark as unread"
              >
                <Mail className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={onDeleteSelected}
                className="p-1 hover:bg-red-50 text-slate-600 hover:text-red-600 rounded transition-colors"
                title="Delete selected"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Messages list / Empty state */}
      <div className="flex-1 overflow-y-auto divide-y divide-slate-100">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center p-6 text-center text-slate-400 select-none">
            <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center mb-3">
              <EmptyIcon className="w-6 h-6 text-slate-400" />
            </div>
            <h3 className="text-xs font-semibold text-slate-700 mb-1">{empty.title}</h3>
            <p className="text-[11px] text-slate-400 max-w-[200px] leading-relaxed">
              {empty.subtitle}
            </p>
          </div>
        ) : (
          messages.map((msg) => {
            const isSelected = selectedMessageId === msg.id;
            const isChecked = selectedIds.has(msg.id);
            const isSentFolder = folder === 'sent';
            const displayParty = isSentFolder
              ? `To: ${msg.to.map((t) => t.name || t.address).join(', ') || 'No recipient'}`
              : msg.from.name || msg.from.address || 'Unknown Sender';

            return (
              <div
                key={msg.id}
                onClick={() => onSelectMessage(msg.id)}
                className={`p-3 cursor-pointer transition-colors relative flex gap-2.5 text-xs ${
                  isSelected
                    ? 'bg-blue-50/70 border-l-4 border-l-blue-700'
                    : msg.isRead
                    ? 'bg-white hover:bg-slate-50/80 border-l-4 border-l-transparent'
                    : 'bg-slate-50/40 hover:bg-slate-100/70 border-l-4 border-l-blue-600'
                }`}
              >
                {/* Selection & Flag */}
                <div className="flex flex-col items-center gap-2 pt-0.5 shrink-0" onClick={(e) => e.stopPropagation()}>
                  <button
                    onClick={() => onToggleSelectId(msg.id)}
                    className="text-slate-400 hover:text-slate-600"
                  >
                    {isChecked ? (
                      <CheckSquare className="w-3.5 h-3.5 text-blue-700" />
                    ) : (
                      <Square className="w-3.5 h-3.5 text-slate-300" />
                    )}
                  </button>
                  <button
                    onClick={(e) => onToggleStarred(msg.id, msg.isStarred, e)}
                    className="text-slate-300 hover:text-amber-400 transition-colors"
                  >
                    <Star
                      className={`w-3.5 h-3.5 ${
                        msg.isStarred ? 'text-amber-400 fill-amber-400' : ''
                      }`}
                    />
                  </button>
                </div>

                {/* Body summary */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-0.5">
                    <span
                      className={`truncate pr-2 ${
                        msg.isRead ? 'font-normal text-slate-700' : 'font-semibold text-slate-900'
                      }`}
                    >
                      {displayParty}
                    </span>
                    <span className="text-[11px] text-slate-400 shrink-0">
                      {formatDate(msg.date)}
                    </span>
                  </div>

                  <div
                    className={`truncate mb-1 ${
                      msg.isRead ? 'text-slate-700 font-normal' : 'text-slate-900 font-semibold'
                    }`}
                  >
                    {msg.subject || '(No Subject)'}
                  </div>

                  <div className="text-[11px] text-slate-500 line-clamp-2 leading-relaxed break-words">
                    {msg.snippet || '(No text content)'}
                  </div>

                  {msg.hasAttachments && (
                    <div className="mt-1 flex items-center gap-1 text-[11px] text-slate-400">
                      <Paperclip className="w-3 h-3" />
                      <span>Attachment</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
