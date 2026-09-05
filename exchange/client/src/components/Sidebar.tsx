import React from 'react';
import { 
  Inbox, 
  Send, 
  FileText, 
  Trash2, 
  AlertOctagon, 
  Plus, 
  Star, 
  Paperclip
} from 'lucide-react';
import type { FolderSummary, MailFolder } from '../types';

interface SidebarProps {
  currentFolder: MailFolder;
  onSelectFolder: (folder: MailFolder) => void;
  folderSummaries: FolderSummary[];
  onOpenCompose: () => void;
  starredFilter: boolean;
  onToggleStarredFilter: () => void;
  hasAttachmentFilter: boolean;
  onToggleAttachmentFilter: () => void;
  accountEmail?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentFolder,
  onSelectFolder,
  folderSummaries,
  onOpenCompose,
  starredFilter,
  onToggleStarredFilter,
  hasAttachmentFilter,
  onToggleAttachmentFilter,
  accountEmail = 'exchange@company.local',
}) => {
  const getCount = (folder: MailFolder) => {
    const summary = folderSummaries.find((s) => s.folder === folder);
    return summary ? { total: summary.total, unread: summary.unread } : { total: 0, unread: 0 };
  };

  const navItems: { folder: MailFolder; label: string; icon: React.FC<{ className?: string }> }[] = [
    { folder: 'inbox', label: 'Inbox', icon: Inbox },
    { folder: 'sent', label: 'Sent Items', icon: Send },
    { folder: 'drafts', label: 'Drafts', icon: FileText },
    { folder: 'trash', label: 'Deleted Items', icon: Trash2 },
    { folder: 'spam', label: 'Junk Email', icon: AlertOctagon },
  ];

  return (
    <aside className="w-60 bg-white border-r border-slate-200 flex flex-col justify-between select-none shrink-0 h-full">
      <div className="p-3">
        {/* Compose Button */}
        <button
          onClick={onOpenCompose}
          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-700 hover:bg-blue-800 active:bg-blue-900 text-white rounded-md font-medium text-xs shadow-xs transition-colors mb-4"
        >
          <Plus className="w-4 h-4" />
          <span>New Message</span>
        </button>

        {/* Mail Folders */}
        <div className="space-y-0.5">
          <div className="px-2 py-1 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Folders
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isSelected = currentFolder === item.folder && !starredFilter && !hasAttachmentFilter;
            const counts = getCount(item.folder);
            return (
              <button
                key={item.folder}
                onClick={() => {
                  if (starredFilter) onToggleStarredFilter();
                  if (hasAttachmentFilter) onToggleAttachmentFilter();
                  onSelectFolder(item.folder);
                }}
                className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  isSelected
                    ? 'bg-blue-50 text-blue-800 font-semibold'
                    : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900'
                }`}
              >
                <div className="flex items-center gap-2.5 truncate">
                  <Icon className={`w-4 h-4 shrink-0 ${isSelected ? 'text-blue-700' : 'text-slate-400'}`} />
                  <span className="truncate">{item.label}</span>
                </div>
                {counts.unread > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-blue-700 text-white leading-tight">
                    {counts.unread}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Quick Views */}
        <div className="mt-5 space-y-0.5">
          <div className="px-2 py-1 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Quick Views
          </div>
          <button
            onClick={onToggleStarredFilter}
            className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors ${
              starredFilter
                ? 'bg-amber-50 text-amber-900 font-semibold'
                : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900'
            }`}
          >
            <div className="flex items-center gap-2.5">
              <Star className={`w-4 h-4 shrink-0 ${starredFilter ? 'text-amber-500 fill-amber-500' : 'text-slate-400'}`} />
              <span>Flagged / Starred</span>
            </div>
          </button>
          <button
            onClick={onToggleAttachmentFilter}
            className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors ${
              hasAttachmentFilter
                ? 'bg-blue-50 text-blue-800 font-semibold'
                : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900'
            }`}
          >
            <div className="flex items-center gap-2.5">
              <Paperclip className={`w-4 h-4 shrink-0 ${hasAttachmentFilter ? 'text-blue-700' : 'text-slate-400'}`} />
              <span>With Attachments</span>
            </div>
          </button>
        </div>
      </div>

      {/* User / Mailbox Account Badge */}
      <div className="p-3 border-t border-slate-200 bg-slate-50/50">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-full bg-slate-200 text-slate-700 flex items-center justify-center font-semibold text-xs shrink-0">
            EX
          </div>
          <div className="truncate">
            <div className="text-xs font-semibold text-slate-800 truncate leading-tight">
              Enterprise Mailbox
            </div>
            <div className="text-[11px] text-slate-500 truncate" title={accountEmail}>
              {accountEmail}
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};
