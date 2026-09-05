import React, { useState, useEffect, useRef } from 'react';
import { X, Send, Paperclip, Trash2, AlertCircle, CheckCircle2 } from 'lucide-react';
import { sendMessage, saveDraft } from '../api';

interface ComposeModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSent: () => void;
  initialTo?: string;
  initialSubject?: string;
  initialBody?: string;
}

export const ComposeModal: React.FC<ComposeModalProps> = ({
  isOpen,
  onClose,
  onSent,
  initialTo = '',
  initialSubject = '',
  initialBody = '',
}) => {
  const [to, setTo] = useState(initialTo);
  const [showCc, setShowCc] = useState(false);
  const [showBcc, setShowBcc] = useState(false);
  const [cc, setCc] = useState('');
  const [bcc, setBcc] = useState('');
  const [subject, setSubject] = useState(initialSubject);
  const [body, setBody] = useState(initialBody);
  const [files, setFiles] = useState<File[]>([]);
  const [isSending, setIsSending] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (isOpen) {
      setTo(initialTo);
      setSubject(initialSubject);
      setBody(initialBody);
      setErrorMessage(null);
      setSuccessMessage(null);
    }
  }, [isOpen, initialTo, initialSubject, initialBody]);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const newFiles = Array.from(e.target.files);
      setFiles((prev) => [...prev, ...newFiles]);
    }
  };

  const removeFile = (idx: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!to.trim()) {
      setErrorMessage('Recipient "To" address is required');
      return;
    }

    setIsSending(true);
    setErrorMessage(null);

    try {
      const formData = new FormData();
      formData.append('to', to.trim());
      if (cc.trim()) formData.append('cc', cc.trim());
      if (bcc.trim()) formData.append('bcc', bcc.trim());
      formData.append('subject', subject.trim());
      formData.append('text', body);

      files.forEach((file) => {
        formData.append('attachments', file);
      });

      await sendMessage(formData);
      setSuccessMessage('Message sent successfully!');
      setTimeout(() => {
        onSent();
        onClose();
      }, 1000);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to send message via SMTP');
    } finally {
      setIsSending(false);
    }
  };

  const handleSaveDraft = async () => {
    setIsSaving(true);
    try {
      await saveDraft({
        to: to.trim(),
        subject: subject.trim(),
        text: body,
      });
      setSuccessMessage('Draft saved');
      setTimeout(() => setSuccessMessage(null), 2500);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to save draft');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
      <div className="bg-white rounded-lg shadow-xl border border-slate-300 w-full max-w-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="h-11 bg-slate-900 text-white px-4 flex items-center justify-between select-none">
          <div className="text-xs font-semibold tracking-wide">New Message</div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Notifications */}
        {errorMessage && (
          <div className="px-4 py-2 bg-red-50 border-b border-red-200 text-red-700 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span className="flex-1">{errorMessage}</span>
          </div>
        )}
        {successMessage && (
          <div className="px-4 py-2 bg-emerald-50 border-b border-emerald-200 text-emerald-700 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span className="flex-1">{successMessage}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSend} className="flex flex-col flex-1 overflow-hidden">
          <div className="p-4 space-y-2 border-b border-slate-200 text-xs">
            {/* To field */}
            <div className="flex items-center gap-2 border-b border-slate-100 pb-1.5">
              <label className="w-12 text-slate-500 font-medium shrink-0">To:</label>
              <input
                type="text"
                value={to}
                onChange={(e) => setTo(e.target.value)}
                placeholder="recipient@example.com"
                className="flex-1 focus:outline-none text-slate-800"
                required
              />
              <div className="flex items-center gap-2 text-[11px] text-slate-400">
                {!showCc && (
                  <button
                    type="button"
                    onClick={() => setShowCc(true)}
                    className="hover:text-blue-600"
                  >
                    Cc
                  </button>
                )}
                {!showBcc && (
                  <button
                    type="button"
                    onClick={() => setShowBcc(true)}
                    className="hover:text-blue-600"
                  >
                    Bcc
                  </button>
                )}
              </div>
            </div>

            {/* CC */}
            {showCc && (
              <div className="flex items-center gap-2 border-b border-slate-100 pb-1.5">
                <label className="w-12 text-slate-500 font-medium shrink-0">Cc:</label>
                <input
                  type="text"
                  value={cc}
                  onChange={(e) => setCc(e.target.value)}
                  placeholder="comma-separated emails"
                  className="flex-1 focus:outline-none text-slate-800"
                />
              </div>
            )}

            {/* BCC */}
            {showBcc && (
              <div className="flex items-center gap-2 border-b border-slate-100 pb-1.5">
                <label className="w-12 text-slate-500 font-medium shrink-0">Bcc:</label>
                <input
                  type="text"
                  value={bcc}
                  onChange={(e) => setBcc(e.target.value)}
                  placeholder="comma-separated emails"
                  className="flex-1 focus:outline-none text-slate-800"
                />
              </div>
            )}

            {/* Subject */}
            <div className="flex items-center gap-2 pt-0.5">
              <label className="w-12 text-slate-500 font-medium shrink-0">Subject:</label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="Subject line"
                className="flex-1 focus:outline-none text-slate-800 font-medium"
              />
            </div>
          </div>

          {/* Files List */}
          {files.length > 0 && (
            <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 flex flex-wrap gap-2 text-xs">
              {files.map((file, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-1.5 px-2.5 py-1 bg-white border border-slate-200 rounded text-slate-700 shadow-2xs"
                >
                  <Paperclip className="w-3 h-3 text-slate-400" />
                  <span className="truncate max-w-[150px]">{file.name}</span>
                  <span className="text-[10px] text-slate-400">
                    ({(file.size / 1024).toFixed(1)} KB)
                  </span>
                  <button
                    type="button"
                    onClick={() => removeFile(idx)}
                    className="text-slate-400 hover:text-red-500 ml-1"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Body Editor */}
          <div className="flex-1 p-4 flex flex-col">
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Write your email here..."
              className="w-full flex-1 resize-none focus:outline-none text-xs text-slate-800 leading-relaxed font-sans"
            />
          </div>

          {/* Footer */}
          <div className="h-12 bg-slate-50 border-t border-slate-200 px-4 flex items-center justify-between select-none">
            <div className="flex items-center gap-2">
              <button
                type="submit"
                disabled={isSending}
                className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-700 hover:bg-blue-800 active:bg-blue-900 text-white rounded font-medium text-xs shadow-xs transition-colors disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{isSending ? 'Sending...' : 'Send'}</span>
              </button>

              <button
                type="button"
                onClick={handleSaveDraft}
                disabled={isSaving}
                className="px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-200 rounded font-medium transition-colors disabled:opacity-50"
              >
                {isSaving ? 'Saving...' : 'Save Draft'}
              </button>

              {/* Hidden file input */}
              <input
                ref={fileInputRef}
                type="file"
                multiple
                onChange={handleFileChange}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="p-1.5 text-slate-600 hover:text-slate-900 hover:bg-slate-200 rounded transition-colors"
                title="Attach files"
              >
                <Paperclip className="w-4 h-4" />
              </button>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-red-600 transition-colors"
              title="Discard draft"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
