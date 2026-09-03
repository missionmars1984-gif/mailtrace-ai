import React, { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Bot,
  X,
  Send,
  Sparkles,
  RefreshCw,
  HelpCircle,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import { ApiService } from '../../services/api.js';
import type { CaseRecord } from '../../types.js';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  time: string;
}

export const FloatingAssistant: React.FC = () => {
  const location = useLocation();
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content:
        'Hello Analyst. I am the MailTrace SOC AI Assistant, grounded in case telemetry, RFC822 headers, and observed GeoIP infrastructure. How can I assist your investigation?',
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeCase, setActiveCase] = useState<CaseRecord | null>(null);
  const [casesList, setCasesList] = useState<CaseRecord[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Determine active case from URL or latest case
  useEffect(() => {
    const loadContext = async () => {
      try {
        const cases = await ApiService.getCases();
        setCasesList(cases);

        // Check if on /investigation/:id
        const match = location.pathname.match(/\/investigation\/([^/]+)/);
        if (match && match[1]) {
          const found = cases.find((c) => c.id === match[1] || c.caseNumber === match[1]);
          if (found) {
            setActiveCase(found);
            return;
          }
        }

        if (cases.length > 0 && !activeCase) {
          setActiveCase(cases[0]);
        }
      } catch (err) {
        console.warn('Could not load case context for assistant:', err);
      }
    };

    loadContext();
  }, [location.pathname]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async (queryText?: string) => {
    const text = queryText || inputQuery;
    if (!text.trim() || loading) return;

    const userMsg: Message = {
      role: 'user',
      content: text.trim(),
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setLoading(true);

    try {
      const res = await ApiService.askAssistant(text.trim(), activeCase?.id);
      const assistantMsg: Message = {
        role: 'assistant',
        content: res.answer,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `Assistant Error: ${err.message || 'Could not process query.'}`,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const suggestedQuestions = [
    'Why was this email flagged?',
    'Why is the risk score high?',
    'Where does the infrastructure geolocate?',
    'Why is the identity inconsistent?',
    'Explain the SPF result.',
    'Summarize this case.',
  ];

  return (
    <>
      {/* Floating Pill Trigger */}
      <div className="fixed bottom-6 right-6 z-40">
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center space-x-2.5 px-4 py-3 bg-[#0B1F3A] hover:bg-[#122A4E] text-white rounded-full shadow-lg shadow-navy-900/30 border border-slate-700/50 transition-all transform hover:scale-105"
        >
          <div className="w-6 h-6 rounded-full bg-[#246BFE] flex items-center justify-center text-white">
            <Bot className="w-3.5 h-3.5" />
          </div>
          <span className="text-xs font-bold tracking-wide">SOC AI Assistant</span>
          {activeCase && (
            <span className="text-[10px] font-mono bg-blue-900/80 text-blue-200 px-2 py-0.5 rounded-full border border-blue-700/60">
              {activeCase.caseNumber}
            </span>
          )}
        </button>
      </div>

      {/* Slide-Over Drawer */}
      {isOpen && (
        <div className="fixed inset-y-0 right-0 w-full max-w-md bg-white shadow-2xl z-50 flex flex-col border-l border-[#E5E9F2] animate-in slide-in-from-right duration-200">
          {/* Header */}
          <div className="p-4 border-b border-[#E5E9F2] bg-[#F7F9FC] flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="w-8 h-8 rounded-xl bg-[#246BFE] flex items-center justify-center text-white shadow-xs">
                <Bot className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-[#0B1F3A]">SOC AI Assistant</h3>
                <span className="text-[10px] text-[#68809F] font-mono flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                  Grounded Evidence Model
                </span>
              </div>
            </div>

            <button
              onClick={() => setIsOpen(false)}
              className="p-1.5 rounded-lg text-[#68809F] hover:bg-slate-200/60 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Context Selector */}
          <div className="px-4 py-2.5 bg-white border-b border-[#E5E9F2] flex items-center justify-between text-xs">
            <span className="text-[#68809F] font-medium text-[11px]">Active Investigation:</span>
            <select
              value={activeCase?.id || ''}
              onChange={(e) => {
                const found = casesList.find((c) => c.id === e.target.value);
                if (found) setActiveCase(found);
              }}
              className="px-2 py-1 rounded bg-[#F7F9FC] border border-[#E5E9F2] text-[11px] font-mono text-[#0B1F3A] max-w-[200px] truncate focus:outline-none"
            >
              {casesList.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.caseNumber} - {c.classification} ({c.riskScore})
                </option>
              ))}
            </select>
          </div>

          {/* Quick Prompts */}
          <div className="px-4 py-2 bg-[#F7F9FC]/60 border-b border-[#E5E9F2] flex items-center gap-1.5 overflow-x-auto text-[11px]">
            {suggestedQuestions.slice(0, 3).map((sq) => (
              <button
                key={sq}
                onClick={() => handleSend(sq)}
                className="whitespace-nowrap px-2.5 py-1 rounded-lg bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-[#EEF4FF] hover:border-[#246BFE]/40 hover:text-[#246BFE] transition-colors font-medium text-[10px]"
              >
                {sq}
              </button>
            ))}
          </div>

          {/* Messages Area */}
          <div className="flex-1 p-4 overflow-y-auto space-y-3.5 bg-white">
            {messages.map((m, idx) => (
              <div
                key={idx}
                className={`flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'}`}
              >
                <div
                  className={`max-w-[85%] rounded-2xl px-3.5 py-2.5 text-xs leading-relaxed ${
                    m.role === 'user'
                      ? 'bg-[#246BFE] text-white rounded-br-none shadow-sm'
                      : 'bg-[#F7F9FC] text-[#0B1F3A] border border-[#E5E9F2] rounded-bl-none'
                  }`}
                >
                  <div className="whitespace-pre-line">{m.content}</div>
                </div>
                <span className="text-[10px] text-[#68809F] mt-1 px-1 font-mono">{m.time}</span>
              </div>
            ))}
            {loading && (
              <div className="flex items-center space-x-2 text-xs text-[#68809F] p-2 bg-[#F7F9FC] rounded-lg w-fit border border-[#E5E9F2]">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#246BFE]" />
                <span>Grounding response in verified headers & findings...</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input Footer */}
          <div className="p-3 border-t border-[#E5E9F2] bg-[#F7F9FC]">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSend();
              }}
              className="flex items-center space-x-2"
            >
              <input
                type="text"
                value={inputQuery}
                onChange={(e) => setInputQuery(e.target.value)}
                placeholder={
                  activeCase
                    ? `Ask about ${activeCase.caseNumber}...`
                    : 'Ask about email threats, headers...'
                }
                className="flex-1 px-3.5 py-2 rounded-xl bg-white border border-[#E5E9F2] text-xs text-[#0B1F3A] placeholder-[#68809F] focus:outline-none focus:ring-2 focus:ring-[#246BFE]/30 focus:border-[#246BFE]"
              />
              <button
                type="submit"
                disabled={!inputQuery.trim() || loading}
                className="p-2.5 rounded-xl bg-[#246BFE] hover:bg-blue-700 text-white disabled:opacity-40 transition-colors shadow-xs"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
};
