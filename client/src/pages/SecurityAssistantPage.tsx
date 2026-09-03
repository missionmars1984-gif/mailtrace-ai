import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bot,
  Send,
  Sparkles,
  HelpCircle,
  RefreshCw,
  FolderArchive,
  ExternalLink,
  ShieldAlert,
} from 'lucide-react';
import { ApiService } from '../services/api.js';
import type { CaseRecord, AssistantMessage } from '../types.js';

export const SecurityAssistantPage: React.FC = () => {
  const navigate = useNavigate();
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedCase, setSelectedCase] = useState<CaseRecord | null>(null);
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant'; content: string; time: string }>>([
    {
      role: 'assistant',
      content:
        'Welcome to the dedicated MailTrace AI Security Assistant console. I am grounded in verifiable email MIME headers, SPF/DKIM/DMARC alignment results, and observed GeoIP infrastructure. Select an active investigation case below to begin forensic questioning.',
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [inputQuery, setInputQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    ApiService.getCases().then((list) => {
      setCases(list);
      if (list.length > 0) setSelectedCase(list[0]);
    });
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async (queryText?: string) => {
    const text = queryText || inputQuery;
    if (!text.trim() || loading) return;

    const userMsg = {
      role: 'user' as const,
      content: text.trim(),
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setLoading(true);

    try {
      const res = await ApiService.askAssistant(text.trim(), selectedCase?.id);
      const assistantMsg = {
        role: 'assistant' as const,
        content: res.answer,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant' as const,
          content: `Assistant Error: ${err.message || 'Service unavailable.'}`,
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
    'What is the observed IP?',
    'Where does the infrastructure geolocate?',
    'Why is the identity inconsistent?',
    'Explain the SPF result.',
    'Summarize this case.',
    'What indicators should I investigate?',
  ];

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">SOC AI Security Assistant</h1>
          <p className="text-xs text-[#68809F] mt-1">
            Grounded forensic questioning agent trained on RFC822 transport headers, cryptographic authentication, and attack heuristics.
          </p>
        </div>
        {selectedCase && (
          <button
            onClick={() => navigate(`/investigation/${selectedCase.id}`)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#246BFE] text-[#246BFE] hover:bg-[#EEF4FF] rounded-xl text-xs font-bold transition-colors self-start sm:self-auto"
          >
            <span>Open Case {selectedCase.caseNumber}</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left Column: Context Card & Selector */}
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-white p-5 rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-3">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider block">
              Active Investigation Context
            </span>
            <select
              value={selectedCase?.id || ''}
              onChange={(e) => {
                const found = cases.find((c) => c.id === e.target.value);
                if (found) setSelectedCase(found);
              }}
              className="w-full p-2.5 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2] text-xs font-mono text-[#0B1F3A] focus:outline-none focus:ring-2 focus:ring-[#246BFE]/30"
            >
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.caseNumber} - {c.classification} ({c.riskScore})
                </option>
              ))}
            </select>

            {selectedCase && (
              <div className="pt-3 border-t border-[#E5E9F2] space-y-2 text-xs">
                <div>
                  <span className="text-[#68809F] block text-[10px] uppercase font-bold">Subject</span>
                  <span className="font-medium text-[#0B1F3A] line-clamp-2">{selectedCase.metadata.subject}</span>
                </div>
                <div>
                  <span className="text-[#68809F] block text-[10px] uppercase font-bold">Claimed From</span>
                  <span className="font-mono text-[#0B1F3A] truncate block">{selectedCase.metadata.from.address}</span>
                </div>
                <div>
                  <span className="text-[#68809F] block text-[10px] uppercase font-bold">Verdict & Score</span>
                  <span className="font-bold text-[#246BFE]">{selectedCase.classification} ({selectedCase.riskScore}/100)</span>
                </div>
              </div>
            )}
          </div>

          {/* Quick Prompts Panel */}
          <div className="bg-white p-5 rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-2.5">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider block">
              Suggested Forensic Questions
            </span>
            <div className="space-y-1.5">
              {suggestedQuestions.map((q) => (
                <button
                  key={q}
                  onClick={() => handleSend(q)}
                  className="w-full text-left p-2 rounded-lg bg-[#F7F9FC] hover:bg-[#EEF4FF] hover:text-[#246BFE] text-xs text-[#0B1F3A] transition-colors border border-transparent hover:border-[#246BFE]/30"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Chat Window */}
        <div className="lg:col-span-3 bg-white rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] flex flex-col h-[650px] overflow-hidden">
          {/* Chat Header */}
          <div className="p-4 bg-[#F7F9FC] border-b border-[#E5E9F2] flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-[#246BFE] text-white flex items-center justify-center">
                <Bot className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-[#0B1F3A]">Security Operations Assistant</h3>
                <span className="text-[10px] text-emerald-600 font-medium">Ready • Grounded Evidence Mode</span>
              </div>
            </div>
            <span className="text-xs font-mono text-[#68809F]">
              {selectedCase ? selectedCase.caseNumber : 'No Case Selected'}
            </span>
          </div>

          {/* Chat History */}
          <div className="flex-1 p-6 overflow-y-auto space-y-4">
            {messages.map((m, idx) => (
              <div
                key={idx}
                className={`flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'}`}
              >
                <div
                  className={`max-w-[85%] rounded-2xl p-4 text-xs leading-relaxed ${
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
              <div className="flex items-center space-x-2 text-xs text-[#68809F] p-3 bg-[#F7F9FC] rounded-xl w-fit border border-[#E5E9F2]">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#246BFE]" />
                <span>Evaluating RFC822 evidence & crafting response...</span>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Input Bar */}
          <div className="p-4 bg-[#F7F9FC] border-t border-[#E5E9F2]">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSend();
              }}
              className="flex items-center gap-2"
            >
              <input
                type="text"
                value={inputQuery}
                onChange={(e) => setInputQuery(e.target.value)}
                placeholder="Ask about SPF records, sending IP, lookalike domain, or why flagged..."
                className="flex-1 px-4 py-2.5 rounded-xl bg-white border border-[#E5E9F2] text-xs text-[#0B1F3A] placeholder-[#68809F] focus:outline-none focus:ring-2 focus:ring-[#246BFE]/30 focus:border-[#246BFE]"
              />
              <button
                type="submit"
                disabled={!inputQuery.trim() || loading}
                className="p-2.5 rounded-xl bg-[#246BFE] hover:bg-blue-700 text-white disabled:opacity-40 transition-colors shadow-xs"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};
