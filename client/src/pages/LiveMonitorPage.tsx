import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Radio,
  Play,
  CheckCircle,
  AlertTriangle,
  Server,
  RefreshCw,
  ExternalLink,
  Flame,
  ShieldCheck,
  Globe,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { ApiService } from '../services/api.js';
import type { ThreatClassification, RiskLevel } from '../types.js';
import { RiskBadge } from '../components/common/RiskBadge.js';

interface StreamEvent {
  caseId: string;
  caseNumber: string;
  subject: string;
  from: string;
  classification: ThreatClassification;
  riskScore: number;
  riskLevel: RiskLevel;
  originIp?: string;
  timestamp: string;
}

export const LiveMonitorPage: React.FC = () => {
  const navigate = useNavigate();
  const [connected, setConnected] = useState<boolean>(false);
  const [events, setEvents] = useState<StreamEvent[]>([]);

  // Connect to SSE stream
  useEffect(() => {
    let eventSource: EventSource | null = null;

    try {
      eventSource = new EventSource('/api/live-stream');

      eventSource.addEventListener('connected', () => {
        setConnected(true);
      });

      eventSource.addEventListener('email-analyzed', (e) => {
        try {
          const data: StreamEvent = JSON.parse(e.data);
          setEvents((prev) => [data, ...prev.slice(0, 49)]);
        } catch (err) {
          console.warn('Error parsing live-stream payload:', err);
        }
      });

      eventSource.addEventListener('ping', () => {
        setConnected(true);
      });

      eventSource.onerror = () => {
        setConnected(false);
      };
    } catch (err) {
      console.warn('Could not initialize SSE connection:', err);
      setConnected(false);
    }

    // Load initial cases so list isn't empty
    ApiService.getCases(undefined, undefined)
      .then((cases) => {
        const initialEvents: StreamEvent[] = cases.slice(0, 10).map((c) => ({
          caseId: c.id,
          caseNumber: c.caseNumber,
          subject: c.metadata.subject,
          from: c.metadata.from.address,
          classification: c.classification,
          riskScore: c.riskScore,
          riskLevel: c.riskLevel,
          originIp: c.hops[c.hops.length - 1]?.ip,
          timestamp: c.createdAt,
        }));
        setEvents(initialEvents);
      })
      .catch((err) => console.warn('Could not load initial stream cases:', err));

    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  }, []);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">Live Threat Monitor</h1>
            <div
              className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${
                connected
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                  : 'bg-red-50 text-red-800 border-red-200'
              }`}
            >
              {connected ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
                  <span className="w-2 h-2 rounded-full bg-emerald-500 -ml-3" />
                  <span>● Connected (SSE Stream Active)</span>
                </>
              ) : (
                <>
                  <WifiOff className="w-3.5 h-3.5" />
                  <span>Disconnected</span>
                </>
              )}
            </div>
          </div>
          <p className="text-xs text-[#68809F] mt-1">
            Real-time incoming telemetry stream observing mail transfer agent activity, automated rule triage, and payload verdicts.
          </p>
        </div>

        {/* Action Button */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => navigate('/analyze')}
            className="px-3.5 py-2 rounded-xl bg-[#246BFE] hover:bg-blue-700 text-white text-xs font-bold transition-colors inline-flex items-center gap-1.5 shadow-sm"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Analyze Email</span>
          </button>
        </div>
      </div>

      {/* Stream Metrics Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-5">
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Stream Status</span>
            <Radio className="w-4 h-4 text-[#246BFE]" />
          </div>
          <div className="text-xl font-bold text-[#0B1F3A] mt-2">Continuous Listening</div>
          <p className="text-[11px] text-[#68809F] mt-1">Server-Sent Events on /api/live-stream</p>
        </div>

        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Live Events Received</span>
            <Server className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-xl font-bold font-mono text-[#0B1F3A] mt-2">{events.length} Transmissions</div>
          <p className="text-[11px] text-[#68809F] mt-1">In-memory telemetry buffer</p>
        </div>

        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Automated Quarantined</span>
            <Flame className="w-4 h-4 text-red-600" />
          </div>
          <div className="text-xl font-bold font-mono text-[#EF4444] mt-2">
            {events.filter((e) => e.riskScore >= 55).length} High-Risk
          </div>
          <p className="text-[11px] text-[#68809F] mt-1">Score ≥ 55 automatically quarantined</p>
        </div>
      </div>

      {/* Stream Feed Table */}
      <div className="bg-white rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] overflow-hidden">
        <div className="p-4 bg-[#F7F9FC] border-b border-[#E5E9F2] flex items-center justify-between">
          <span className="text-xs font-bold text-[#0B1F3A] tracking-wide">
            Live Stream Feed
          </span>
          <span className="text-[11px] text-[#68809F]">Auto-scroll enabled • Live updates</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#E5E9F2] bg-[#F7F9FC] text-[#68809F] font-bold">
                <th className="py-3 px-4 uppercase text-[10px]">Timestamp</th>
                <th className="py-3 px-4 uppercase text-[10px]">Case ID</th>
                <th className="py-3 px-4 uppercase text-[10px]">Claimed Sender</th>
                <th className="py-3 px-4 uppercase text-[10px]">Subject</th>
                <th className="py-3 px-4 uppercase text-[10px]">Origin IP</th>
                <th className="py-3 px-4 uppercase text-[10px]">Verdict</th>
                <th className="py-3 px-4 uppercase text-[10px]">Score</th>
                <th className="py-3 px-4 uppercase text-[10px] text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E9F2]">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-xs text-[#68809F]">
                    No live stream events observed yet. Real-time telemetry will appear here as emails are analyzed.
                  </td>
                </tr>
              ) : (
                events.map((e, idx) => (
                  <tr
                    key={idx}
                    onClick={() => navigate(`/investigation/${e.caseId}`)}
                    className="hover:bg-[#F7F9FC] cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 text-[#68809F] whitespace-nowrap font-mono text-[11px]">
                      {new Date(e.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4 font-mono font-bold text-[#246BFE] whitespace-nowrap">
                      {e.caseNumber}
                    </td>
                    <td className="py-3 px-4 font-medium text-[#0B1F3A] max-w-[200px] truncate" title={e.from}>
                      {e.from}
                    </td>
                    <td className="py-3 px-4 text-[#0B1F3A] max-w-[260px] truncate font-medium" title={e.subject}>
                      {e.subject}
                    </td>
                    <td className="py-3 px-4 font-mono text-[#68809F]">
                      {e.originIp || 'Internal'}
                    </td>
                    <td className="py-3 px-4">
                      <RiskBadge score={e.riskScore} classification={e.classification} showScore={false} size="sm" />
                    </td>
                    <td className="py-3 px-4">
                      <span className="font-mono font-bold text-[#0B1F3A]">{e.riskScore}/100</span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <span className="text-xs font-bold text-[#246BFE] hover:underline inline-flex items-center gap-1">
                        View ➔
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
