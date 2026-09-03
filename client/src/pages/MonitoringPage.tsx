import React, { useEffect, useState } from 'react';
import {
  Activity,
  Server,
  Database,
  Cpu,
  Globe,
  Radio,
  RefreshCw,
  CheckCircle2,
  Clock,
} from 'lucide-react';
import { ApiService } from '../services/api.js';

export const MonitoringPage: React.FC = () => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const loadMonitoring = async () => {
    try {
      setLoading(true);
      const res = await ApiService.getMonitoring();
      setData(res);
    } catch (err) {
      console.error('Failed to load system monitoring:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMonitoring();
    const timer = setInterval(loadMonitoring, 10000);
    return () => clearInterval(timer);
  }, []);

  const formatUptime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const hrs = Math.floor(mins / 60);
    if (hrs > 0) return `${hrs}h ${mins % 60}m`;
    return `${mins}m ${Math.floor(seconds % 60)}s`;
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">System Health & Telemetry</h1>
          <p className="text-xs text-[#68809F] mt-1">
            Real-time status of forensic ingestion pipelines, SQLite storage engine, and AI inference latency.
          </p>
        </div>
        <button
          onClick={loadMonitoring}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-slate-50 rounded-xl text-xs font-semibold shadow-2xs transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-[#246BFE]' : ''}`} />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* Main Status Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Engine State</span>
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          </div>
          <div className="text-2xl font-bold text-[#0B1F3A] mt-2 flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-600" />
            <span>{data?.status || 'HEALTHY'}</span>
          </div>
          <p className="text-[11px] text-[#68809F] mt-1">All subsystems operating nominally</p>
        </div>

        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Engine Uptime</span>
            <Clock className="w-4 h-4 text-[#246BFE]" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#0B1F3A] mt-2">
            {data ? formatUptime(data.uptimeSeconds) : '...'}
          </div>
          <p className="text-[11px] text-[#68809F] mt-1">Continuous daemon service</p>
        </div>

        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Memory Allocation</span>
            <Cpu className="w-4 h-4 text-purple-600" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#0B1F3A] mt-2">
            {data ? `${data.memoryUsageMB} MB` : '...'}
          </div>
          <p className="text-[11px] text-[#68809F] mt-1">Process RSS memory</p>
        </div>

        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Active SSE Clients</span>
            <Radio className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#0B1F3A] mt-2">
            {data ? data.sseClientsCount : 0} Live Listeners
          </div>
          <p className="text-[11px] text-[#68809F] mt-1">Real-time WebSocket/SSE subscribers</p>
        </div>
      </div>

      {/* Detailed Services Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Database */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-3">
          <div className="flex items-center gap-2.5 pb-3 border-b border-[#E5E9F2]">
            <Database className="w-4 h-4 text-[#246BFE]" />
            <h3 className="font-bold text-sm text-[#0B1F3A]">Database Storage Engine</h3>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-[#68809F]">Engine:</span>
              <span className="font-mono font-bold text-[#0B1F3A]">{data?.database?.engine || 'SQLite (node:sqlite)'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#68809F]">Total Stored Cases:</span>
              <span className="font-mono font-bold text-[#246BFE]">{data?.database?.totalCases ?? 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#68809F]">Persistence Path:</span>
              <span className="font-mono text-[#0B1F3A]">server/data/mailtrace.db</span>
            </div>
          </div>
        </div>

        {/* AI Threat Engine */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-3">
          <div className="flex items-center gap-2.5 pb-3 border-b border-[#E5E9F2]">
            <Cpu className="w-4 h-4 text-purple-600" />
            <h3 className="font-bold text-sm text-[#0B1F3A]">AI Synthesis Engine</h3>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-[#68809F]">Model:</span>
              <span className="font-bold text-[#0B1F3A]">{data?.aiEngine?.provider}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#68809F]">Operational Mode:</span>
              <span className="font-mono font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded">
                {data?.aiEngine?.mode}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#68809F]">Grounding Enforcement:</span>
              <span className="text-emerald-600 font-bold">Strict Evidence Only</span>
            </div>
          </div>
        </div>

        {/* GeoIP Provider */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-3">
          <div className="flex items-center gap-2.5 pb-3 border-b border-[#E5E9F2]">
            <Globe className="w-4 h-4 text-emerald-600" />
            <h3 className="font-bold text-sm text-[#0B1F3A]">Geolocation Provider</h3>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-[#68809F]">Upstream Provider:</span>
              <span className="font-bold text-[#0B1F3A]">ip-api.com API</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#68809F]">Local Cache:</span>
              <span className="font-bold text-emerald-600">Active (SQLite geo_locations)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#68809F]">Private IP Filter:</span>
              <span className="font-bold text-[#0B1F3A]">RFC 1918 Enforced</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
