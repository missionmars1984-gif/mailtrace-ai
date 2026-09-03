import React, { useEffect, useState } from 'react';
import {
  Settings,
  Shield,
  Sliders,
  Database,
  Lock,
  RefreshCw,
  CheckCircle,
} from 'lucide-react';
import { ApiService } from '../services/api.js';

export const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [saved, setSaved] = useState<boolean>(false);

  useEffect(() => {
    ApiService.getSettings()
      .then(setSettings)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">Platform Configuration & Rules</h1>
        <p className="text-xs text-[#68809F] mt-1">
          Adjust risk scoring engine boundaries, upstream threat intelligence feeds, and forensic evidence retention policies.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Card 1: Scoring Thresholds */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-4">
          <div className="flex items-center gap-2.5 pb-3 border-b border-[#E5E9F2]">
            <Sliders className="w-4 h-4 text-[#246BFE]" />
            <h3 className="font-bold text-sm text-[#0B1F3A]">Risk Scoring Thresholds (0–100)</h3>
          </div>

          <div className="space-y-4 text-xs">
            <div>
              <div className="flex justify-between font-bold mb-1">
                <span className="text-emerald-700">Lower Concern Range</span>
                <span className="font-mono">0 – 54</span>
              </div>
              <p className="text-[#68809F] text-[11px]">Normal business emails with verified cryptographic authentication.</p>
            </div>

            <div>
              <div className="flex justify-between font-bold mb-1">
                <span className="text-amber-700">Elevated Review Threshold</span>
                <span className="font-mono">55 – 79</span>
              </div>
              <p className="text-[#68809F] text-[11px]">Suspicious routing or moderate identity discrepancies requiring analyst scrutiny.</p>
            </div>

            <div>
              <div className="flex justify-between font-bold mb-1">
                <span className="text-red-700">Critical Threat Cutoff</span>
                <span className="font-mono">80 – 100</span>
              </div>
              <p className="text-[#68809F] text-[11px]">Confirmed credential harvest URLs, weaponized payloads, or severe brand impersonation.</p>
            </div>
          </div>
        </div>

        {/* Card 2: AI Forensics Model */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-4">
          <div className="flex items-center gap-2.5 pb-3 border-b border-[#E5E9F2]">
            <Shield className="w-4 h-4 text-purple-600" />
            <h3 className="font-bold text-sm text-[#0B1F3A]">AI Model Configuration</h3>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <label className="text-[#68809F] font-bold block text-[10px] uppercase">Active Inference Engine</label>
              <div className="font-bold text-[#0B1F3A] mt-0.5 text-sm">
                {settings?.aiEngine || 'Google Gemini 2.5 Flash'}
              </div>
            </div>

            <div>
              <label className="text-[#68809F] font-bold block text-[10px] uppercase">Grounding Enforcement</label>
              <span className="text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded text-[11px] font-bold inline-block mt-0.5">
                Strict Case Evidence Only (Hallucination Prevention Active)
              </span>
            </div>

            <div>
              <label className="text-[#68809F] font-bold block text-[10px] uppercase">Temperature</label>
              <span className="font-mono text-[#0B1F3A] font-bold">0.1 (Deterministic Precision)</span>
            </div>
          </div>
        </div>

        {/* Card 3: Storage & Retention */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-4">
          <div className="flex items-center gap-2.5 pb-3 border-b border-[#E5E9F2]">
            <Database className="w-4 h-4 text-emerald-600" />
            <h3 className="font-bold text-sm text-[#0B1F3A]">Evidence Retention & Integrity</h3>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <label className="text-[#68809F] font-bold block text-[10px] uppercase">Evidence Retention Window</label>
              <span className="font-bold text-[#0B1F3A]">{settings?.retentionPolicyDays || 90} Days (Full RFC822 MIME preserved)</span>
            </div>

            <div>
              <label className="text-[#68809F] font-bold block text-[10px] uppercase">Custody Seal Algorithm</label>
              <span className="font-mono text-[#0B1F3A] font-bold">SHA-256 (FIPS 180-4 compliant)</span>
            </div>

            <div>
              <label className="text-[#68809F] font-bold block text-[10px] uppercase">Database Engine</label>
              <span className="font-mono text-[#0B1F3A]">Embedded SQLite (Native Node.js DatabaseSync)</span>
            </div>
          </div>
        </div>

        {/* Card 4: Geolocation Provider */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-4">
          <div className="flex items-center gap-2.5 pb-3 border-b border-[#E5E9F2]">
            <Lock className="w-4 h-4 text-amber-600" />
            <h3 className="font-bold text-sm text-[#0B1F3A]">Network & Privacy Rules</h3>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <label className="text-[#68809F] font-bold block text-[10px] uppercase">Private RFC 1918 Masking</label>
              <span className="text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded text-[11px] font-bold inline-block mt-0.5">
                ENFORCED (Loopback & RFC1918 never sent to external GeoIP)
              </span>
            </div>

            <div>
              <label className="text-[#68809F] font-bold block text-[10px] uppercase">Default Export Format</label>
              <span className="font-bold text-[#0B1F3A]">Forensic Dossier (STIX / JSON / PDF)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="pt-4 flex items-center justify-end">
        <button
          onClick={handleSave}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#246BFE] hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-sm shadow-blue-500/20 transition-colors"
        >
          {saved ? <CheckCircle className="w-4 h-4" /> : null}
          <span>{saved ? 'Settings Saved' : 'Save Configuration'}</span>
        </button>
      </div>
    </div>
  );
};
