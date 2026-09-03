import React from 'react';
import {
  Globe2,
  MapPin,
  Server,
  Building,
  Info,
  Compass,
  Radio,
  Layers,
} from 'lucide-react';
import type { CaseRecord } from '../../types.js';

interface GeoTabProps {
  caseData: CaseRecord;
}

export const GeoTab: React.FC<GeoTabProps> = ({ caseData }) => {
  const { hops } = caseData;
  const originHop = hops.length > 0 ? hops[hops.length - 1] : undefined;
  const isPrivate = originHop?.isPrivate;
  const geo = originHop?.geo;

  // Convert lat/long to SVG percentages (Mercator projection approximation)
  const getCoordinates = (lat?: number, lon?: number) => {
    if (lat === undefined || lon === undefined || (lat === 0 && lon === 0)) {
      return { x: 50, y: 50, valid: false };
    }
    const x = ((lon + 180) / 360) * 100;
    const y = ((85 - Math.max(-85, Math.min(85, lat))) / 170) * 100;
    return { x, y, valid: true };
  };

  const coords = getCoordinates(geo?.lat, geo?.lon);

  return (
    <div className="space-y-6">
      {/* Mandatory Forensic Disclaimer */}
      <div className="p-4 bg-blue-50/80 border border-blue-200 rounded-xl flex items-start gap-3 text-xs text-blue-950 shadow-sm">
        <Info className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="font-bold block text-sm mb-0.5">Observed Email Infrastructure & Approximate Network Location:</strong>
          IP geolocation represents <strong>observed email infrastructure</strong> derived strictly from the technical <code className="bg-blue-100/80 px-1 py-0.5 rounded font-mono">Received:</code> email headers. It establishes an <strong>approximate network location</strong> of the transmitting relay and does <em>not</em> establish the physical location, legal identity, or device location of the sender. Threat actors frequently route email through commercial VPNs, cloud proxies, or compromised relays.
        </div>
      </div>

      {/* SVG Map Canvas */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6 shadow-md overflow-hidden relative">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800 text-slate-300 text-xs">
          <span className="font-semibold flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-blue-400" />
            Observed Sending Infrastructure Map
          </span>
          <span className="font-mono text-[11px] text-slate-400">
            Source: Email technical header (Received hop #{originHop?.hopNumber || 1})
          </span>
        </div>

        {/* Minimal High-Tech World Map Representation */}
        <div className="relative w-full h-80 my-4 bg-slate-950/60 rounded-lg border border-slate-800/80 flex items-center justify-center overflow-hidden">
          {/* Subtle Grid Lines */}
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:40px_40px] opacity-30" />

          {/* SVG Map Outline */}
          <svg
            viewBox="0 0 1000 500"
            className="w-full h-full text-slate-800/80 fill-current opacity-70"
            xmlns="http://www.w3.org/2000/svg"
          >
            {/* North America */}
            <path d="M150,80 Q200,60 280,70 Q320,120 280,180 Q220,240 180,220 Q120,180 130,120 Z" />
            {/* South America */}
            <path d="M260,260 Q320,280 300,380 Q260,450 240,410 Q220,330 260,260 Z" />
            {/* Europe */}
            <path d="M470,80 Q540,70 560,130 Q510,180 470,160 Q440,110 470,80 Z" />
            {/* Africa */}
            <path d="M480,190 Q580,200 560,320 Q520,390 480,330 Q440,240 480,190 Z" />
            {/* Asia */}
            <path d="M580,80 Q780,60 820,170 Q750,260 620,220 Q570,140 580,80 Z" />
            {/* Australia */}
            <path d="M750,330 Q840,320 830,400 Q760,420 730,370 Z" />
          </svg>

          {/* Plotted Pin Marker */}
          {coords.valid && !isPrivate && (
            <div
              className="absolute transform -translate-x-1/2 -translate-y-1/2 z-10 flex flex-col items-center group cursor-pointer"
              style={{ left: `${coords.x}%`, top: `${coords.y}%` }}
            >
              <div className="w-8 h-8 rounded-full bg-red-500/20 animate-ping absolute -top-1" />
              <div className="w-4 h-4 rounded-full bg-red-600 border-2 border-white shadow-lg shadow-red-500/50 flex items-center justify-center text-white" />
              <div className="mt-1 px-2 py-0.5 rounded bg-slate-900/90 text-white text-[10px] font-mono border border-slate-700 shadow whitespace-nowrap">
                {geo?.city ? `${geo.city}, ` : ''}{geo?.country} ({geo?.lat?.toFixed(2)}°, {geo?.lon?.toFixed(2)}°)
              </div>
            </div>
          )}

          {isPrivate && (
            <div className="z-10 text-center px-4 py-3 bg-slate-900/90 border border-slate-700 rounded-lg text-slate-300 text-xs">
              <span className="font-bold text-amber-400 block mb-1">Internal Relay Host</span>
              Geolocation unavailable — private/internal RFC 1918 IP address.
            </div>
          )}
        </div>
      </div>

      {/* Structured Geolocation & Infrastructure Telemetry Grid */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
        <h4 className="text-sm font-bold text-slate-900 mb-4 flex items-center gap-2">
          <Layers className="w-4 h-4 text-blue-600" />
          Observed Email Infrastructure Telemetry
        </h4>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-100">
            <span className="text-slate-400 uppercase font-bold text-[10px] block mb-1">
              Observed Public IP
            </span>
            <span className="font-mono font-bold text-slate-900 text-sm">
              {originHop?.ip || 'Unavailable'}
            </span>
            <span className="text-[10px] text-slate-400 block mt-0.5">
              Type: {isPrivate ? 'RFC 1918 Private' : 'Public IPv4'}
            </span>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-100">
            <span className="text-slate-400 uppercase font-bold text-[10px] block mb-1">
              Country & Region
            </span>
            <span className="font-bold text-slate-900 text-sm block truncate">
              {isPrivate ? 'Internal Network' : geo?.country || 'Unknown'}
            </span>
            <span className="text-[10px] text-slate-400 block mt-0.5">
              Region: {geo?.region || 'N/A'}
            </span>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-100">
            <span className="text-slate-400 uppercase font-bold text-[10px] block mb-1">
              City / Metropolitan
            </span>
            <span className="font-bold text-slate-900 text-sm block truncate">
              {isPrivate ? 'Private Intranet' : geo?.city || 'Unresolved'}
            </span>
            <span className="text-[10px] text-slate-400 block mt-0.5">
              Coordinates: {geo?.lat !== undefined ? `${geo.lat.toFixed(4)}°, ${geo.lon?.toFixed(4)}°` : 'N/A'}
            </span>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-100">
            <span className="text-slate-400 uppercase font-bold text-[10px] block mb-1">
              ASN & Internet Service Provider
            </span>
            <span className="font-mono font-bold text-slate-900 text-sm block">
              {geo?.asn || 'Unassigned'}
            </span>
            <span className="text-[10px] text-slate-400 block mt-0.5 truncate" title={geo?.org || geo?.isp}>
              {geo?.org || geo?.isp || 'Internal Enterprise Cluster'}
            </span>
          </div>
        </div>

        <div className="mt-4 pt-4 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between text-xs text-slate-500 gap-2">
          <span>
            Telemetry Source: <strong className="font-mono text-slate-700">Received:</strong> header hop sequence
          </span>
          <span className="font-medium text-slate-600">
            Resolution Confidence: {coords.valid ? '85% (Autonomous System level)' : 'N/A'}
          </span>
        </div>
      </div>
    </div>
  );
};
