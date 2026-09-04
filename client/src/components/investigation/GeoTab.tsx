import React, { useState, useEffect } from 'react';
import {
  Globe2,
  MapPin,
  Server,
  Building,
  Info,
  Compass,
  Radio,
  Layers,
  Network,
  CheckCircle2,
} from 'lucide-react';
import type { CaseRecord, RouteHop } from '../../types.js';

interface GeoTabProps {
  caseData: CaseRecord;
}

export const GeoTab: React.FC<GeoTabProps> = ({ caseData }) => {
  const { hops, observedOriginRelay } = caseData;

  // Identify default origin hop index
  const getDefaultIndex = (): number => {
    if (!hops || hops.length === 0) return 0;
    if (observedOriginRelay) {
      const idx = hops.findIndex((h) => h.hopNumber === observedOriginRelay.hopNumber || (h.ip && h.ip === observedOriginRelay.ip));
      if (idx !== -1) return idx;
    }
    const publicIdx = hops.findIndex((h) => h.ip && !h.isPrivate);
    if (publicIdx !== -1) return publicIdx;
    return 0;
  };

  const [selectedHopIndex, setSelectedHopIndex] = useState<number>(getDefaultIndex);

  // Reset selected hop whenever caseData changes
  useEffect(() => {
    setSelectedHopIndex(getDefaultIndex());
  }, [caseData.id, caseData.caseNumber]);

  const activeHop: RouteHop | undefined = (hops && hops[selectedHopIndex]) || observedOriginRelay || (hops && hops[0]);
  const isPrivate = Boolean(activeHop?.isPrivate);
  const geo = activeHop?.geo;
  const lookupStatus = geo?.lookupStatus || (isPrivate ? 'private_ip' : 'unavailable');

  // Convert lat/long to SVG percentages (Mercator projection approximation)
  const getCoordinates = (lat?: number, lon?: number) => {
    if (lat === undefined || lon === undefined || (lat === 0 && lon === 0) || isNaN(lat) || isNaN(lon)) {
      return { x: 50, y: 50, valid: false };
    }
    const x = ((lon + 180) / 360) * 100;
    const y = ((85 - Math.max(-85, Math.min(85, lat))) / 170) * 100;
    return { x, y, valid: true };
  };

  const coords = getCoordinates(geo?.lat, geo?.lon);
  const hasGenuinePin = coords.valid && !isPrivate && (lookupStatus === 'resolved' || Boolean(geo?.lat && geo?.lon));

  // Extract all hops with valid coordinates for route mapping
  const plottableHops = (hops || [])
    .map((h, idx) => ({
      hop: h,
      idx,
      coords: getCoordinates(h.geo?.lat, h.geo?.lon),
    }))
    .filter((item) => item.coords.valid && !item.hop.isPrivate);

  return (
    <div className="space-y-6">
      {/* Mandatory Forensic Disclaimer */}
      <div className="p-4 bg-blue-50/80 border border-blue-200 rounded-xl flex items-start gap-3 text-xs text-blue-950 shadow-sm">
        <Info className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="font-bold block text-sm mb-0.5">Observed Email Infrastructure & Approximate Network Location:</strong>
          IP geolocation represents <strong>observed infrastructure</strong> and does <strong>not</strong> establish the physical location or identity of the sender. Transmitting relays are derived strictly from RFC 5322 <code className="bg-blue-100/80 px-1 py-0.5 rounded font-mono">Received:</code> technical headers.
        </div>
      </div>

      {/* Interactive Hop Selector Bar */}
      {hops && hops.length > 0 && (
        <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-700 flex items-center gap-1.5">
              <Network className="w-4 h-4 text-blue-600" />
              Transport Route Hop Selector ({hops.length} Hops Analyzed):
            </span>
            <span className="text-[11px] text-slate-500">
              Click any hop to inspect its specific geographic location
            </span>
          </div>

          <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin">
            {hops.map((hop, idx) => {
              const isSelected = idx === selectedHopIndex;
              const isPublicRelay = hop.isPublicOriginRelay;
              const hasGeo = Boolean(hop.geo?.country && !hop.isPrivate && hop.geo?.lat);

              return (
                <button
                  key={hop.hopNumber || idx}
                  onClick={() => setSelectedHopIndex(idx)}
                  className={`px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-2 transition-all whitespace-nowrap border ${
                    isSelected
                      ? 'bg-blue-600 text-white border-blue-600 shadow-sm'
                      : 'bg-slate-50 text-slate-700 border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  <span className={`font-mono font-bold px-1.5 py-0.5 rounded text-[10px] ${isSelected ? 'bg-blue-700 text-white' : 'bg-slate-200 text-slate-800'}`}>
                    #{hop.hopNumber}
                  </span>
                  <span className="font-mono text-[11px] font-bold">
                    {hop.ip || 'No IP'}
                  </span>
                  {isPublicRelay && (
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${isSelected ? 'bg-amber-400 text-slate-900' : 'bg-blue-100 text-blue-800'}`}>
                      Origin Relay
                    </span>
                  )}
                  {hop.isPrivate ? (
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${isSelected ? 'bg-blue-800 text-blue-200' : 'bg-slate-200 text-slate-600'}`}>
                      Private
                    </span>
                  ) : hasGeo ? (
                    <span className={`text-[10px] flex items-center gap-1 ${isSelected ? 'text-blue-100' : 'text-emerald-700 font-semibold'}`}>
                      <MapPin className="w-2.5 h-2.5" />
                      {hop.geo?.countryCode || hop.geo?.country}
                    </span>
                  ) : null}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* SVG Map Canvas */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6 shadow-md overflow-hidden relative">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800 text-slate-300 text-xs">
          <span className="font-semibold flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-blue-400" />
            Observed Geographic Route & Relay Map
          </span>
          <span className="font-mono text-[11px] text-slate-400">
            Active: Hop #{activeHop?.hopNumber || 1} ({activeHop?.ip || 'No IP'}) {activeHop?.isPublicOriginRelay ? '— [Observed Public Origin Relay]' : ''}
          </span>
        </div>

        {/* High-Tech World Map Representation */}
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

            {/* Connecting Flight Route Lines Between Plottable Public Hops */}
            {plottableHops.length > 1 && (
              <polyline
                fill="none"
                stroke="#3B82F6"
                strokeWidth="2"
                strokeDasharray="4 4"
                className="opacity-75"
                points={plottableHops.map((p) => `${p.coords.x * 10},${p.coords.y * 5}`).join(' ')}
              />
            )}
          </svg>

          {/* Secondary Inactive Plottable Markers */}
          {plottableHops.map(({ hop, idx, coords: pCoords }) => {
            if (idx === selectedHopIndex) return null; // Rendered below with active styling
            return (
              <div
                key={hop.hopNumber || idx}
                onClick={() => setSelectedHopIndex(idx)}
                className="absolute transform -translate-x-1/2 -translate-y-1/2 z-10 flex flex-col items-center group cursor-pointer"
                style={{ left: `${pCoords.x}%`, top: `${pCoords.y}%` }}
                title={`Hop #${hop.hopNumber}: ${hop.ip} (${hop.geo?.city || hop.geo?.country})`}
              >
                <div className="w-3 h-3 rounded-full bg-blue-500 border-2 border-white shadow hover:scale-125 transition-transform" />
                <div className="hidden group-hover:block mt-1 px-1.5 py-0.5 rounded bg-slate-900/90 text-white text-[9px] font-mono whitespace-nowrap z-20 border border-slate-700">
                  Hop #{hop.hopNumber}: {hop.geo?.country}
                </div>
              </div>
            );
          })}

          {/* Primary Selected Pin Marker */}
          {hasGenuinePin && (
            <div
              className="absolute transform -translate-x-1/2 -translate-y-1/2 z-20 flex flex-col items-center group cursor-pointer"
              style={{ left: `${coords.x}%`, top: `${coords.y}%` }}
            >
              <div className="w-8 h-8 rounded-full bg-red-500/20 animate-ping absolute -top-1" />
              <div className="w-4 h-4 rounded-full bg-red-600 border-2 border-white shadow-lg shadow-red-500/50 flex items-center justify-center text-white" />
              <div className="mt-1 px-2.5 py-1 rounded bg-slate-900/95 text-white text-[11px] font-mono border border-slate-700 shadow-lg whitespace-nowrap flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-red-500" />
                <strong>Hop #{activeHop?.hopNumber}:</strong> {geo?.city ? `${geo.city}, ` : ''}{geo?.country} ({geo?.lat?.toFixed(2)}°, {geo?.lon?.toFixed(2)}°)
              </div>
            </div>
          )}

          {/* Explicit Status Banners When Selected Pin Cannot Be Plotted */}
          {isPrivate && (
            <div className="z-10 text-center px-4 py-3 bg-slate-900/90 border border-slate-700 rounded-lg text-slate-300 text-xs max-w-sm">
              <span className="font-bold text-amber-400 block mb-1">Internal / Private Infrastructure</span>
              Geolocation unavailable — private/internal IP ({activeHop?.ip || 'RFC 1918'}).
            </div>
          )}

          {!isPrivate && lookupStatus === 'rate_limited' && (
            <div className="z-10 text-center px-4 py-3 bg-slate-900/90 border border-amber-700/80 rounded-lg text-amber-200 text-xs max-w-sm">
              <span className="font-bold text-amber-400 block mb-1">Rate Limit Exceeded</span>
              GeoIP service rate limited.
            </div>
          )}

          {!isPrivate && lookupStatus === 'timeout' && (
            <div className="z-10 text-center px-4 py-3 bg-slate-900/90 border border-slate-700 rounded-lg text-slate-300 text-xs max-w-sm">
              <span className="font-bold text-amber-400 block mb-1">Lookup Timed Out</span>
              Location lookup timed out.
            </div>
          )}

          {!isPrivate && lookupStatus === 'lookup_failed' && (
            <div className="z-10 text-center px-4 py-3 bg-slate-900/90 border border-slate-700 rounded-lg text-slate-300 text-xs max-w-sm">
              <span className="font-bold text-slate-400 block mb-1">Lookup Unavailable</span>
              Location lookup unavailable.
            </div>
          )}

          {(!activeHop || !activeHop.ip) && (
            <div className="z-10 text-center px-4 py-3 bg-slate-900/90 border border-slate-700 rounded-lg text-slate-300 text-xs max-w-sm">
              <span className="font-bold text-slate-400 block mb-1">No Transport IP</span>
              No routable IPs found in transport headers.
            </div>
          )}
        </div>
      </div>

      {/* Structured Geolocation & Infrastructure Telemetry Grid */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-600" />
            Observed Infrastructure Telemetry — Hop #{activeHop?.hopNumber || 1}
          </h4>
          {activeHop?.isPublicOriginRelay && (
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-blue-100 text-blue-800 border border-blue-200 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-blue-600" />
              Observed Public Origin Relay
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-100">
            <span className="text-slate-400 uppercase font-bold text-[10px] block mb-1">
              Observed IP
            </span>
            <span className="font-mono font-bold text-slate-900 text-sm">
              {activeHop?.ip || 'Unavailable'}
            </span>
            <span className="text-[10px] text-slate-400 block mt-0.5">
              Type: {isPrivate ? 'RFC 1918 Private' : (activeHop?.ipType || 'Public IP')}
            </span>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-100">
            <span className="text-slate-400 uppercase font-bold text-[10px] block mb-1">
              Country & Region
            </span>
            <span className="font-bold text-slate-900 text-sm block truncate">
              {isPrivate ? 'Internal Network' : (geo?.country || activeHop?.country || 'Unavailable')}
            </span>
            <span className="text-[10px] text-slate-400 block mt-0.5">
              Region: {isPrivate ? 'Internal Subnet' : (geo?.region || activeHop?.region || 'N/A')}
            </span>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-100">
            <span className="text-slate-400 uppercase font-bold text-[10px] block mb-1">
              City / Metropolitan
            </span>
            <span className="font-bold text-slate-900 text-sm block truncate">
              {isPrivate ? 'Private Intranet' : (geo?.city || activeHop?.city || 'Unresolved')}
            </span>
            <span className="text-[10px] text-slate-400 block mt-0.5">
              Coordinates: {hasGenuinePin && (geo?.lat !== undefined || activeHop?.lat !== undefined) ? `${(geo?.lat ?? activeHop?.lat)?.toFixed(4)}°, ${(geo?.lon ?? activeHop?.lon)?.toFixed(4)}°` : 'N/A'}
            </span>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-100">
            <span className="text-slate-400 uppercase font-bold text-[10px] block mb-1">
              ASN & Internet Service Provider
            </span>
            <span className="font-mono font-bold text-slate-900 text-sm block">
              {geo?.asn || activeHop?.asn || (isPrivate ? 'RFC1918' : 'Unassigned')}
            </span>
            <span className="text-[10px] text-slate-400 block mt-0.5 truncate" title={geo?.org || geo?.isp || activeHop?.org}>
              {geo?.org || geo?.isp || activeHop?.org || (isPrivate ? 'Internal Enterprise Cluster' : 'Unavailable')}
            </span>
          </div>
        </div>

        <div className="mt-4 pt-4 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between text-xs text-slate-500 gap-2">
          <span>
            Telemetry Source: <strong className="font-mono text-slate-700">Received:</strong> header hop sequence
          </span>
          <span className="font-medium text-slate-600">
            Lookup Status: <strong className="font-semibold text-slate-800">{geo?.statusMessage || (lookupStatus === 'resolved' ? 'Resolved' : lookupStatus === 'private_ip' ? 'Private / Internal IP' : 'Unavailable')}</strong>
          </span>
        </div>
      </div>
    </div>
  );
};
