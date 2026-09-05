import React from 'react';
import {
  Network,
  ArrowDown,
  Server,
  MapPin,
  Clock,
  ShieldAlert,
  Globe,
  Lock,
} from 'lucide-react';
import type { CaseRecord } from '../../types.js';

interface RouteTabProps {
  caseData: CaseRecord;
}

export const RouteTab: React.FC<RouteTabProps> = ({ caseData }) => {
  const { hops } = caseData;

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-100 gap-2">
          <div>
            <h4 className="text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
              <Network className="w-4 h-4 text-blue-600" />
              Email Transport Route Hops ({hops.length})
            </h4>
            <p className="text-xs text-slate-500 mt-0.5">
              Reconstructed in chronological order from transmission origin to destination delivery mail exchanger.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500 bg-slate-50 px-3 py-1 rounded border border-slate-200 self-start sm:self-auto">
            Public Origin Relay: Hop #{hops.find((h) => h.isPublicOriginRelay)?.hopNumber || 1}
          </span>
        </div>

        {hops.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-xs">
            No RFC 822 / RFC 5322 Received hop headers were found in this message.
          </div>
        ) : (
          <div className="mt-8 relative pl-6 sm:pl-8 space-y-8">
            {/* Connecting Vertical Line */}
            <div className="absolute left-[19px] sm:left-[27px] top-6 bottom-6 w-0.5 bg-blue-200" />

            {hops.map((hop, idx) => {
              const isFirstHop = idx === 0;
              const isPublicOrigin = Boolean(hop.isPublicOriginRelay);
              const isFinalMx = idx === hops.length - 1 && hops.length > 1;
              const isTor = hop.geo?.org?.toLowerCase().includes('tor') || hop.geo?.org?.toLowerCase().includes('relay');

              return (
                <div key={idx} className="relative group">
                  {/* Timeline Bullet Node */}
                  <div
                    className={`absolute -left-6 sm:-left-8 top-1.5 w-6 h-6 rounded-full border-2 flex items-center justify-center text-[10px] font-bold z-10 transition-transform ${
                      isPublicOrigin
                        ? 'bg-blue-600 border-blue-200 text-white shadow-md shadow-blue-500/20 ring-4 ring-blue-50'
                        : isFirstHop
                        ? 'bg-slate-800 border-slate-200 text-white shadow-sm'
                        : 'bg-white border-blue-600 text-blue-600'
                    }`}
                  >
                    {hop.hopNumber}
                  </div>

                  {/* Hop Card */}
                  <div
                    className={`p-5 rounded-xl border transition-all ${
                      isPublicOrigin
                        ? 'bg-gradient-to-r from-blue-50/40 via-white to-white border-blue-300 shadow-sm ring-1 ring-blue-100'
                        : 'bg-white border-slate-200 shadow-sm hover:border-slate-300'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-100">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-xs text-slate-900 font-mono">
                          Hop #{hop.hopNumber}
                        </span>
                        {isPublicOrigin && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-extrabold tracking-wider bg-blue-600 text-white uppercase">
                            Observed Public Origin Relay
                          </span>
                        )}
                        {isFirstHop && !isPublicOrigin && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider bg-slate-800 text-white uppercase">
                            Initial Transmission Hop
                          </span>
                        )}
                        {isFinalMx && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider bg-slate-600 text-white uppercase">
                            Destination MX Relay
                          </span>
                        )}
                        {hop.isPrivate && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-600 border border-slate-200">
                            RFC 1918 Private IP
                          </span>
                        )}
                        {isTor && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-extrabold tracking-wider bg-amber-600 text-white uppercase flex items-center gap-1">
                            <ShieldAlert className="w-3 h-3" /> Tor Anonymizer
                          </span>
                        )}
                      </div>

                      {hop.timestamp && (
                        <span className="text-[11px] text-slate-400 font-mono flex items-center gap-1">
                          <Clock className="w-3 h-3 text-slate-400" />
                          {new Date(hop.timestamp).toUTCString()}
                        </span>
                      )}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 text-xs font-mono">
                      <div>
                        <span className="text-slate-400 font-sans block text-[10px] uppercase font-bold">
                          Transmitted From Host
                        </span>
                        <span className="text-slate-800 break-all">{hop.from || 'Not Stated'}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 font-sans block text-[10px] uppercase font-bold">
                          Received By Relay
                        </span>
                        <span className="text-slate-800 break-all">{hop.by || 'Not Stated'}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 font-sans block text-[10px] uppercase font-bold">
                          Observed IP Address
                        </span>
                        <span className="text-blue-600 font-bold break-all">{hop.ip || 'Unavailable'}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 font-sans block text-[10px] uppercase font-bold">
                          Geographic & ASN Infrastructure
                        </span>
                        <span className="text-slate-700 font-sans break-all">
                          {hop.isPrivate ? (
                            <span className="text-amber-700 font-medium">
                              Location unavailable — private/internal IP
                            </span>
                          ) : (hop.geoAvailable || hop.geo?.geoAvailable || hop.geo?.lookupStatus === 'resolved' || hop.lookupStatus === 'resolved') ? (
                            <span className="flex items-center gap-1.5">
                              <MapPin className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
                              {(hop.geo?.city || hop.city) ? `${hop.geo?.city || hop.city}, ` : ''}{hop.geo?.country || hop.country}
                              {(hop.geo?.asn || hop.asn) && <span className="font-mono text-slate-500">({hop.geo?.asn || hop.asn})</span>}
                            </span>
                          ) : (
                            <span className="text-slate-500">
                              Location unavailable — GeoIP lookup unavailable
                            </span>
                          )}
                        </span>
                      </div>
                    </div>
                  </div>

                  {idx < hops.length - 1 && (
                    <div className="flex justify-center my-1.5 opacity-60">
                      <ArrowDown className="w-4 h-4 text-blue-400" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
