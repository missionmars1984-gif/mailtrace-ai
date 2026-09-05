import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Globe,
  Radio,
  Server,
  Filter,
  ShieldAlert,
  ExternalLink,
  RefreshCw,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { ApiService } from '../services/api.js';
import type { ThreatMapData, ThreatMapNode } from '../types.js';
import L from 'leaflet';

export const ThreatMapPage: React.FC = () => {
  const navigate = useNavigate();
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const markersLayerRef = useRef<L.LayerGroup | null>(null);

  const [mapData, setMapData] = useState<ThreatMapData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedNode, setSelectedNode] = useState<ThreatMapNode | null>(null);

  const loadMapData = async () => {
    try {
      setLoading(true);
      const data = await ApiService.getThreatMap();
      setMapData(data);
    } catch (err) {
      console.error('Failed to load threat map data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMapData();

    // Listen to real-time email-analyzed events to auto-refresh map
    let eventSource: EventSource | null = null;
    try {
      const apiBase = ((import.meta as any).env?.VITE_API_URL || '').replace(/\/$/, '') + '/api';
      eventSource = new EventSource(`${apiBase}/live/stream`);
      eventSource.addEventListener('email-analyzed', () => {
        loadMapData();
      });
    } catch {}

    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  }, []);

  // Initialize Leaflet map
  useEffect(() => {
    if (!mapContainerRef.current) return;

    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    if ((mapContainerRef.current as any)._leaflet_id) {
      delete (mapContainerRef.current as any)._leaflet_id;
    }

    const map = L.map(mapContainerRef.current, {
      center: [20, 0],
      zoom: 2,
      minZoom: 2,
      maxZoom: 14,
      zoomControl: true,
    });

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      maxZoom: 18,
    }).addTo(map);

    const markersGroup = L.layerGroup().addTo(map);
    mapInstanceRef.current = map;
    markersLayerRef.current = markersGroup;

    const timer = setTimeout(() => {
      map.invalidateSize();
    }, 250);

    return () => {
      clearTimeout(timer);
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  // Update markers when mapData changes
  useEffect(() => {
    if (!mapInstanceRef.current || !markersLayerRef.current || !mapData) return;

    markersLayerRef.current.clearLayers();

    mapData.nodes.forEach((node) => {
      if (
        typeof node.lat !== 'number' ||
        typeof node.lon !== 'number' ||
        isNaN(node.lat) ||
        isNaN(node.lon) ||
        node.lat < -90 ||
        node.lat > 90 ||
        node.lon < -180 ||
        node.lon > 180 ||
        (node.lat === 0 && node.lon === 0)
      ) {
        return;
      }

      const markerColor =
        node.riskScore >= 80 ? '#EF4444' : node.riskScore >= 55 ? '#F59E0B' : '#10B981';

      // Custom sleek SVG pulse marker
      const customIcon = L.divIcon({
        className: 'custom-leaflet-marker',
        html: `
          <div style="
            width: 24px;
            height: 24px;
            background-color: ${markerColor};
            border: 2px solid #FFFFFF;
            border-radius: 50%;
            box-shadow: 0 2px 6px rgba(0,0,0,0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #FFFFFF;
            font-size: 10px;
            font-weight: bold;
            font-family: monospace;
            cursor: pointer;
          ">
            ${node.caseCount}
          </div>
        `,
        iconSize: [24, 24],
        iconAnchor: [12, 12],
      });

      const marker = L.marker([node.lat, node.lon], { icon: customIcon });

      const popupHtml = `
        <div style="font-family: inherit; font-size: 12px; min-width: 200px; color: #0B1F3A;">
          <div style="font-weight: bold; font-size: 13px; margin-bottom: 4px; color: #246BFE; font-family: monospace;">
            ${node.ip}
          </div>
          <div style="margin-bottom: 4px;">
            <strong>Jurisdiction:</strong> ${node.city ? node.city + ', ' : ''}${node.country}
          </div>
          <div style="margin-bottom: 4px;">
            <strong>ASN:</strong> ${node.asn || 'Unassigned'}
          </div>
          <div style="margin-bottom: 4px;">
            <strong>ISP:</strong> ${node.isp || node.org || 'Unknown'}
          </div>
          <div style="margin-bottom: 8px;">
            <strong>Threat Score:</strong> <span style="font-weight: bold; color: ${markerColor};">${node.riskScore}/100</span> (${node.caseCount} cases)
          </div>
          <div style="border-top: 1px solid #E5E9F2; padding-top: 6px; font-size: 11px;">
            <a href="/investigation/${node.cases[0]?.id || ''}" style="color: #246BFE; text-decoration: none; font-weight: bold;">
              Investigate Associated Case ➔
            </a>
          </div>
        </div>
      `;

      marker.bindPopup(popupHtml);
      marker.on('click', () => setSelectedNode(node));
      markersLayerRef.current?.addLayer(marker);
    });

    mapInstanceRef.current?.invalidateSize();
  }, [mapData]);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">Origin Threat Infrastructure Map</h1>
          <p className="text-xs text-[#68809F] mt-1">
            Global geographic mapping of observed mail transfer agents, public routing relays, and autonomous systems.
          </p>
        </div>
        <button
          onClick={loadMapData}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-slate-50 rounded-xl text-xs font-semibold shadow-2xs transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-[#246BFE]' : ''}`} />
          <span>Refresh Coordinates</span>
        </button>
      </div>

      {/* Four Counters Required by Section 22 */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Observable Public Nodes */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Observable Public Nodes</span>
            <div className="w-8 h-8 rounded-lg bg-blue-50 text-[#246BFE] flex items-center justify-center">
              <Globe className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-[#0B1F3A] mt-3 font-mono">
            {mapData?.stats.observablePublicNodes ?? 0}
          </div>
          <p className="text-[11px] text-[#68809F] mt-1">Geolocatable public MTAs</p>
        </div>

        {/* Autonomous Systems */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Autonomous Systems</span>
            <div className="w-8 h-8 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-indigo-600 mt-3 font-mono">
            {mapData?.stats.autonomousSystems ?? 0}
          </div>
          <p className="text-[11px] text-[#68809F] mt-1">Distinct BGP AS Networks</p>
        </div>

        {/* Geolocated Jurisdictions */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Geolocated Jurisdictions</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-50 text-[#10B981] flex items-center justify-center">
              <Radio className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-[#10B981] mt-3 font-mono">
            {mapData?.stats.geolocatedJurisdictions ?? 0}
          </div>
          <p className="text-[11px] text-[#68809F] mt-1">Countries hosting relay nodes</p>
        </div>

        {/* Local / Loopback Filtered */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Local / Loopback Filtered</span>
            <div className="w-8 h-8 rounded-lg bg-slate-100 text-[#68809F] flex items-center justify-center">
              <Filter className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-[#0B1F3A] mt-3 font-mono">
            {mapData?.stats.localLoopbackFiltered ?? 0}
          </div>
          <p className="text-[11px] text-[#68809F] mt-1">RFC 1918 private subnets isolated</p>
        </div>
      </div>

      {/* Mandatory Forensic Disclaimer Required by Section 10 & 22 */}
      <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-950 flex items-start gap-3 shadow-2xs">
        <Info className="w-4 h-4 text-amber-700 flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong>Mandatory Forensic Disclaimer:</strong> IP geolocation represents approximate network infrastructure location. It does not prove the physical location or identity of the human sender. Never interpret relay coordinates as the attacker's physical home or office.
        </div>
      </div>

      {/* Interactive Leaflet Map Container */}
      <div className="bg-white rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] overflow-hidden">
        <div className="p-4 bg-[#F7F9FC] border-b border-[#E5E9F2] flex items-center justify-between">
          <span className="text-xs font-bold text-[#0B1F3A] tracking-wide">
            OpenStreetMap Live Threat Cartography
          </span>
          <div className="flex items-center gap-4 text-xs font-semibold text-[#68809F]">
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#10B981]" /> Safe (0–54)</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]" /> High (55–79)</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" /> Critical (80–100)</span>
          </div>
        </div>

        <div className="relative w-full h-[520px]">
          <div ref={mapContainerRef} className="w-full h-full" />
        </div>
      </div>

      {/* Node Details Panel */}
      {selectedNode && (
        <div className="bg-white rounded-xl border border-[#246BFE]/30 p-6 shadow-md animate-in fade-in duration-200">
          <div className="flex items-center justify-between pb-4 border-b border-[#E5E9F2]">
            <div>
              <span className="text-[10px] font-bold text-[#68809F] uppercase tracking-wider block">Inspected Infrastructure Node</span>
              <span className="text-lg font-mono font-bold text-[#246BFE]">{selectedNode.ip}</span>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-xs font-semibold text-[#68809F] hover:text-[#0B1F3A]"
            >
              Close
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 text-xs">
            <div>
              <span className="text-[#68809F] block">Geographic Jurisdiction:</span>
              <span className="font-bold text-[#0B1F3A]">{selectedNode.city ? selectedNode.city + ', ' : ''}{selectedNode.country}</span>
            </div>
            <div>
              <span className="text-[#68809F] block">Autonomous System (ASN):</span>
              <span className="font-mono font-bold text-[#0B1F3A]">{selectedNode.asn || 'Unassigned'}</span>
            </div>
            <div>
              <span className="text-[#68809F] block">Network Operator (ISP):</span>
              <span className="font-bold text-[#0B1F3A] truncate block">{selectedNode.isp || selectedNode.org || 'Unknown'}</span>
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-[#E5E9F2]">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider block mb-2">
              Associated Cases ({selectedNode.cases.length}):
            </span>
            <div className="flex flex-wrap gap-2">
              {selectedNode.cases.map((c) => (
                <button
                  key={c.id}
                  onClick={() => navigate(`/investigation/${c.id}`)}
                  className="px-3 py-1.5 bg-[#EEF4FF] hover:bg-blue-100 text-[#246BFE] rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-colors"
                >
                  <span>{c.caseNumber}</span>
                  <span className="text-[10px] text-blue-900 font-sans">({c.classification})</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
