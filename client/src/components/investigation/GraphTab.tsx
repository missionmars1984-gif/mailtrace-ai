import React, { useState } from 'react';
import {
  Network,
  Share2,
  Info,
  ShieldAlert,
  CheckCircle2,
  ExternalLink,
} from 'lucide-react';
import type { CaseRecord, GraphNode, GraphEdge } from '../../types.js';

interface GraphTabProps {
  caseData: CaseRecord;
}

export const GraphTab: React.FC<GraphTabProps> = ({ caseData }) => {
  const { graph } = caseData;
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(graph.nodes[0] || null);

  // Compute 2D node layout coordinates automatically
  const getNodeCoordinates = (index: number, total: number, type: string) => {
    // Semi-radial or clustered layout
    const width = 800;
    const height = 450;
    const centerX = width / 2;
    const centerY = height / 2;

    if (type === 'email') {
      return { x: centerX, y: centerY };
    }

    // Distribute non-email nodes in an ellipse around the center
    const angle = ((index - 1) / Math.max(1, total - 1)) * 2 * Math.PI;
    const radiusX = 280;
    const radiusY = 170;

    const x = centerX + Math.cos(angle) * radiusX;
    const y = centerY + Math.sin(angle) * radiusY;
    return { x, y };
  };

  const nodePositions = graph.nodes.map((node, idx) => ({
    ...node,
    ...getNodeCoordinates(idx, graph.nodes.length, node.type),
  }));

  const getNodeColor = (type: string, riskLevel?: string) => {
    if (riskLevel === 'HIGH') return '#ef4444'; // Red
    if (riskLevel === 'MEDIUM') return '#f59e0b'; // Amber

    switch (type) {
      case 'email':
        return '#2563eb'; // Blue
      case 'sender':
        return '#3b82f6';
      case 'domain':
        return '#6366f1'; // Indigo
      case 'ip':
        return '#8b5cf6'; // Purple
      case 'asn':
        return '#06b6d4'; // Cyan
      case 'geo':
        return '#10b981'; // Emerald
      case 'url':
        return '#f97316'; // Orange
      case 'attachment':
        return '#ec4899'; // Pink
      case 'hash':
        return '#64748b'; // Slate
      default:
        return '#94a3b8';
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-100 gap-2">
          <div>
            <h4 className="text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
              <Share2 className="w-4 h-4 text-blue-600" />
              Entity Correlation Graph
            </h4>
            <p className="text-xs text-slate-500 mt-0.5">
              Correlates forensic artifacts (Email ➔ Sender ➔ Domain ➔ IP ➔ ASN, Email ➔ URLs, Email ➔ Attachments ➔ Hashes).
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>Click any node to inspect telemetry</span>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mt-6">
          {/* Interactive SVG Graph Area */}
          <div className="lg:col-span-3 bg-slate-950 rounded-xl p-4 border border-slate-800 relative overflow-hidden flex items-center justify-center min-h-[460px]">
            {/* Background Grid */}
            <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:30px_30px] opacity-20" />

            <svg viewBox="0 0 800 450" className="w-full h-full max-h-[460px]">
              {/* Edges */}
              {graph.edges.map((edge, idx) => {
                const sourceNode = nodePositions.find((n) => n.id === edge.source);
                const targetNode = nodePositions.find((n) => n.id === edge.target);
                if (!sourceNode || !targetNode) return null;

                const isConnectedToSelected =
                  selectedNode && (selectedNode.id === edge.source || selectedNode.id === edge.target);

                return (
                  <g key={idx}>
                    <line
                      x1={sourceNode.x}
                      y1={sourceNode.y}
                      x2={targetNode.x}
                      y2={targetNode.y}
                      stroke={isConnectedToSelected ? '#60a5fa' : '#334155'}
                      strokeWidth={isConnectedToSelected ? 2.5 : 1.2}
                      strokeDasharray={isConnectedToSelected ? 'none' : '3 3'}
                    />
                    {/* Edge Label */}
                    <text
                      x={(sourceNode.x + targetNode.x) / 2}
                      y={(sourceNode.y + targetNode.y) / 2 - 4}
                      fill="#94a3b8"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      {edge.label}
                    </text>
                  </g>
                );
              })}

              {/* Nodes */}
              {nodePositions.map((node) => {
                const isSelected = selectedNode?.id === node.id;
                const nodeColor = getNodeColor(node.type, node.riskLevel);

                return (
                  <g
                    key={node.id}
                    className="cursor-pointer transition-transform duration-150"
                    onClick={() => setSelectedNode(node)}
                  >
                    {isSelected && (
                      <circle
                        cx={node.x}
                        cy={node.y}
                        r={node.type === 'email' ? 28 : 22}
                        fill="none"
                        stroke="#60a5fa"
                        strokeWidth="2"
                        className="animate-pulse"
                      />
                    )}
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={node.type === 'email' ? 22 : 16}
                      fill={nodeColor}
                      stroke="#ffffff"
                      strokeWidth="2"
                    />
                    <text
                      x={node.x}
                      y={node.y + (node.type === 'email' ? 34 : 26)}
                      fill="#f1f5f9"
                      fontSize="10"
                      fontFamily="sans-serif"
                      fontWeight={isSelected ? 'bold' : 'normal'}
                      textAnchor="middle"
                    >
                      {node.label.length > 20 ? node.label.substring(0, 18) + '...' : node.label}
                    </text>
                    <text
                      x={node.x}
                      y={node.y + (node.type === 'email' ? 44 : 36)}
                      fill="#94a3b8"
                      fontSize="8"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      [{node.type.toUpperCase()}]
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Node Inspector Panel */}
          <div className="bg-slate-50 p-5 rounded-xl border border-slate-200 flex flex-col justify-between">
            {selectedNode ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-200">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    Node Telemetry
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      selectedNode.riskLevel === 'HIGH'
                        ? 'bg-red-100 text-red-700'
                        : selectedNode.riskLevel === 'MEDIUM'
                        ? 'bg-amber-100 text-amber-700'
                        : 'bg-slate-200 text-slate-700'
                    }`}
                  >
                    {selectedNode.riskLevel || 'STANDARD'}
                  </span>
                </div>

                <div>
                  <label className="text-[10px] font-bold text-slate-400 uppercase">Entity Label</label>
                  <p className="text-xs font-mono font-bold text-slate-900 break-all mt-0.5">
                    {selectedNode.label}
                  </p>
                </div>

                <div>
                  <label className="text-[10px] font-bold text-slate-400 uppercase">Entity Class</label>
                  <p className="text-xs font-semibold text-blue-600 mt-0.5 uppercase">
                    {selectedNode.type}
                  </p>
                </div>

                <div>
                  <label className="text-[10px] font-bold text-slate-400 uppercase">Direct Associations</label>
                  <div className="mt-1 space-y-1">
                    {graph.edges
                      .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                      .map((edge, idx) => {
                        const otherId = edge.source === selectedNode.id ? edge.target : edge.source;
                        const otherNode = graph.nodes.find((n) => n.id === otherId);
                        return (
                          <div
                            key={idx}
                            className="p-1.5 bg-white rounded border border-slate-200 text-[11px] font-mono text-slate-700"
                          >
                            <span className="text-blue-500 font-bold">{edge.label}</span> ➔ {otherNode?.label}
                          </div>
                        );
                      })}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-12 text-xs text-slate-400">
                Select a graph node to inspect forensic attributes.
              </div>
            )}

            <div className="mt-6 pt-4 border-t border-slate-200 text-[11px] text-slate-500">
              Correlations represent verified transmission relationships from parsed RFC822 headers.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
