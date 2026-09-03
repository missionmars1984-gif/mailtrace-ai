import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Scale,
  BrainCircuit,
  Target,
  CheckCircle2,
  Sliders,
  Sparkles,
  Layers,
  HeartHandshake,
} from 'lucide-react';
import type { CaseRecord } from '../../types.js';
import { RiskBadge } from '../common/RiskBadge.js';

interface ThreatAnalysisTabProps {
  caseData: CaseRecord;
}

export const ThreatAnalysisTab: React.FC<ThreatAnalysisTabProps> = ({ caseData }) => {
  const {
    classification,
    riskScore,
    riskLevel,
    confidence,
    scoreBreakdown,
    componentScores,
    keyFindings,
    aiAssessment,
    recommendedAction,
  } = caseData;

  const contributors = scoreBreakdown?.contributors || [];
  const synergyBonus = scoreBreakdown?.synergyBonus || 0;
  const whyHighRisk = scoreBreakdown?.whyHighRisk || aiAssessment.summary;
  const recommendedActions = aiAssessment.recommended_actions || (recommendedAction ? [recommendedAction] : []);
  const cs = componentScores || scoreBreakdown?.componentScores;

  const componentList = cs
    ? [
        { key: 'nlpRisk', label: 'NLP Threat Semantics', weight: '20%', score: cs.nlpRisk ?? cs.contentRisk ?? 0 },
        { key: 'urlRisk', label: 'URL Forensics', weight: '18%', score: cs.urlRisk },
        { key: 'identityRisk', label: 'Identity Consistency', weight: '15%', score: cs.identityRisk },
        { key: 'becRisk', label: 'BEC / Wire Fraud', weight: '10%', score: cs.becRisk },
        { key: 'headerRisk', label: 'Email Authentication & Headers', weight: '7%', score: cs.headerRisk },
        { key: 'socialEngineeringRisk', label: 'Social Engineering', weight: '6%', score: cs.socialEngineeringRisk ?? 0 },
        { key: 'attachmentRisk', label: 'Attachment Payloads', weight: '5%', score: cs.attachmentRisk },
        { key: 'senderRisk', label: 'Sender Profile', weight: '10%', score: cs.senderRisk },
        { key: 'replyToRisk', label: 'Reply-To Alignment', weight: '5%', score: cs.replyToRisk },
        { key: 'threatIntelRisk', label: 'Threat Intel & Tor', weight: '5%', score: cs.threatIntelRisk },
      ]
    : [];

  return (
    <div className="space-y-6">
      {/* 1. Core Security Verdict Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Threat Type */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-slate-400 uppercase font-bold text-[10px] tracking-wider block mb-1">
            Threat Classification
          </span>
          <div className="text-xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-600" />
            {classification}
          </div>
          <span className="text-xs text-slate-500 block mt-1">
            Multi-Signal Forensic Verdict
          </span>
        </div>

        {/* Risk Score */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-slate-400 uppercase font-bold text-[10px] tracking-wider block mb-1">
            Calibrated Risk Score
          </span>
          <div className="text-2xl font-black font-mono tracking-tight text-slate-900 flex items-baseline gap-1">
            <span
              className={
                riskScore >= 81 ? 'text-red-600' : riskScore >= 61 ? 'text-orange-600' : riskScore >= 41 ? 'text-amber-600' : 'text-emerald-600'
              }
            >
              {riskScore}
            </span>
            <span className="text-xs text-slate-400 font-sans font-normal">/100</span>
          </div>
          <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden mt-2">
            <div
              className={`h-full rounded-full ${
                riskScore >= 81
                  ? 'bg-red-500'
                  : riskScore >= 61
                  ? 'bg-orange-500'
                  : riskScore >= 41
                  ? 'bg-amber-500'
                  : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.max(5, riskScore)}%` }}
            />
          </div>
        </div>

        {/* Model Confidence */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-slate-400 uppercase font-bold text-[10px] tracking-wider block mb-1">
            Diagnostic Confidence
          </span>
          <div className="text-2xl font-black font-mono tracking-tight text-slate-900">
            {confidence}%
          </div>
          <span className="text-xs text-slate-500 block mt-1">
            Evidence & Telemetry Completeness
          </span>
        </div>

        {/* Severity Level */}
        <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
          <span className="text-slate-400 uppercase font-bold text-[10px] tracking-wider block mb-1">
            Risk Tier Category
          </span>
          <div className="mt-1">
            <RiskBadge score={riskScore} level={riskLevel} classification={classification} size="md" />
          </div>
          <span className="text-xs text-slate-500 block mt-1">
            Policy: {riskScore >= 81 ? 'Immediate Quarantine' : riskScore >= 61 ? 'High Risk Review' : riskScore >= 41 ? 'Suspicious Warning' : 'Allow Delivery'}
          </span>
        </div>
      </div>

      {/* 2. Independent Multi-Signal Component Scores */}
      {cs && (
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-600" />
              <h4 className="text-sm font-bold text-slate-900">
                Independent Multi-Signal Evidence Vectors (10 Dimensions)
              </h4>
            </div>
            {Boolean(cs.benignEvidence && cs.benignEvidence > 0) && (
              <span className="text-xs text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-full font-medium inline-flex items-center gap-1.5 self-start">
                <HeartHandshake className="w-3.5 h-3.5" />
                Benign Negative Evidence: -{cs.benignEvidence} pts
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3.5">
            {componentList.map((comp) => {
              const hasScore = comp.score !== null && comp.score !== undefined;
              const numScore = hasScore ? (comp.score as number) : 0;
              return (
                <div key={comp.key} className="p-3 bg-slate-50 rounded-lg border border-slate-200/80 space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-700 truncate">{comp.label}</span>
                    <span className="text-[10px] font-mono text-slate-400 font-bold">{comp.weight}</span>
                  </div>
                  <div className="flex items-baseline justify-between font-mono">
                    <span
                      className={`text-sm font-black ${
                        !hasScore ? 'text-slate-400' : numScore >= 70 ? 'text-red-600' : numScore >= 40 ? 'text-amber-600' : 'text-slate-700'
                      }`}
                    >
                      {hasScore ? numScore : 'N/A'}
                      {hasScore && <span className="text-[10px] font-normal text-slate-400">/100</span>}
                    </span>
                    <span className="text-[10px] uppercase font-bold text-slate-400">
                      {!hasScore ? 'NONE' : numScore >= 70 ? 'HIGH' : numScore >= 40 ? 'MED' : 'LOW'}
                    </span>
                  </div>
                  <div className="w-full bg-slate-200 h-1 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${
                        !hasScore ? 'bg-slate-300' : numScore >= 70 ? 'bg-red-500' : numScore >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${hasScore ? Math.max(3, numScore) : 0}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 3. Transparent Score Contributors Breakdown Table */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-slate-100 bg-slate-50 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Scale className="w-4 h-4 text-blue-600" />
            <h4 className="text-sm font-bold text-slate-900">
              Evidence-Driven Score Contributors Breakdown
            </h4>
          </div>
          <span className="text-xs font-mono text-slate-500 font-semibold">
            Total Threat Score: {riskScore}/100
          </span>
        </div>

        {contributors.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            No threat contributors detected. Email satisfies all baseline integrity checks.
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {contributors.map((contrib, idx) => (
              <div key={idx} className="p-4 flex items-center justify-between gap-4 hover:bg-slate-50/50 transition-colors">
                <div className="flex items-center gap-3">
                  <span
                    className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded uppercase ${
                      contrib.severity === 'CRITICAL'
                        ? 'bg-red-100 text-red-800'
                        : contrib.severity === 'HIGH'
                        ? 'bg-orange-100 text-orange-800'
                        : contrib.severity === 'MEDIUM'
                        ? 'bg-amber-100 text-amber-800'
                        : 'bg-slate-100 text-slate-700'
                    }`}
                  >
                    {contrib.severity}
                  </span>
                  <div>
                    <span className="text-xs font-bold text-slate-900 block">{contrib.name}</span>
                    <span className="text-[11px] text-slate-400 font-medium">Source: {contrib.source}</span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="font-mono font-bold text-xs text-red-600 bg-red-50 px-2.5 py-1 rounded border border-red-200">
                    +{contrib.points} pts
                  </span>
                </div>
              </div>
            ))}

            {synergyBonus > 0 && (
              <div className="p-4 bg-red-50/40 flex items-center justify-between gap-4 border-t border-red-100">
                <div className="flex items-center gap-3">
                  <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded uppercase bg-red-600 text-white">
                    MULTIPLIER
                  </span>
                  <div>
                    <span className="text-xs font-bold text-red-950 block">Evidence Correlation & Synergy Bonus</span>
                    <span className="text-[11px] text-red-700 font-medium">
                      Multi-vector attack pattern detected across independent threat channels
                    </span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="font-mono font-bold text-xs text-red-700 bg-red-100 px-2.5 py-1 rounded border border-red-300">
                    +{synergyBonus} pts
                  </span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 4. Threat Reasoning ("WHY THIS IS HIGH RISK") */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
        <div className="flex items-center gap-2 pb-3 border-b border-slate-100 mb-3">
          <BrainCircuit className="w-4 h-4 text-blue-600" />
          <h4 className="text-sm font-bold text-slate-900">
            Forensic Threat Reasoning & Intent Assessment
          </h4>
        </div>

        <div className="bg-slate-50 p-4 rounded-lg border border-slate-200 text-xs text-slate-800 leading-relaxed font-medium">
          {whyHighRisk}
        </div>
      </div>

      {/* 5. Key Evidence & Recommended Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Key Corroborating Evidence */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-100 mb-4">
            <Target className="w-4 h-4 text-blue-600" />
            <h4 className="text-sm font-bold text-slate-900">Key Corroborating Evidence</h4>
          </div>

          <div className="space-y-2.5">
            {keyFindings.map((finding, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-50 border border-slate-100 text-xs text-slate-700"
              >
                <span className="w-4 h-4 rounded-full bg-blue-100 text-blue-700 font-bold flex items-center justify-center flex-shrink-0 text-[10px] mt-0.5">
                  ✓
                </span>
                <span className="leading-relaxed font-medium">{finding}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Recommended Actions */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-100 mb-4">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <h4 className="text-sm font-bold text-slate-900">Mandated Incident Response Actions</h4>
          </div>

          <div className="space-y-2.5">
            {recommendedActions.map((act, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-50 border border-slate-100 text-xs text-slate-700"
              >
                <span className="w-4 h-4 rounded-full bg-emerald-100 text-emerald-700 font-bold flex items-center justify-center flex-shrink-0 text-[10px] mt-0.5">
                  {idx + 1}
                </span>
                <span className="leading-relaxed">{act}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
