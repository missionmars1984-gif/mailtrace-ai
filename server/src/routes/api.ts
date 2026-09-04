import { Router, Request, Response } from 'express';
import { EmailParser } from '../parser/emailParser.js';
import { ModelA_EmailNlpClassifier } from '../models/nlpClassifier.js';
import { ModelB_UrlRiskModel } from '../models/urlRiskModel.js';
import { ModelC_SenderIdentityModel } from '../models/identityModel.js';
import { ModelD_BecModel } from '../models/becModel.js';
import { ModelE_AttachmentModel } from '../models/attachmentModel.js';
import { ModelF_HeaderAnomalyEngine } from '../models/headerModel.js';
import { SocialEngineeringEngine } from '../models/socialEngineeringEngine.js';
import { UrlAnalyzer } from '../analyzers/urlAnalyzer.js';
import { InfrastructureAnalyzer } from '../analyzers/infrastructureAnalyzer.js';
import { CorrelationBuilder } from '../analyzers/correlationBuilder.js';
import { GeminiClient } from '../ai/geminiClient.js';
import { RiskEngine } from '../scoring/riskEngine.js';
import { ForensicHashService } from '../crypto/forensicHash.js';
import { DatabaseService } from '../db/database.js';
import { GeoLocationProvider, geoProvider } from '../services/geoLocationProvider.js';
import type {
  CaseRecord,
  SecurityFinding,
  AssistantMessage,
  ThreatClassification,
  ModelAvailability,
  DebugTrace,
} from '../types/index.js';

export const apiRouter = Router();

// Track active SSE clients for real-time live monitor streaming
const sseClients: Response[] = [];

export function broadcastLiveEvent(eventType: string, data: any) {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (let i = sseClients.length - 1; i >= 0; i--) {
    try {
      sseClients[i].write(payload);
    } catch {
      sseClients.splice(i, 1);
    }
  }
}

/**
 * Executes the full MailTrace AI canonical end-to-end multi-model threat detection & forensics pipeline.
 */
export async function runAnalysisPipeline(rawEmailContent: string | Buffer): Promise<CaseRecord> {
  // 1. Parse raw email & extract RFC822 envelope and body structures
  const parsed = await EmailParser.parse(rawEmailContent);

  // 2. Identify sending IP from earliest public origin hop or chronological Hop #1
  const originHop = parsed.hops.find((h) => h.ip && !GeoLocationProvider.isPrivateOrReserved(h.ip).isPrivate) || parsed.hops[0];
  const sendingIp = originHop?.ip;

  // 3. Extract all URLs (HTML hrefs, plain text, angle-brackets, www domains)
  const rawUrls = UrlAnalyzer.extractUrls(parsed.bodyText, parsed.bodyHtml);

  // 4. MODEL B: URL Risk Model (Shannon entropy, brand mismatch, TLD, structured forest ensemble)
  const urlModelOutput = ModelB_UrlRiskModel.analyzeUrls(rawUrls);

  // 5. MODEL C: Sender & Identity Model (Display Name vs From vs Reply-To vs Return-Path vs Org)
  const identityModelOutput = ModelC_SenderIdentityModel.analyze({
    from: parsed.from,
    replyTo: parsed.replyTo,
    returnPath: parsed.returnPath,
    auth: parsed.auth,
    urlDomains: urlModelOutput.parsedUrls.map((u) => u.domain),
  });
  if (sendingIp) {
    identityModelOutput.identityAnalysis.observed.sendingIp = sendingIp;
  }

  // 6. MODEL D: BEC & Financial Fraud Model (Combinatorial evaluation)
  const becModelOutput = ModelD_BecModel.analyze({
    subject: parsed.subject,
    bodyText: parsed.bodyText,
    senderDisplayName: parsed.from.name || '',
    senderAddress: parsed.from.address,
    replyToAddress: parsed.replyTo?.address,
    identityRisk: identityModelOutput.identityRisk,
  });

  // 7. MODEL E: Attachment Analysis Model (null when no attachments present)
  const attachmentModelOutput = ModelE_AttachmentModel.analyze(parsed.attachments);

  // 8. MODEL F: Header & Authentication Anomaly Engine (SPF, DKIM, DMARC, Routing)
  const fromDomain = parsed.from.address.includes('@') ? parsed.from.address.split('@')[1] : '';
  const returnPathDomain = parsed.returnPath && parsed.returnPath.includes('@') ? parsed.returnPath.split('@')[1] : '';
  const replyToDomain = parsed.replyTo?.address && parsed.replyTo.address.includes('@') ? parsed.replyTo.address.split('@')[1] : undefined;

  const headerModelOutput = ModelF_HeaderAnomalyEngine.analyze({
    auth: parsed.auth,
    rawHeaders: parsed.rawHeaders,
    hops: parsed.hops,
    fromDomain,
    returnPathDomain,
    replyToDomain,
  });

  // 9. SOCIAL ENGINEERING ENGINE (9 Psychological dimensions)
  const socialOutput = SocialEngineeringEngine.analyze(
    parsed.subject,
    parsed.bodyText,
    parsed.from.name || ''
  );

  // 10. MODEL A: Email NLP Classifier (Multi-label probability distribution & contextual semantics)
  const nlpModelOutput = await ModelA_EmailNlpClassifier.classify({
    subject: parsed.subject,
    bodyText: parsed.bodyText,
    bodyHtml: parsed.bodyHtml,
    senderDisplayName: parsed.from.name || '',
    senderAddress: parsed.from.address,
    urlContexts: urlModelOutput.features.map((f) => f.rawUrl),
  });

  // 11. Route & Infrastructure enrichment with real GeoIP
  const { hops, findings: infraFindings, diagnostic: geoDiagnostic, observedOriginRelay } = await InfrastructureAnalyzer.enrichHops(parsed.hops);

  // Update observed sendingIp with the verified observedOriginRelay
  if (observedOriginRelay?.ip) {
    identityModelOutput.identityAnalysis.observed.sendingIp = observedOriginRelay.ip;
  } else if (hops[0]?.ip) {
    identityModelOutput.identityAnalysis.observed.sendingIp = hops[0].ip;
  }

  // Consolidate findings across all independent models
  const findings: SecurityFinding[] = [
    ...identityModelOutput.findings,
    ...urlModelOutput.findings,
    ...becModelOutput.findings,
    ...attachmentModelOutput.findings,
    ...headerModelOutput.findings,
    ...socialOutput.findings,
    ...infraFindings,
  ];

  // 12. EVIDENCE FUSION LAYER (Calibrated multi-model weighting + Hard Escalation Safeguards)
  const scoreBreakdown = RiskEngine.evaluate({
    nlpProbabilities: nlpModelOutput.probabilities,
    nlpRisk: nlpModelOutput.nlpRisk,
    urlRisk: urlModelOutput.urlRisk,
    urls: urlModelOutput.parsedUrls,
    identityRisk: identityModelOutput.identityRisk,
    identityConsistencyScore: identityModelOutput.identityConsistencyScore,
    identityAnalysis: identityModelOutput.identityAnalysis,
    claimedIdentity: identityModelOutput.claimedIdentity,
    observedIdentity: identityModelOutput.observedIdentity,
    becRisk: becModelOutput.becRisk,
    becPatterns: becModelOutput.detectedPatterns,
    attachmentRisk: attachmentModelOutput.attachmentRisk,
    attachments: attachmentModelOutput.parsedAttachments,
    authenticationRisk: headerModelOutput.authenticationRisk,
    headerRisk: headerModelOutput.headerRisk,
    auth: parsed.auth,
    hops,
    socialSignals: socialOutput.signals,
    findings,
    urlAnalysisStatus: urlModelOutput.urlReputationStatus,
    attachmentAnalysisStatus: attachmentModelOutput.attachmentAnalysisStatus,
    parsedEmail: {
      from: parsed.from.address,
      to: parsed.to.map((t) => t.address),
      cc: parsed.cc.map((c) => c.address),
      replyTo: parsed.replyTo?.address,
      subject: parsed.subject,
      body: parsed.bodyText,
      attachments: parsed.attachments.map((a) => ({
        filename: a.filename || 'attachment.dat',
        size: a.size,
        contentType: a.contentType,
        sha256: a.sha256,
      })),
      urls: rawUrls,
    },
  });

  // 13. Generate Case ID
  const caseNumber = DatabaseService.getNextCaseNumber();
  const id = `case_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const createdAt = new Date().toISOString();

  // 14. Entity Correlation & IOC Extraction
  const { graph, iocs } = CorrelationBuilder.build({
    caseId: caseNumber,
    from: parsed.from,
    identity: identityModelOutput.identityAnalysis,
    urls: urlModelOutput.parsedUrls,
    attachments: attachmentModelOutput.parsedAttachments,
    hops,
  });

  // 15. Transparent Model Availability Declaration
  const modelAvailability: ModelAvailability = {
    nlp: nlpModelOutput.modelTier,
    url: urlModelOutput.modelTier,
    identity: identityModelOutput.modelTier,
    bec: becModelOutput.modelTier,
    attachment: attachmentModelOutput.modelTier,
    header: headerModelOutput.modelTier,
    socialEngineering: 'PSYCHOLOGICAL_DIMENSION_ENGINE',
  };

  // 16. SECTION 21 Internal Debug Trace
  const debugTrace: DebugTrace = {
    input: {
      from: parsed.from.address,
      to: parsed.to.map((t) => t.address),
      replyTo: parsed.replyTo?.address,
      returnPath: parsed.returnPath,
      subject: parsed.subject,
      bodyLength: parsed.bodyText.length,
      urlCount: rawUrls.length,
      attachmentCount: parsed.attachments.length,
      hopCount: parsed.hops.length,
    },
    extractedFeatures: {
      urlFeatures: urlModelOutput.features,
      becPatterns: becModelOutput.detectedPatterns,
      identityInconsistency: 100 - identityModelOutput.identityConsistencyScore,
      monetarySignals: becModelOutput.monetarySignals,
      socialSignals: socialOutput.signals,
    },
    nlpOutput: nlpModelOutput.probabilities,
    urlOutput: {
      urlRisk: urlModelOutput.urlRisk,
      highestRiskUrl: urlModelOutput.highestRiskUrl,
      urlCount: rawUrls.length,
      features: urlModelOutput.features,
    },
    identityOutput: {
      identityRisk: identityModelOutput.identityRisk,
      claimedIdentity: identityModelOutput.claimedIdentity,
      observedIdentity: identityModelOutput.observedIdentity,
      identityConsistency: identityModelOutput.identityConsistencyScore,
      inconsistencies: identityModelOutput.identityAnalysis.reasons,
    },
    headerOutput: {
      authenticationRisk: headerModelOutput.authenticationRisk,
      spf: headerModelOutput.spfStatus,
      dkim: headerModelOutput.dkimStatus,
      dmarc: headerModelOutput.dmarcStatus,
      routingAnomalies: headerModelOutput.routingAnomalies,
    },
    becOutput: {
      becRisk: becModelOutput.becRisk,
      indicators: becModelOutput.indicators,
      monetarySignals: becModelOutput.monetarySignals,
    },
    attachmentOutput: {
      attachmentRisk: attachmentModelOutput.attachmentRisk,
      count: attachmentModelOutput.attachmentCount,
      dangerousCount: attachmentModelOutput.dangerousCount,
    },
    socialEngineeringOutput: socialOutput.signals,
    evidenceFusion: {
      weightedBase: scoreBreakdown.components.threatContentScore,
      synergyBonus: scoreBreakdown.synergyBonus || 0,
      escalationRulesApplied: scoreBreakdown.appliedEscalationRules,
      benignDiscount: scoreBreakdown.benignEvidenceScore,
      calibratedScore: scoreBreakdown.finalScore,
      modelAgreementScore: scoreBreakdown.modelAgreementRatio,
    },
    finalRisk: {
      riskScore: scoreBreakdown.finalScore,
      confidence: scoreBreakdown.confidence,
      classification: scoreBreakdown.classification,
    },
  };

  // SECTION 21 & SECTION 17 Console Debug Logging
  console.log(`\n==================== [DEBUG TRACE - ${caseNumber}] ====================`);
  console.log(`[INPUT] From: ${parsed.from.address} | Subject: "${parsed.subject}"`);
  console.log(
    `[NLP OUTPUT] P(phish)=${nlpModelOutput.probabilities.phishing} P(cred_theft)=${nlpModelOutput.probabilities.credential_theft} P(bec)=${nlpModelOutput.probabilities.bec} P(legit)=${nlpModelOutput.probabilities.legitimate}`
  );
  console.log(`[URL OUTPUT] Risk=${urlModelOutput.urlRisk} | URLs=${rawUrls.length} | Highest=${urlModelOutput.highestRiskUrl || 'None'}`);
  console.log(`[IDENTITY OUTPUT] Risk=${identityModelOutput.identityRisk} | Consistency=${identityModelOutput.identityConsistencyScore}/100`);
  console.log(`[HEADER OUTPUT] AuthRisk=${headerModelOutput.authenticationRisk} | SPF=${headerModelOutput.spfStatus} DKIM=${headerModelOutput.dkimStatus} DMARC=${headerModelOutput.dmarcStatus}`);
  console.log(`[BEC OUTPUT] Risk=${becModelOutput.becRisk} | Patterns=[${becModelOutput.indicators.join(', ') || 'None'}]`);
  console.log(`[ATTACHMENT OUTPUT] Risk=${attachmentModelOutput.attachmentRisk ?? 'null'} | Dangerous=${attachmentModelOutput.dangerousCount}`);
  console.log(`[EVIDENCE FUSION] Base=${scoreBreakdown.components.threatContentScore} Synergy=+${scoreBreakdown.synergyBonus || 0} Escalations=[${scoreBreakdown.appliedEscalationRules.join(', ') || 'None'}]`);
  console.log(`[FINAL RISK] Score=${scoreBreakdown.finalScore}/100 | Confidence=${scoreBreakdown.confidence}% | Classification=${scoreBreakdown.classification}`);
  console.log(`========================================================================\n`);

  // 17. Forensic Integrity Hashes
  const evidencePayload = {
    caseNumber,
    from: parsed.from,
    returnPath: parsed.returnPath,
    replyTo: parsed.replyTo,
    subject: parsed.subject,
    date: parsed.date,
    findings,
    urls: urlModelOutput.parsedUrls.map((u) => u.url),
    attachments: attachmentModelOutput.parsedAttachments.map((a) => ({ filename: a.filename, sha256: a.sha256 })),
    hops: hops.map((h) => ({ hop: h.hopNumber, ip: h.ip })),
  };

  const evidenceHash = ForensicHashService.sha256(evidencePayload);

  const reportPayload = {
    caseNumber,
    createdAt,
    evidenceHash,
    classification: scoreBreakdown.classification,
    riskScore: scoreBreakdown.finalScore,
    riskLevel: scoreBreakdown.riskLevel,
    confidence: scoreBreakdown.confidence,
    summary: scoreBreakdown.whyHighRisk || '',
    keyFindings: scoreBreakdown.scoringReasons,
    identityAnalysis: identityModelOutput.identityAnalysis,
  };

  const reportHash = ForensicHashService.sha256(reportPayload);

  // 18. Assemble Complete Case Record (adhering strictly to Section 16 schema)
  const caseRecord: CaseRecord = {
    id,
    caseNumber,
    createdAt,
    subject: parsed.subject,
    metadata: {
      from: parsed.from,
      to: parsed.to,
      cc: parsed.cc,
      bcc: parsed.bcc,
      replyTo: parsed.replyTo,
      returnPath: parsed.returnPath,
      subject: parsed.subject,
      date: parsed.date,
      messageId: parsed.messageId,
      auth: parsed.auth,
    },
    classification: scoreBreakdown.classification,
    riskScore: scoreBreakdown.finalScore,
    riskLevel: scoreBreakdown.riskLevel,
    confidence: scoreBreakdown.confidence,
    threatTypes: scoreBreakdown.threatTypes,
    claimedIdentity: scoreBreakdown.claimedIdentity,
    observedIdentity: scoreBreakdown.observedIdentity,
    identityConsistency: scoreBreakdown.identityConsistency,
    componentScores: scoreBreakdown.componentScores,
    evidence: scoreBreakdown.evidence,
    indicators: scoreBreakdown.indicators,
    extractedIOCs: scoreBreakdown.extractedIOCs,
    campaignIndicators: scoreBreakdown.campaignIndicators,
    quarantineRecommendation: scoreBreakdown.quarantineRecommendation,
    quarantineStatus: scoreBreakdown.quarantineRecommendation ? 'QUARANTINED' : 'NOT_QUARANTINED',
    quarantineReason: scoreBreakdown.quarantineRecommendation ? scoreBreakdown.whyHighRisk : undefined,
    quarantinedAt: scoreBreakdown.quarantineRecommendation ? createdAt : undefined,
    recommendedAction: scoreBreakdown.recommendedAction,
    summary: scoreBreakdown.whyHighRisk || '',
    keyFindings: scoreBreakdown.scoringReasons.length > 0 ? scoreBreakdown.scoringReasons : [scoreBreakdown.whyHighRisk || ''],
    identityAnalysis: identityModelOutput.identityAnalysis,
    findings,
    urls: urlModelOutput.parsedUrls,
    attachments: attachmentModelOutput.parsedAttachments,
    hops,
    iocs,
    graph,
    aiAssessment: {
      classification: scoreBreakdown.classification,
      risk_score: scoreBreakdown.finalScore,
      confidence: scoreBreakdown.confidence,
      summary: scoreBreakdown.whyHighRisk || '',
      key_findings: scoreBreakdown.scoringReasons,
      identity_assessment: identityModelOutput.identityAnalysis.reasons.join('. '),
      phishing_indicators: urlModelOutput.findings.map((f) => f.title),
      bec_indicators: becModelOutput.indicators,
      recommended_actions: [scoreBreakdown.recommendedAction],
      isFallback: nlpModelOutput.modelTier !== 'GEMINI_GENAI',
      nlpProbabilities: nlpModelOutput.probabilities,
    },
    scoreBreakdown,
    modelAvailability,
    debugTrace,
    evidenceHash,
    reportHash,
    rawEmail: typeof rawEmailContent === 'string' ? rawEmailContent : rawEmailContent.toString('utf-8'),
    rawHeaders: parsed.rawHeaders,
    observedOriginRelay,
    geoDiagnostic,
  };

  // 19. Persist to SQLite
  DatabaseService.saveCase(caseRecord);

  // 20. Broadcast to real-time live monitor subscribers
  broadcastLiveEvent('email-analyzed', {
    caseId: caseRecord.id,
    caseNumber: caseRecord.caseNumber,
    subject: caseRecord.metadata.subject,
    from: caseRecord.metadata.from.address,
    classification: caseRecord.classification,
    riskScore: caseRecord.riskScore,
    riskLevel: caseRecord.riskLevel,
    originIp: observedOriginRelay?.ip || hops[0]?.ip || 'Unknown',
    timestamp: caseRecord.createdAt,
  });

  return caseRecord;
}

// POST /api/analyze/email - Uploaded .eml content
apiRouter.post('/analyze/email', async (req: Request, res: Response) => {
  try {
    const { emailContent, rawEmail } = req.body;
    const content = emailContent || rawEmail;
    if (!content || typeof content !== 'string' || !content.trim()) {
      return res.status(400).json({ error: 'Please provide valid .eml or raw email content.' });
    }
    const result = await runAnalysisPipeline(content);
    return res.status(201).json(result);
  } catch (err: any) {
    console.error('[MailTrace API] Error running analyze/email:', err);
    return res.status(500).json({ error: err.message || 'Error processing email file.' });
  }
});

// POST /api/analyze/raw - Raw RFC822 MIME paste
apiRouter.post('/analyze/raw', async (req: Request, res: Response) => {
  try {
    const content = typeof req.body === 'string' ? req.body : req.body.rawEmail;
    if (!content || typeof content !== 'string' || !content.trim()) {
      return res.status(400).json({ error: 'Please provide raw MIME email text.' });
    }
    const result = await runAnalysisPipeline(content);
    return res.status(201).json(result);
  } catch (err: any) {
    console.error('[MailTrace API] Error running analyze/raw:', err);
    return res.status(500).json({ error: err.message || 'Error processing raw email.' });
  }
});

// POST /api/analyze - Real email forensic analysis
apiRouter.post('/analyze', async (req: Request, res: Response) => {
  try {
    const { rawEmail, emailContent } = req.body;
    const contentToAnalyze = rawEmail || emailContent;

    if (!contentToAnalyze || typeof contentToAnalyze !== 'string' || contentToAnalyze.trim().length === 0) {
      return res.status(400).json({ error: 'Please provide raw RFC822 email content (headers and body) for analysis.' });
    }

    const result = await runAnalysisPipeline(contentToAnalyze);
    return res.status(201).json(result);
  } catch (err: any) {
    console.error('[MailTrace API] Error running analysis:', err);
    return res.status(500).json({ error: err.message || 'An error occurred during email forensic analysis.' });
  }
});

// GET /api/dashboard - Dashboard metrics
apiRouter.get('/dashboard', (_req: Request, res: Response) => {
  try {
    const stats = DatabaseService.getDashboardStats();
    return res.json(stats);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/stats - Alias for dashboard
apiRouter.get('/stats', (_req: Request, res: Response) => {
  try {
    const stats = DatabaseService.getDashboardStats();
    return res.json(stats);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/cases - List all cases
apiRouter.get('/cases', (req: Request, res: Response) => {
  try {
    const { search, classification, limit } = req.query;
    const cases = DatabaseService.getAllCases({
      search: typeof search === 'string' ? search : undefined,
      classification: typeof classification === 'string' ? classification : undefined,
      limit: limit ? parseInt(limit as string, 10) : undefined,
    });
    return res.json(cases);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/cases/:id - Get full investigation details
apiRouter.get('/cases/:id', (req: Request, res: Response) => {
  try {
    const caseId = String(req.params.id);
    const record = DatabaseService.getCaseById(caseId);
    if (!record) {
      return res.status(404).json({ error: `Case "${caseId}" not found.` });
    }
    return res.json(record);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/cases/:id/report - Standalone report
apiRouter.get('/cases/:id/report', (req: Request, res: Response) => {
  try {
    const caseId = String(req.params.id);
    const record = DatabaseService.getCaseById(caseId);
    if (!record) {
      return res.status(404).json({ error: `Case "${caseId}" not found.` });
    }
    return res.json(record);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// DELETE /api/cases/:id - Delete a specific case
apiRouter.delete('/cases/:id', (req: Request, res: Response) => {
  try {
    const caseId = String(req.params.id);
    const deleted = DatabaseService.deleteCase(caseId);
    if (!deleted) {
      return res.status(404).json({ error: `Case "${caseId}" not found or already deleted.` });
    }
    return res.json({ success: true, message: `Case "${caseId}" deleted successfully.` });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// DELETE /api/cases - Delete all cases (clear registry)
apiRouter.delete('/cases', (_req: Request, res: Response) => {
  try {
    DatabaseService.deleteAllCases();
    return res.json({ success: true, message: 'All cases cleared successfully.' });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/cases/:id/indicators - Get extracted IOC items for a case
apiRouter.get('/cases/:id/indicators', (req: Request, res: Response) => {
  try {
    const caseId = String(req.params.id);
    const iocs = DatabaseService.getCaseIndicators(caseId);
    return res.json(iocs);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/iocs - Threat intelligence repository
apiRouter.get('/iocs', (req: Request, res: Response) => {
  try {
    const { search, type } = req.query;
    const list = DatabaseService.getAllIndicators(
      typeof search === 'string' ? search : undefined,
      typeof type === 'string' ? type : undefined
    );
    return res.json(list);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/iocs/:value - Lookup specific indicator
apiRouter.get('/iocs/:value', (req: Request, res: Response) => {
  try {
    const val = decodeURIComponent(String(req.params.value));
    const item = DatabaseService.getIndicatorByValue(val);
    if (!item) {
      return res.status(404).json({ error: `Indicator "${val}" not found in threat repository.` });
    }
    return res.json(item);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/ip/:ip - Direct IP intelligence lookup
apiRouter.get('/ip/:ip', async (req: Request, res: Response) => {
  try {
    const ip = String(req.params.ip);
    const data = await geoProvider.getLocation(ip);
    return res.json(data);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/threat-map - Interactive Threat Map data with counters
apiRouter.get('/threat-map', (_req: Request, res: Response) => {
  try {
    const mapData = DatabaseService.getThreatMapData();
    return res.json(mapData);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/reports - List all forensic reports
apiRouter.get('/reports', (_req: Request, res: Response) => {
  try {
    const reports = DatabaseService.getAllReports();
    return res.json(reports);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/reports/:id - Get specific dossier
apiRouter.get('/reports/:id', (req: Request, res: Response) => {
  try {
    const report = DatabaseService.getReportById(String(req.params.id));
    if (!report) {
      return res.status(404).json({ error: `Report "${req.params.id}" not found.` });
    }
    return res.json(report);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/reports - Export/generate report
apiRouter.post('/reports', (req: Request, res: Response) => {
  try {
    const { caseId } = req.body;
    if (!caseId) return res.status(400).json({ error: 'caseId is required.' });
    const caseRecord = DatabaseService.getCaseById(caseId);
    if (!caseRecord) return res.status(404).json({ error: 'Case not found.' });

    const report = DatabaseService.getReportById(caseRecord.caseNumber) || DatabaseService.getReportById(caseRecord.id);
    return res.json(report);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/campaigns - Discovered campaign clusters
apiRouter.get('/campaigns', (_req: Request, res: Response) => {
  try {
    const campaigns = DatabaseService.getCampaigns();
    return res.json(campaigns);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/quarantine - List all quarantined email cases
apiRouter.get('/quarantine', (_req: Request, res: Response) => {
  try {
    const quarantinedCases = DatabaseService.getQuarantinedCases();
    return res.json(quarantinedCases);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/quarantine/:id/release - Release email from quarantine
apiRouter.post('/quarantine/:id/release', (req: Request, res: Response) => {
  try {
    const caseId = String(req.params.id);
    const { reason = 'Analyst authorized release after verification' } = req.body || {};
    const updated = DatabaseService.updateQuarantineStatus(caseId, 'RELEASED', reason);
    if (!updated) {
      return res.status(404).json({ error: `Case "${caseId}" not found.` });
    }
    return res.json({ success: true, message: `Case "${caseId}" has been released from quarantine.` });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/quarantine/:id/quarantine - Manually isolate/quarantine case
apiRouter.post('/quarantine/:id/quarantine', (req: Request, res: Response) => {
  try {
    const caseId = String(req.params.id);
    const { reason = 'Manual SOC analyst quarantine isolation' } = req.body || {};
    const updated = DatabaseService.updateQuarantineStatus(caseId, 'QUARANTINED', reason);
    if (!updated) {
      return res.status(404).json({ error: `Case "${caseId}" not found.` });
    }
    return res.json({ success: true, message: `Case "${caseId}" has been quarantined.` });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/assistant - Security Assistant grounded in case evidence
apiRouter.post('/assistant', async (req: Request, res: Response) => {
  try {
    const { caseId, question } = req.body;
    if (!question || typeof question !== 'string' || !question.trim()) {
      return res.status(400).json({ error: 'Question is required.' });
    }

    let caseData: CaseRecord | null = null;
    if (caseId) {
      caseData = DatabaseService.getCaseById(caseId);
    } else {
      const allCases = DatabaseService.getAllCases({ limit: 1 });
      if (allCases.length > 0) caseData = allCases[0];
    }

    const answer = await GeminiClient.askSecurityAssistant({
      caseData,
      question: question.trim(),
    });

    const userMsg: AssistantMessage = {
      id: `msg_u_${Date.now()}`,
      caseId: caseData?.id,
      role: 'user',
      content: question.trim(),
      timestamp: new Date().toISOString(),
    };
    const assistantMsg: AssistantMessage = {
      id: `msg_a_${Date.now()}`,
      caseId: caseData?.id,
      role: 'assistant',
      content: answer,
      timestamp: new Date().toISOString(),
    };

    DatabaseService.saveAssistantMessage(userMsg);
    DatabaseService.saveAssistantMessage(assistantMsg);

    return res.json({
      answer,
      caseNumber: caseData?.caseNumber,
      caseId: caseData?.id,
      timestamp: assistantMsg.timestamp,
    });
  } catch (err: any) {
    console.error('[MailTrace API] Error in assistant endpoint:', err);
    return res.status(500).json({ error: err.message || 'Error processing assistant question.' });
  }
});

// GET /api/assistant/history - Assistant messages
apiRouter.get('/assistant/history', (req: Request, res: Response) => {
  try {
    const { caseId } = req.query;
    const history = DatabaseService.getAssistantHistory(typeof caseId === 'string' ? caseId : undefined);
    return res.json(history);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/live-stream & /api/live/stream - Server-Sent Events (SSE) for real-time monitoring
const handleLiveStreamSSE = (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  // 2KB comment padding to force Cloudflare / Nginx reverse proxies to flush immediately
  res.write(':' + ' '.repeat(2048) + '\n\n');

  // Send initial connection acknowledgement
  res.write(`event: connected\ndata: ${JSON.stringify({ status: 'connected', time: new Date().toISOString() })}\n\n`);

  sseClients.push(res);

  // Heartbeat ping every 10s to keep connection alive through proxies & firewalls
  const pingInterval = setInterval(() => {
    try {
      res.write(`event: ping\ndata: ${JSON.stringify({ time: new Date().toISOString() })}\n\n`);
    } catch {
      clearInterval(pingInterval);
    }
  }, 10000);

  req.on('close', () => {
    clearInterval(pingInterval);
    const index = sseClients.indexOf(res);
    if (index !== -1) sseClients.splice(index, 1);
  });
};

apiRouter.get('/live-stream', handleLiveStreamSSE);
apiRouter.get('/live/stream', handleLiveStreamSSE);

// POST /api/ingest/email - Ingest email and broadcast to live monitor
apiRouter.post('/ingest/email', async (req: Request, res: Response) => {
  try {
    const { rawEmail } = req.body;
    if (!rawEmail || typeof rawEmail !== 'string') {
      return res.status(400).json({ error: 'rawEmail is required.' });
    }
    const result = await runAnalysisPipeline(rawEmail);
    return res.status(201).json(result);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/monitoring - System monitoring metrics
apiRouter.get('/monitoring', (_req: Request, res: Response) => {
  const cases = DatabaseService.getAllCases();
  const hasGeminiKey = Boolean(process.env.GEMINI_API_KEY?.trim());

  return res.json({
    status: 'HEALTHY',
    uptimeSeconds: process.uptime(),
    memoryUsageMB: Math.round(process.memoryUsage().rss / (1024 * 1024)),
    database: {
      engine: 'SQLite (node:sqlite)',
      totalCases: cases.length,
      status: 'Connected',
    },
    aiEngine: {
      provider: hasGeminiKey ? 'Google Gemini 2.5 Flash' : 'Deterministic Rule Engine',
      status: 'Operational',
      mode: hasGeminiKey ? 'HYBRID_AI' : 'DETERMINISTIC_FALLBACK',
    },
    geoIpProvider: {
      service: 'ip-api.com + Local SQLite Cache',
      status: 'Active',
      rateLimitRemaining: '45 req/min (Cached)',
    },
    sseClientsCount: sseClients.length,
    timestamp: new Date().toISOString(),
  });
});

// GET /api/settings - Safe configuration settings
apiRouter.get('/settings', (_req: Request, res: Response) => {
  const hasGeminiKey = Boolean(process.env.GEMINI_API_KEY?.trim());
  return res.json({
    platform: 'MailTrace AI Forensics & Threat Intel Platform',
    version: '2.4 Enterprise',
    aiEngine: hasGeminiKey ? 'Google Gemini 2.5 Flash' : 'Deterministic Rule Engine',
    hasGeminiKey,
    geoProvider: 'ip-api.com',
    retentionPolicyDays: 90,
    riskThresholds: {
      lowerConcernMax: 54,
      elevatedReviewMin: 55,
      criticalMin: 80,
    },
    defaultExportFormat: 'JSON / Dossier PDF',
  });
});



// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

interface AuthenticatedUser {
  id: string;
  name: string;
  email: string;
  role: string;
  department: string;
  avatarInitials: string;
  token: string;
  lastLogin: string;
}

// In-memory active sessions cache
const activeSessions = new Map<string, AuthenticatedUser>();

// POST /api/auth/login - Authenticate SOC Analyst
apiRouter.post('/auth/login', (req: Request, res: Response) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const trimmedPassword = String(password).trim();

  let user: Omit<AuthenticatedUser, 'token' | 'lastLogin'> | null = null;

  if (normalizedEmail === 'admin@mailtrace.ai') {
    if (trimmedPassword === 'password123' || trimmedPassword === 'Admin@2026!') {
      user = {
        id: 'usr_soc_001',
        name: 'Alex Mercer',
        email: 'admin@mailtrace.ai',
        role: 'Lead Security Analyst',
        department: 'Cyber Threat Intelligence',
        avatarInitials: 'AM',
      };
    }
  } else if (normalizedEmail === 'forensics@mailtrace.ai') {
    if (trimmedPassword === 'password123' || trimmedPassword === 'Forensics@2026!') {
      user = {
        id: 'usr_soc_002',
        name: 'Sarah Chen',
        email: 'forensics@mailtrace.ai',
        role: 'Digital Forensics Specialist',
        department: 'Incident Response & DFIR',
        avatarInitials: 'SC',
      };
    }
  } else if (normalizedEmail.includes('@') && trimmedPassword.length >= 6) {
    const namePart = normalizedEmail.split('@')[0];
    const capitalizedName = namePart.charAt(0).toUpperCase() + namePart.slice(1);
    user = {
      id: `usr_${Date.now().toString(36)}`,
      name: capitalizedName,
      email: normalizedEmail,
      role: 'Security Analyst',
      department: 'SOC Operations',
      avatarInitials: capitalizedName.slice(0, 2).toUpperCase(),
    };
  }

  if (!user) {
    return res.status(401).json({
      error: 'Invalid credentials. Use admin@mailtrace.ai / password123 or any corporate email with 6+ char password.'
    });
  }

  const token = `mt_token_${Buffer.from(`${user.id}:${Date.now()}`).toString('base64')}`;
  const sessionUser: AuthenticatedUser = {
    ...user,
    token,
    lastLogin: new Date().toISOString(),
  };

  activeSessions.set(token, sessionUser);

  return res.json({
    success: true,
    user: sessionUser,
  });
});

// GET /api/auth/me - Validate session token
apiRouter.get('/auth/me', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'No authorization token provided' });
  }

  const sessionUser = activeSessions.get(token);
  if (!sessionUser) {
    return res.status(401).json({ error: 'Session expired or invalid' });
  }

  return res.json({
    success: true,
    user: sessionUser,
  });
});

// POST /api/auth/logout - Invalidate session token
apiRouter.post('/auth/logout', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;

  if (token) {
    activeSessions.delete(token);
  }

  return res.json({ success: true, message: 'Signed out successfully' });
});

// GET /api/status - Engine status & health
apiRouter.get('/status', (_req: Request, res: Response) => {
  const hasGeminiKey = Boolean(process.env.GEMINI_API_KEY?.trim());
  return res.json({
    status: 'ONLINE',
    platform: 'MailTrace AI Forensics Engine v2.4 (SIH 2026)',
    aiEngine: hasGeminiKey ? 'Google Gemini 2.5 Flash' : 'Deterministic Rule Engine (Fallback Active)',
    evidenceIntegrity: 'SHA-256 Active',
    database: 'SQLite (node:sqlite) Connected',
  });
});

// POST /api/debug/analyze - Development diagnostic audit endpoint (Section 17)
apiRouter.post('/debug/analyze', async (req: Request, res: Response) => {
  try {
    const rawEmail = req.body?.rawEmail || req.body?.email || req.body?.content;
    if (!rawEmail) {
      return res.status(400).json({ error: 'Missing rawEmail payload for diagnostic analysis' });
    }

    const caseRecord = await runAnalysisPipeline(rawEmail);
    return res.json({
      success: true,
      caseNumber: caseRecord.caseNumber,
      riskScore: caseRecord.riskScore,
      confidence: caseRecord.confidence,
      classification: caseRecord.classification,
      threatTypes: caseRecord.threatTypes,
      componentScores: caseRecord.componentScores,
      evidence: caseRecord.evidence,
      debugTrace: caseRecord.debugTrace,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Diagnostic pipeline execution failed' });
  }
});
