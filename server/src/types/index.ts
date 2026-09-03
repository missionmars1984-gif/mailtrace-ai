export type ThreatClassification =
  | 'Clean'
  | 'Suspicious'
  | 'Phishing'
  | 'BEC'
  | 'Impersonation'
  | 'Malware'
  | 'Legitimate';

export type RiskLevel =
  | 'Clean'
  | 'Low Risk'
  | 'Suspicious'
  | 'High Risk'
  | 'Critical'
  | 'Lower Concern'
  | 'Elevated Review';

export type ConsistencyRating = 'HIGH' | 'MEDIUM' | 'LOW';

export interface EmailAddressInfo {
  name: string;
  address: string;
  domain?: string;
}

export interface AuthenticationResults {
  spf: { status: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unknown'; details?: string; raw?: string };
  dkim: { status: 'pass' | 'fail' | 'neutral' | 'none' | 'unknown'; details?: string; raw?: string };
  dmarc: { status: 'pass' | 'fail' | 'none' | 'unknown'; details?: string; raw?: string };
  raw?: string;
}

export interface GeoLocationData {
  country: string;
  countryCode?: string;
  region?: string;
  city?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  asn?: string;
  org?: string;
  isp?: string;
  isPrivate?: boolean;
  ipType?: 'PUBLIC' | 'PRIVATE' | 'LOOPBACK' | 'RESERVED';
}

export interface RouteHop {
  hopNumber: number;
  from?: string;
  by?: string;
  ip?: string;
  timestamp?: string;
  delayMs?: number;
  isPrivate?: boolean;
  isOrigin?: boolean;
  geo?: GeoLocationData;
}

export interface ParsedAttachment {
  filename: string;
  extension: string;
  contentType: string;
  size: number;
  sha256: string;
  isDangerous: boolean;
  isDoubleExtension: boolean;
  isMacro: boolean;
  riskReasons: string[];
}

export interface ParsedUrl {
  url: string;
  domain: string;
  protocol: string;
  isIpHost: boolean;
  isShortened: boolean;
  hasExcessiveSubdomains: boolean;
  isPunycode: boolean;
  hasSuspiciousKeywords: boolean;
  riskIndicators: string[];
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  entropy?: number;
  subdomainCount?: number;
  pathLength?: number;
  queryParamCount?: number;
}

export interface ClaimedIdentity {
  displayName: string;
  email: string;
  domain: string;
}

export interface ObservedIdentity {
  returnPath: string;
  replyTo: string;
  sendingIp?: string;
  sendingDomain?: string;
  authDomain?: string;
}

export interface IdentityAnalysis {
  claimed: ClaimedIdentity;
  observed: ObservedIdentity;
  consistency: ConsistencyRating;
  reasons: string[];
  replyToMismatch: boolean;
  returnPathMismatch: boolean;
  displayNameSpoofing: boolean;
  lookalikeDomain: boolean;
  lookalikeTarget?: string;
  punycodeDetected: boolean;
}

export interface SecurityFinding {
  type: 'IDENTITY' | 'PHISHING' | 'BEC' | 'URL' | 'ATTACHMENT' | 'INFRASTRUCTURE' | 'AUTH';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  source?: string;
  snippet?: string;
  observed: string;
  impact: string;
}

export interface NlpProbabilities {
  phishing: number;
  spear_phishing: number;
  bec: number;
  credential_theft: number;
  social_engineering: number;
  malware_delivery: number;
  spam: number;
  legitimate: number;
}

export interface SocialEngineeringSignals {
  urgency: number;
  authority: number;
  fear: number;
  secrecy: number;
  pressure: number;
  reward: number;
  curiosity: number;
  trustExploitation: number;
  procedureBypass: number;
  overallRisk: number;
  indicators: string[];
}

export interface ComponentScores {
  senderRisk: number;
  identityRisk: number;
  replyToRisk: number;
  urlRisk: number | null;
  nlpRisk: number;
  credentialRisk: number;
  mfaRisk: number;
  financialRisk: number;
  becRisk: number;
  brandRisk: number;
  attachmentRisk: number | null;
  headerRisk: number;
  authenticationRisk?: number;
  socialEngineeringRisk: number;
  threatIntelRisk?: number | null;
  contentRisk?: number;
  benignEvidence?: number;
}

export interface ModelAvailability {
  nlp: string;
  url: string;
  identity: string;
  bec: string;
  attachment: string;
  header: string;
  socialEngineering: string;
}

export interface DebugTrace {
  input: {
    from: string;
    to: string[];
    replyTo?: string;
    returnPath?: string;
    subject: string;
    bodyLength: number;
    urlCount: number;
    attachmentCount: number;
    hopCount: number;
  };
  extractedFeatures: Record<string, any>;
  nlpOutput: NlpProbabilities;
  urlOutput: {
    urlRisk: number;
    highestRiskUrl?: string;
    urlCount: number;
    features: any[];
  };
  identityOutput: {
    identityRisk: number;
    claimedIdentity: string;
    observedIdentity: string;
    identityConsistency: number;
    inconsistencies: string[];
  };
  headerOutput: {
    authenticationRisk: number;
    spf: string;
    dkim: string;
    dmarc: string;
    routingAnomalies: string[];
  };
  becOutput: {
    becRisk: number;
    indicators: string[];
    monetarySignals: string[];
  };
  attachmentOutput: {
    attachmentRisk: number | null;
    count: number;
    dangerousCount: number;
  };
  socialEngineeringOutput: SocialEngineeringSignals;
  evidenceFusion: {
    weightedBase: number;
    synergyBonus: number;
    escalationRulesApplied: string[];
    benignDiscount: number;
    calibratedScore: number;
    modelAgreementScore: number;
  };
  finalRisk: {
    riskScore: number;
    confidence: number;
    classification: string;
  };
}

export interface EvidenceItem {
  finding: string;
  source: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  explanation: string;
  observed?: string;
}

export interface ScoreContributor {
  name: string;
  points: number;
  source: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
}

export interface ScoreBreakdown {
  finalScore: number;
  riskLevel: RiskLevel;
  confidence: number;
  contributors?: ScoreContributor[];
  componentScores?: ComponentScores;
  synergyBonus?: number;
  whyHighRisk?: string;
  scoringReasons: string[];
  components: {
    identityScore: number;
    authScore: number;
    threatContentScore: number;
    urlScore: number;
    attachmentScore: number;
    infrastructureScore: number;
    synergyScore?: number;
    aiInfluenceScore: number;
  };
}

export interface ThreatIntelligence {
  status: string;
  hasExternalFeed: boolean;
  notes: string;
}

export interface AiAssessment {
  classification: ThreatClassification;
  risk_score: number;
  confidence: number;
  summary: string;
  key_findings: string[];
  identity_assessment: string;
  phishing_indicators: string[];
  bec_indicators: string[];
  recommended_actions: string[];
  isFallback: boolean;
  nlpProbabilities?: NlpProbabilities;
}

export interface IOCItem {
  type: 'IP' | 'DOMAIN' | 'URL' | 'EMAIL' | 'HASH' | 'ATTACHMENT';
  value: string;
  context: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'email' | 'sender' | 'domain' | 'ip' | 'asn' | 'geo' | 'url' | 'attachment' | 'hash';
  riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

export interface CorrelationGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface CaseRecord {
  id: string;
  caseNumber: string;
  createdAt: string;
  metadata: {
    from: EmailAddressInfo;
    to: EmailAddressInfo[];
    cc?: EmailAddressInfo[];
    bcc?: EmailAddressInfo[];
    replyTo?: EmailAddressInfo;
    returnPath?: string;
    subject: string;
    date?: string;
    messageId?: string;
    auth: AuthenticationResults;
  };
  classification: ThreatClassification;
  riskScore: number;
  riskLevel: RiskLevel;
  confidence: number;
  threatTypes: string[];
  claimedIdentity: string;
  observedIdentity: string;
  identityConsistency: number;
  componentScores: ComponentScores;
  evidence: EvidenceItem[];
  indicators: string[];
  extractedIOCs: IOCItem[];
  campaignIndicators: string[];
  quarantineRecommendation: boolean;
  recommendedAction: string;
  summary: string;
  keyFindings: string[];
  identityAnalysis: IdentityAnalysis;
  findings: SecurityFinding[];
  urls: ParsedUrl[];
  attachments: ParsedAttachment[];
  hops: RouteHop[];
  iocs: IOCItem[];
  graph: CorrelationGraph;
  aiAssessment: AiAssessment;
  scoreBreakdown?: ScoreBreakdown;
  modelAvailability?: ModelAvailability;
  debugTrace?: DebugTrace;
  quarantineStatus?: 'QUARANTINED' | 'RELEASED' | 'NOT_QUARANTINED';
  quarantineReason?: string;
  quarantinedAt?: string;
  evidenceHash: string;
  reportHash: string;
  rawEmail?: string;
  rawHeaders?: Record<string, string | string[]>;
}

export interface DashboardStats {
  totalScanned: number;
  emailsAnalyzed?: number;
  threatsDetected: number;
  highRiskCount: number;
  criticalCount: number;
  quarantined: number;
  averageRisk: number;
  riskDistribution: {
    safe: number;
    suspicious: number;
    highRisk: number;
    critical: number;
  };
  classificationDistribution: {
    clean: number;
    phishing: number;
    bec: number;
    impersonation: number;
    malware: number;
    suspicious: number;
    legitimate?: number;
  };
  threatActivityTrend: Array<{ date: string; scanned: number; threats: number }>;
  recentCases: Array<{
    id: string;
    caseNumber: string;
    from: string;
    subject: string;
    classification: ThreatClassification;
    riskScore: number;
    riskLevel: RiskLevel;
    date: string;
    status: string;
  }>;
}

export interface ThreatMapNode {
  ip: string;
  country: string;
  countryCode?: string;
  region?: string;
  city?: string;
  lat: number;
  lon: number;
  isp?: string;
  asn?: string;
  org?: string;
  isPrivate: boolean;
  caseCount: number;
  riskScore: number;
  cases: Array<{ id: string; caseNumber: string; classification: ThreatClassification; riskScore: number }>;
}

export interface ThreatMapData {
  nodes: ThreatMapNode[];
  stats: {
    observablePublicNodes: number;
    autonomousSystems: number;
    geolocatedJurisdictions: number;
    localLoopbackFiltered: number;
  };
}

export interface CampaignCluster {
  id: string;
  name: string;
  threatType: ThreatClassification;
  riskLevel?: RiskLevel;
  description: string;
  commonIndicatorType: 'IP' | 'DOMAIN' | 'URL' | 'SENDER' | 'SUBJECT' | 'HASH';
  commonIndicatorValue: string;
  caseCount: number;
  caseIds: string[];
  cases: Array<{ id: string; caseNumber: string; subject: string; riskScore: number; date: string; from?: string; classification?: string }>;
  firstSeen: string;
  lastSeen: string;
  targetedDepartments: string[];
  matchConfidence: number;
  whyLinked: string;
  commonSenders?: string[];
  commonDomains?: string[];
  commonUrls?: string[];
  commonSubjects?: string[];
  commonIndicators?: string[];
}

export interface ReportRecord {
  id: string;
  caseId: string;
  caseNumber: string;
  dossierId: string;
  classification: ThreatClassification;
  riskScore: number;
  riskLevel: RiskLevel;
  evidenceHash: string;
  reportHash: string;
  generatedAt: string;
  sizeBytes: number;
  title: string;
  summary: string;
  data?: CaseRecord;
}

export interface AssistantMessage {
  id: string;
  caseId?: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}



export interface SystemEngineStatus {
  status: string;
  platform: string;
  aiEngine: string;
  evidenceIntegrity: string;
  database: string;
}
