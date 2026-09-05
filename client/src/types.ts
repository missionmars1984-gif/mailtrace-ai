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

export type IpClassificationType =
  | 'PUBLIC'
  | 'PRIVATE'
  | 'LOOPBACK'
  | 'LINK_LOCAL'
  | 'MULTICAST'
  | 'DOCUMENTATION'
  | 'RESERVED'
  | 'UNSPECIFIED'
  | 'INVALID';

export type GeoLookupStatus =
  | 'resolved'
  | 'private_ip'
  | 'unavailable'
  | 'rate_limited'
  | 'lookup_failed'
  | 'timeout';

export interface NormalizedGeoLocation {
  ip: string;
  classification: IpClassificationType;
  geoAvailable: boolean;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  asn?: string;
  organization?: string;
  isp?: string;
  network?: string;
  provider?: string;
  error?: string;
}

export type ConfidenceLevel = 'VERY_LOW' | 'LOW' | 'MODERATE' | 'HIGH' | 'VERY_HIGH';

export type NetworkClassificationType =
  | 'RESIDENTIAL'
  | 'MOBILE'
  | 'CORPORATE'
  | 'EDUCATIONAL'
  | 'HOSTING'
  | 'CLOUD'
  | 'CDN'
  | 'VPN'
  | 'PROXY'
  | 'TOR'
  | 'PRIVACY_RELAY'
  | 'SECURITY_SCANNER'
  | 'UNKNOWN';

export interface LocationHypothesis {
  ip?: string;
  country: string | null;
  countryCode?: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracyRadiusKm: number;
  confidence: number;
  confidenceLevel: ConfidenceLevel;
  networkType: NetworkClassificationType;
  asn?: string | null;
  isp?: string | null;
  organization?: string | null;
  evidence: string[];
  limitations: string[];
  sourceSignals: string[];
  hypothesisType: 'INFRASTRUCTURE' | 'INTERACTION' | 'USER_ESTIMATE' | 'COMPETING';
}

export interface TrackingEvent {
  id: string;
  caseId: string;
  eventType: 'open' | 'click';
  ip: string;
  userAgent?: string;
  timestamp: string;
  isPrefetchOrProxy?: boolean;
  proxyType?: 'APPLE_MPP' | 'GOOGLE_PROXY' | 'SECURITY_SCANNER' | 'GENUINE_CLIENT' | 'UNKNOWN';
  targetUrl?: string;
  geo?: LocationHypothesis;
}

export interface MultiSignalGeoAttribution {
  sendingInfrastructure: LocationHypothesis | null;
  interactionLocation: LocationHypothesis | null;
  estimatedUserLocation: LocationHypothesis | null;
  competingHypotheses: LocationHypothesis[];
  anomalies: string[];
  limitations: string[];
  overallConfidence: number;
  overallConfidenceLevel: ConfidenceLevel;
  trackingEventsCount: number;
  lastInteractionAt?: string;
  impossibleTravelDetected?: boolean;
  scoringWeightsSnapshot?: Record<string, number>;
}

export interface GeoLocationData {
  ip?: string;
  country: string | null;
  countryCode?: string | null;
  region?: string | null;
  city?: string | null;
  postalCode?: string | null;
  lat?: number | null;
  lon?: number | null;
  latitude?: number | null;
  longitude?: number | null;
  timezone?: string | null;
  asn?: string | null;
  org?: string | null;
  organization?: string | null;
  isp?: string | null;
  network?: string | null;
  provider?: string | null;
  lookupTimestamp?: string;
  error?: string | null;
  isPrivate?: boolean;
  isPublic?: boolean;
  geoAvailable?: boolean;
  location?: string | null;
  reason?: string;
  ipType?: IpClassificationType;
  classification?: IpClassificationType;
  networkType?: NetworkClassificationType;
  lookupStatus?: GeoLookupStatus;
  statusMessage?: string;
  source?: string;
}

export interface RouteHop {
  hopNumber: number;
  hop?: number;
  from?: string;
  by?: string;
  hostname?: string;
  ip?: string;
  timestamp?: string;
  delayMs?: number;
  isPrivate?: boolean;
  isPublic?: boolean;
  geoAvailable?: boolean;
  location?: string | null;
  reason?: string;
  isOrigin?: boolean;
  isPublicOriginRelay?: boolean;
  ipType?: IpClassificationType;
  classification?: IpClassificationType;
  rawHopText?: string;
  rawReceivedHeader?: string;
  country?: string | null;
  countryCode?: string | null;
  region?: string | null;
  city?: string | null;
  postalCode?: string | null;
  lat?: number | null;
  lon?: number | null;
  latitude?: number | null;
  longitude?: number | null;
  asn?: string | null;
  org?: string | null;
  organization?: string | null;
  isp?: string | null;
  network?: string | null;
  provider?: string | null;
  error?: string | null;
  lookupStatus?: GeoLookupStatus;
  statusMessage?: string;
  networkType?: NetworkClassificationType;
  geo?: GeoLocationData;
}

export interface GeoPipelineDiagnostic {
  receivedHeadersFound: number;
  ipsExtracted: number;
  publicIps: number;
  privateIps: number;
  ipsSentToGeoIp: number;
  geoIpResponses: number;
  failedLookups: number;
  routeHops: number;
  observedPublicOriginRelay?: string;
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
  socialEngineeringRisk: number;
  threatIntelRisk?: number | null;
  contentRisk?: number;
  benignEvidence?: number;
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
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
}

export interface ScoreBreakdown {
  finalScore: number;
  riskLevel: RiskLevel;
  confidence: number;
  threatTypes?: string[];
  contributors?: ScoreContributor[];
  componentScores?: ComponentScores;
  whyHighRisk?: string;
  scoringReasons?: string[];
  appliedEscalationRules?: string[];
  benignEvidenceScore?: number;
  synergyBonus?: number;
  components?: any;
}

export interface NlpProbabilities {
  phishing: number;
  bec: number;
  spam: number;
  legitimate: number;
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
  subject?: string;
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
  modelAvailability?: any;
  debugTrace?: any;
  quarantineStatus?: 'QUARANTINED' | 'RELEASED' | 'NOT_QUARANTINED';
  quarantineReason?: string;
  quarantinedAt?: string;
  evidenceHash: string;
  reportHash: string;
  rawEmail?: string;
  rawHeaders?: Record<string, string | string[]>;
  observedOriginRelay?: RouteHop;
  geoDiagnostic?: GeoPipelineDiagnostic;
  claimedLocation?: string;
  observedLocation?: string;
  geoAttribution?: MultiSignalGeoAttribution;
  trackingEvents?: TrackingEvent[];
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

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  department: string;
  avatarInitials: string;
  token: string;
  lastLogin: string;
}

export interface AuthResponse {
  success: boolean;
  user: UserProfile;
  error?: string;
}
