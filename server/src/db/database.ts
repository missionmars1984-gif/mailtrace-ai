import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import type {
  CaseRecord,
  DashboardStats,
  IOCItem,
  ThreatClassification,
  RiskLevel,
  GeoLocationData,
  ThreatMapData,
  ThreatMapNode,
  ReportRecord,
  CampaignCluster,
  AssistantMessage,
  TrackingEvent,
} from '../types/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbDir = path.resolve(__dirname, '../../data');

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, 'mailtrace.db');
const db = new DatabaseSync(dbPath);

// Enable WAL mode & busy timeout for concurrent multi-process access
try {
  db.exec(`PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;`);
} catch {}

// Initialize comprehensive schema
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    message_id TEXT,
    provider_message_id TEXT,
    thread_id TEXT,
    folder TEXT NOT NULL,
    from_name TEXT,
    from_addr TEXT NOT NULL,
    to_json TEXT NOT NULL,
    cc_json TEXT,
    bcc_json TEXT,
    reply_to TEXT,
    subject TEXT,
    snippet TEXT,
    body_text TEXT,
    body_html TEXT,
    date TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    is_starred INTEGER DEFAULT 0,
    has_attachments INTEGER DEFAULT 0,
    raw_source TEXT,
    source TEXT DEFAULT 'mailpit',
    delivery_status TEXT DEFAULT 'DELIVERED TO MAILBOX',
    risk_score INTEGER,
    risk_level TEXT,
    threat_classification TEXT,
    case_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS message_attachments (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    data BLOB,
    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS exchange_sync_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_messages_msg_id ON messages(message_id);
  CREATE INDEX IF NOT EXISTS idx_messages_provider_id ON messages(provider_message_id);
  CREATE INDEX IF NOT EXISTS idx_messages_thread_id ON messages(thread_id);
  CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date DESC);
  CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(from_addr);
  CREATE INDEX IF NOT EXISTS idx_messages_folder ON messages(folder);
  CREATE INDEX IF NOT EXISTS idx_messages_risk ON messages(risk_score);

  CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    case_number TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL,
    sender_from TEXT NOT NULL,
    subject TEXT NOT NULL,
    classification TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    summary TEXT NOT NULL,
    data_json TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    report_hash TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS indicators (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT NOT NULL,
    severity TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS geo_locations (
    ip TEXT PRIMARY KEY,
    country TEXT NOT NULL,
    country_code TEXT,
    region TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    timezone TEXT,
    isp TEXT,
    org TEXT,
    asn TEXT,
    is_private INTEGER NOT NULL DEFAULT 0,
    ip_type TEXT NOT NULL DEFAULT 'PUBLIC',
    lookup_status TEXT NOT NULL DEFAULT 'resolved',
    status_message TEXT,
    cached_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    case_number TEXT NOT NULL,
    dossier_id TEXT UNIQUE NOT NULL,
    classification TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    report_hash TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    data_json TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS assistant_messages (
    id TEXT PRIMARY KEY,
    case_id TEXT,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS tracking_events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT,
    timestamp TEXT NOT NULL,
    is_proxy INTEGER DEFAULT 0,
    proxy_type TEXT,
    target_url TEXT,
    data_json TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_indicators_case ON indicators(case_id);
  CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type);
  CREATE INDEX IF NOT EXISTS idx_indicators_val ON indicators(value);
  CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(generated_at DESC);
  CREATE INDEX IF NOT EXISTS idx_tracking_events_case ON tracking_events(case_id);
  CREATE INDEX IF NOT EXISTS idx_tracking_events_time ON tracking_events(timestamp DESC);
`);

try {
  db.exec(`PRAGMA foreign_keys = OFF;`);
} catch {}
try {
  db.exec(`ALTER TABLE geo_locations ADD COLUMN lookup_status TEXT DEFAULT 'resolved'`);
} catch {}
try {
  db.exec(`ALTER TABLE geo_locations ADD COLUMN status_message TEXT`);
} catch {}
try {
  db.exec(`
    DELETE FROM geo_locations WHERE 
      ip LIKE '10.%' OR 
      ip LIKE '192.168.%' OR 
      ip LIKE '127.%' OR 
      ip LIKE '169.254.%' OR
      is_private = 1
  `);
} catch {}

export class DatabaseService {
  /**
   * Saves or updates a case and persists extracted indicators and default forensic report.
   */
  static saveCase(record: CaseRecord): void {
    const insertCaseStmt = db.prepare(`
      INSERT OR REPLACE INTO cases (
        id, case_number, created_at, sender_from, subject,
        classification, risk_score, risk_level, confidence,
        summary, data_json, evidence_hash, report_hash
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?
      )
    `);

    insertCaseStmt.run(
      record.id,
      record.caseNumber,
      record.createdAt,
      `${record.metadata.from.name ? record.metadata.from.name + ' <' : ''}${record.metadata.from.address}${record.metadata.from.name ? '>' : ''}`,
      record.metadata.subject,
      record.classification,
      record.riskScore,
      record.riskLevel,
      record.confidence,
      record.summary,
      JSON.stringify(record),
      record.evidenceHash,
      record.reportHash
    );

    // Save indicators
    const deleteIndicatorsStmt = db.prepare(`DELETE FROM indicators WHERE case_id = ?`);
    deleteIndicatorsStmt.run(record.id);

    const insertIndicatorStmt = db.prepare(`
      INSERT INTO indicators (id, case_id, type, value, context, severity)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    for (const [index, ioc] of record.iocs.entries()) {
      insertIndicatorStmt.run(
        `${record.id}-${index}-${Date.now()}`,
        record.id,
        ioc.type,
        ioc.value,
        ioc.context,
        ioc.severity
      );
    }

    // Automatically generate and store official forensic report dossier
    const dossierId = `DOSSIER-${record.caseNumber}`;
    const reportRecord: ReportRecord = {
      id: `rep_${record.id}`,
      caseId: record.id,
      caseNumber: record.caseNumber,
      dossierId,
      classification: record.classification,
      riskScore: record.riskScore,
      riskLevel: record.riskLevel,
      evidenceHash: record.evidenceHash,
      reportHash: record.reportHash,
      generatedAt: record.createdAt,
      sizeBytes: Buffer.byteLength(JSON.stringify(record), 'utf-8'),
      title: `Forensic Incident Dossier: ${record.metadata.subject}`,
      summary: record.summary,
    };

    const insertReportStmt = db.prepare(`
      INSERT OR REPLACE INTO reports (
        id, case_id, case_number, dossier_id, classification,
        risk_score, risk_level, evidence_hash, report_hash,
        generated_at, size_bytes, title, summary, data_json
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?
      )
    `);

    insertReportStmt.run(
      reportRecord.id,
      reportRecord.caseId,
      reportRecord.caseNumber,
      reportRecord.dossierId,
      reportRecord.classification,
      reportRecord.riskScore,
      reportRecord.riskLevel,
      reportRecord.evidenceHash,
      reportRecord.reportHash,
      reportRecord.generatedAt,
      reportRecord.sizeBytes,
      reportRecord.title,
      reportRecord.summary,
      JSON.stringify(record)
    );
  }

  static getCaseById(idOrCaseNumber: string): CaseRecord | null {
    const stmt = db.prepare(`
      SELECT data_json FROM cases
      WHERE id = ? OR case_number = ?
      LIMIT 1
    `);
    const row = stmt.get(idOrCaseNumber, idOrCaseNumber) as { data_json: string } | undefined;
    if (!row) return null;
    try {
      const record = JSON.parse(row.data_json) as CaseRecord;
      if (!record.observedOriginRelay && record.hops && record.hops.length > 0) {
        const publicHop = record.hops.find((h) => h.ip && !h.isPrivate);
        if (publicHop) {
          publicHop.isPublicOriginRelay = true;
          record.observedOriginRelay = publicHop;
        } else {
          record.observedOriginRelay = record.hops[0];
        }
      }
      return record;
    } catch {
      return null;
    }
  }

  static getCachedGeoLocation(ip: string): GeoLocationData | null {
    if (!ip) return null;
    try {
      const stmt = db.prepare(`SELECT * FROM geo_locations WHERE ip = ?`);
      const row = stmt.get(ip.trim()) as any;
      if (!row) return null;

      // TTL of 7 days for public cached coordinates
      const cachedAt = new Date(row.cached_at).getTime();
      if (Date.now() - cachedAt > 7 * 24 * 60 * 60 * 1000) {
        return null;
      }

      const lat = typeof row.lat === 'number' ? row.lat : undefined;
      const lon = typeof row.lon === 'number' ? row.lon : undefined;
      const isPrivate = Boolean(row.is_private);
      const isResolved = row.lookup_status === 'resolved';
      const geoAvailable = isResolved && lat !== undefined && lon !== undefined && !(lat === 0 && lon === 0);

      return {
        ip: row.ip,
        country: row.country,
        countryCode: row.country_code || undefined,
        region: row.region || undefined,
        city: row.city || undefined,
        lat,
        lon,
        latitude: lat,
        longitude: lon,
        timezone: row.timezone || undefined,
        isp: row.isp || undefined,
        org: row.org || undefined,
        organization: row.org || row.isp || undefined,
        asn: row.asn || undefined,
        isPrivate,
        isPublic: !isPrivate,
        geoAvailable,
        location: row.city ? `${row.city}, ${row.country}` : row.country,
        reason: isPrivate ? 'Private/internal IP' : undefined,
        ipType: row.ip_type,
        classification: row.ip_type,
        lookupStatus: row.lookup_status || 'resolved',
        statusMessage: row.status_message || undefined,
        source: 'sqlite_cache',
      };
    } catch (err) {
      console.warn(`[DatabaseService] Error reading geo cache for ${ip}:`, err);
      return null;
    }
  }

  static cacheGeoLocation(ip: string, geo: GeoLocationData): void {
    if (!ip || geo.isPrivate) return;
    try {
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO geo_locations (
          ip, country, country_code, region, city,
          lat, lon, timezone, isp, org,
          asn, is_private, ip_type, lookup_status, status_message, cached_at
        ) VALUES (
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?
        )
      `);
      stmt.run(
        ip.trim(),
        geo.country || 'Location Unresolved',
        geo.countryCode || null,
        geo.region || null,
        geo.city || null,
        typeof geo.lat === 'number' ? geo.lat : null,
        typeof geo.lon === 'number' ? geo.lon : null,
        geo.timezone || null,
        geo.isp || null,
        geo.org || null,
        geo.asn || null,
        geo.isPrivate ? 1 : 0,
        geo.ipType || 'PUBLIC',
        geo.lookupStatus || 'resolved',
        geo.statusMessage || null,
        new Date().toISOString()
      );
    } catch (err) {
      console.warn(`[DatabaseService] cacheGeoLocation error for ${ip}:`, err);
    }
  }

  static saveTrackingEvent(event: TrackingEvent): void {
    try {
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO tracking_events (
          id, case_id, event_type, ip, user_agent, timestamp, is_proxy, proxy_type, target_url, data_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        event.id,
        event.caseId,
        event.eventType,
        event.ip,
        event.userAgent || null,
        event.timestamp,
        event.isPrefetchOrProxy ? 1 : 0,
        event.proxyType || null,
        event.targetUrl || null,
        JSON.stringify(event)
      );
    } catch (err) {
      console.warn(`[DatabaseService] saveTrackingEvent error:`, err);
    }
  }

  static getTrackingEventsForCase(caseId: string): TrackingEvent[] {
    try {
      const stmt = db.prepare(`SELECT data_json FROM tracking_events WHERE case_id = ? ORDER BY timestamp ASC`);
      const rows = stmt.all(caseId) as Array<{ data_json: string }>;
      return rows.map((r) => JSON.parse(r.data_json));
    } catch {
      return [];
    }
  }

  static getCasesBySenderDomain(domain: string): CaseRecord[] {
    if (!domain) return [];
    try {
      const pattern = `%@${domain}%`;
      const stmt = db.prepare(`SELECT data_json FROM cases WHERE sender_from LIKE ? ORDER BY created_at DESC LIMIT 20`);
      const rows = stmt.all(pattern) as Array<{ data_json: string }>;
      return rows.map((r) => JSON.parse(r.data_json));
    } catch {
      return [];
    }
  }

  static getCasesBySenderAddress(address: string): CaseRecord[] {
    if (!address) return [];
    try {
      const pattern = `%${address}%`;
      const stmt = db.prepare(`SELECT data_json FROM cases WHERE sender_from LIKE ? ORDER BY created_at DESC LIMIT 20`);
      const rows = stmt.all(pattern) as Array<{ data_json: string }>;
      return rows.map((r) => JSON.parse(r.data_json));
    } catch {
      return [];
    }
  }

  static getAllCases(options?: { search?: string; classification?: string; limit?: number }): CaseRecord[] {
    let sql = `SELECT data_json FROM cases`;
    const params: any[] = [];
    const conditions: string[] = [];

    if (options?.search) {
      conditions.push(`(case_number LIKE ? OR sender_from LIKE ? OR subject LIKE ?)`);
      const searchPattern = `%${options.search}%`;
      params.push(searchPattern, searchPattern, searchPattern);
    }

    if (options?.classification && options.classification !== 'ALL') {
      conditions.push(`classification = ?`);
      params.push(options.classification);
    }

    if (conditions.length > 0) {
      sql += ` WHERE ` + conditions.join(' AND ');
    }

    sql += ` ORDER BY created_at DESC`;

    if (options?.limit && options.limit > 0) {
      sql += ` LIMIT ?`;
      params.push(options.limit);
    }

    const stmt = db.prepare(sql);
    const rows = stmt.all(...params) as Array<{ data_json: string }>;
    return rows.map((r) => {
      const record = JSON.parse(r.data_json) as CaseRecord;
      if (!record.observedOriginRelay && record.hops && record.hops.length > 0) {
        const publicHop = record.hops.find((h) => h.ip && !h.isPrivate);
        if (publicHop) {
          publicHop.isPublicOriginRelay = true;
          record.observedOriginRelay = publicHop;
        } else {
          record.observedOriginRelay = record.hops[0];
        }
      }
      return record;
    });
  }

  static deleteCase(idOrCaseNumber: string): boolean {
    const targetCase = this.getCaseById(idOrCaseNumber);
    if (!targetCase) return false;

    db.exec('BEGIN TRANSACTION');
    try {
      db.prepare(`DELETE FROM indicators WHERE case_id = ?`).run(targetCase.id);
      db.prepare(`DELETE FROM reports WHERE case_id = ?`).run(targetCase.id);
      const res = db.prepare(`DELETE FROM cases WHERE id = ? OR case_number = ?`).run(targetCase.id, targetCase.caseNumber);
      db.exec('COMMIT');
      return (res.changes ?? 0) > 0;
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  static deleteAllCases(): boolean {
    db.exec('BEGIN TRANSACTION');
    try {
      db.exec(`DELETE FROM indicators;`);
      db.exec(`DELETE FROM reports;`);
      db.exec(`DELETE FROM cases;`);
      db.exec('COMMIT');
      return true;
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  static getCaseIndicators(caseId: string): IOCItem[] {
    const stmt = db.prepare(`
      SELECT type, value, context, severity FROM indicators
      WHERE case_id = ?
    `);
    const rows = stmt.all(caseId) as Array<{ type: string; value: string; context: string; severity: string }>;
    return rows.map((r) => ({
      type: r.type as IOCItem['type'],
      value: r.value,
      context: r.context,
      severity: r.severity as IOCItem['severity'],
    }));
  }

  /**
   * Retrieves aggregated indicators across all analyzed cases.
   */
  static getAllIndicators(search?: string, typeFilter?: string): Array<{
    value: string;
    type: string;
    severity: string;
    count: number;
    cases: Array<{ id: string; caseNumber: string; riskScore: number }>;
    firstObserved: string;
    context: string;
  }> {
    const cases = this.getAllCases();
    const map = new Map<string, {
      value: string;
      type: string;
      severity: string;
      count: number;
      cases: Array<{ id: string; caseNumber: string; riskScore: number }>;
      firstObserved: string;
      context: string;
    }>();

    for (const c of cases) {
      for (const ioc of c.iocs) {
        const key = `${ioc.type}:::${ioc.value}`;
        if (!map.has(key)) {
          map.set(key, {
            value: ioc.value,
            type: ioc.type,
            severity: ioc.severity,
            count: 1,
            cases: [{ id: c.id, caseNumber: c.caseNumber, riskScore: c.riskScore }],
            firstObserved: c.createdAt,
            context: ioc.context,
          });
        } else {
          const item = map.get(key)!;
          item.count++;
          if (!item.cases.some(existing => existing.id === c.id)) {
            item.cases.push({ id: c.id, caseNumber: c.caseNumber, riskScore: c.riskScore });
          }
          if (ioc.severity === 'HIGH' || (ioc.severity === 'MEDIUM' && item.severity === 'LOW')) {
            item.severity = ioc.severity;
          }
        }
      }
    }

    let list = Array.from(map.values());

    if (typeFilter && typeFilter !== 'ALL') {
      list = list.filter(i => i.type.toUpperCase() === typeFilter.toUpperCase());
    }

    if (search && search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(i => i.value.toLowerCase().includes(q) || i.context.toLowerCase().includes(q));
    }

    return list.sort((a, b) => b.count - a.count);
  }

  /**
   * Retrieves a specific indicator by exact or partial value.
   */
  static getIndicatorByValue(val: string): {
    value: string;
    type: string;
    severity: string;
    count: number;
    cases: Array<{ id: string; caseNumber: string; riskScore: number; subject: string; date: string }>;
  } | null {
    const cases = this.getAllCases();
    const clean = val.trim().toLowerCase();
    const matchedCases: Array<{ id: string; caseNumber: string; riskScore: number; subject: string; date: string }> = [];
    let detectedType = 'UNKNOWN';
    let highestSeverity = 'LOW';

    for (const c of cases) {
      for (const ioc of c.iocs) {
        if (ioc.value.toLowerCase() === clean || ioc.value.toLowerCase().includes(clean)) {
          detectedType = ioc.type;
          if (ioc.severity === 'HIGH' || (ioc.severity === 'MEDIUM' && highestSeverity === 'LOW')) {
            highestSeverity = ioc.severity;
          }
          if (!matchedCases.some(existing => existing.id === c.id)) {
            matchedCases.push({
              id: c.id,
              caseNumber: c.caseNumber,
              riskScore: c.riskScore,
              subject: c.metadata.subject,
              date: c.createdAt,
            });
          }
        }
      }
    }

    if (matchedCases.length === 0) return null;

    return {
      value: val,
      type: detectedType,
      severity: highestSeverity,
      count: matchedCases.length,
      cases: matchedCases,
    };
  }

  /**
   * Retrieves data specifically for the interactive Threat Map.
   */
  static getThreatMapData(): ThreatMapData {
    const cases = this.getAllCases();
    const map = new Map<string, ThreatMapNode>();

    let observablePublicNodes = 0;
    const autonomousSystemsSet = new Set<string>();
    const jurisdictionsSet = new Set<string>();
    let localLoopbackFiltered = 0;

    for (const c of cases) {
      for (const hop of c.hops) {
        if (!hop.ip) continue;
        const ip = hop.ip;
        const isRfcPrivate =
          ip.startsWith('10.') ||
          ip.startsWith('192.168.') ||
          ip.startsWith('127.') ||
          ip.startsWith('169.254.') ||
          /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
          ip === '::1' ||
          ip.startsWith('fe80:') ||
          ip.startsWith('fc') ||
          ip.startsWith('fd');
        const isPrivate = Boolean(hop.isPrivate) || isRfcPrivate;

        if (isPrivate) {
          localLoopbackFiltered++;
          continue;
        }

        const geo = DatabaseService.getCachedGeoLocation(ip) || hop.geo;
        const lat = geo?.lat;
        const lon = geo?.lon;

        // Valid public geolocated coordinate
        if (
          typeof lat === 'number' &&
          typeof lon === 'number' &&
          !isNaN(lat) &&
          !isNaN(lon) &&
          lat >= -90 &&
          lat <= 90 &&
          lon >= -180 &&
          lon <= 180 &&
          !(lat === 0 && lon === 0)
        ) {
          if (geo?.country) jurisdictionsSet.add(geo.country);
          if (geo?.asn) autonomousSystemsSet.add(geo.asn);

          if (!map.has(ip)) {
            observablePublicNodes++;
            map.set(ip, {
              ip,
              country: geo?.country || 'Unknown Jurisdiction',
              countryCode: geo?.countryCode || undefined,
              region: geo?.region || undefined,
              city: geo?.city || undefined,
              lat,
              lon,
              isp: geo?.isp || geo?.org || undefined,
              asn: geo?.asn || undefined,
              org: geo?.org || undefined,
              isPrivate: false,
              caseCount: 1,
              riskScore: c.riskScore,
              cases: [{ id: c.id, caseNumber: c.caseNumber, classification: c.classification, riskScore: c.riskScore }],
            });
          } else {
            const existing = map.get(ip)!;
            existing.caseCount++;
            existing.riskScore = Math.max(existing.riskScore, c.riskScore);
            if (!existing.cases.some(item => item.id === c.id)) {
              existing.cases.push({ id: c.id, caseNumber: c.caseNumber, classification: c.classification, riskScore: c.riskScore });
            }
          }
        }
      }
    }

    return {
      nodes: Array.from(map.values()),
      stats: {
        observablePublicNodes,
        autonomousSystems: autonomousSystemsSet.size,
        geolocatedJurisdictions: jurisdictionsSet.size,
        localLoopbackFiltered,
      },
    };
  }

  /**
   * Retrieves all quarantined cases from database.
   */
  static getQuarantinedCases(): CaseRecord[] {
    const cases = this.getAllCases();
    return cases.filter((c) => {
      if (c.quarantineStatus === 'RELEASED') return false;
      if (c.quarantineStatus === 'QUARANTINED') return true;
      return c.quarantineRecommendation || c.riskScore >= 75 || c.classification === 'Malware';
    });
  }

  /**
   * Updates quarantine status of a case.
   */
  static updateQuarantineStatus(
    caseId: string,
    status: 'QUARANTINED' | 'RELEASED' | 'NOT_QUARANTINED',
    reason?: string
  ): boolean {
    const caseRecord = this.getCaseById(caseId);
    if (!caseRecord) return false;

    caseRecord.quarantineStatus = status;
    if (reason) caseRecord.quarantineReason = reason;
    if (status === 'QUARANTINED') {
      caseRecord.quarantinedAt = new Date().toISOString();
    }

    const stmt = db.prepare(`
      UPDATE cases
      SET data_json = ?
      WHERE id = ? OR case_number = ?
    `);
    stmt.run(JSON.stringify(caseRecord), caseId, caseId);
    return true;
  }

  /**
   * Analyzes cases and clusters them into evidence-backed campaign relationships.
   * Multi-signal correlation: shared URLs, lookalike targets, sending IPs, attachment hashes, and subject pretexts.
   */
  static getCampaigns(): CampaignCluster[] {
    const cases = this.getAllCases();
    const clusters: CampaignCluster[] = [];

    const inferDepartment = (c: CaseRecord): string => {
      const text = `${c.metadata.subject} ${c.metadata.to.map(t => t.address).join(' ')} ${c.metadata.from.address}`.toLowerCase();
      if (/invoice|payment|wire|bank|remittance|cfo|treasury|payroll/i.test(text)) return 'Finance & Accounting';
      if (/hr|compensation|w-2|salary|benefits|employee|pto/i.test(text)) return 'Human Resources';
      if (/password|vpn|m365|azure|security|helpdesk|it support|admin/i.test(text)) return 'Information Technology';
      if (/dhl|fedex|shipment|delivery|customs|order/i.test(text)) return 'Supply Chain & Logistics';
      if (/legal|docusign|contract|nda|agreement/i.test(text)) return 'Legal & Compliance';
      return 'General Employees';
    };

    // 1. Cluster by Lookalike / Typosquatted Target Domain
    const lookalikeMap = new Map<string, CaseRecord[]>();
    for (const c of cases) {
      if (c.identityAnalysis.lookalikeDomain && c.identityAnalysis.lookalikeTarget) {
        const target = c.identityAnalysis.lookalikeTarget;
        const list = lookalikeMap.get(target) || [];
        list.push(c);
        lookalikeMap.set(target, list);
      }
    }

    for (const [target, matchedCases] of lookalikeMap.entries()) {
      const depts = Array.from(new Set(matchedCases.map(inferDepartment)));
      const commonSenders = Array.from(new Set(matchedCases.map(c => c.metadata.from.address)));
      const commonUrls = Array.from(new Set(matchedCases.flatMap(c => c.urls.map(u => u.domain))));
      const maxScore = Math.max(...matchedCases.map(c => c.riskScore));

      clusters.push({
        id: `camp-target-${target.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
        name: `Brand Impersonation Syndicate: ${target.toUpperCase()}`,
        threatType: 'Impersonation',
        riskLevel: maxScore >= 81 ? 'Critical' : 'High Risk',
        description: `Coordinated brand spoofing campaigns deploying typosquatted infrastructure mimicking official ${target} communication channels.`,
        commonIndicatorType: 'DOMAIN',
        commonIndicatorValue: target,
        caseCount: matchedCases.length,
        caseIds: matchedCases.map(c => c.id),
        cases: matchedCases.map(c => ({
          id: c.id,
          caseNumber: c.caseNumber,
          subject: c.metadata.subject,
          from: c.metadata.from.address,
          riskScore: c.riskScore,
          classification: c.classification,
          date: c.createdAt,
        })),
        firstSeen: matchedCases[matchedCases.length - 1].createdAt,
        lastSeen: matchedCases[0].createdAt,
        targetedDepartments: depts,
        matchConfidence: 94,
        whyLinked: `All ${matchedCases.length} emails exploit lookalike typosquatted domains designed to mimic ${target} authentication portals and deceive employee trust.`,
        commonSenders,
        commonDomains: [target],
        commonUrls,
        commonIndicators: [target, ...commonSenders.slice(0, 3)],
      });
    }

    // 2. Cluster by Shared Attack Domain in URLs
    const domainMap = new Map<string, CaseRecord[]>();
    for (const c of cases) {
      for (const u of c.urls) {
        if (u.riskLevel === 'HIGH' || u.riskLevel === 'MEDIUM' || u.hasSuspiciousKeywords || u.isIpHost) {
          const list = domainMap.get(u.domain) || [];
          if (!list.some(existing => existing.id === c.id)) {
            list.push(c);
            domainMap.set(u.domain, list);
          }
        }
      }
    }

    for (const [domain, matchedCases] of domainMap.entries()) {
      if (matchedCases.length >= 2) {
        const depts = Array.from(new Set(matchedCases.map(inferDepartment)));
        const commonSenders = Array.from(new Set(matchedCases.map(c => c.metadata.from.address)));
        const commonSubjects = Array.from(new Set(matchedCases.map(c => c.metadata.subject)));
        const maxScore = Math.max(...matchedCases.map(c => c.riskScore));

        clusters.push({
          id: `camp-domain-${domain.replace(/[^a-zA-Z0-9]/g, '-')}`,
          name: `Shared Phishing Infrastructure: ${domain}`,
          threatType: 'Phishing',
          riskLevel: maxScore >= 81 ? 'Critical' : 'High Risk',
          description: `Discovered identical high-risk credential harvesting URL domain embedded across multiple separate incoming emails.`,
          commonIndicatorType: 'URL',
          commonIndicatorValue: domain,
          caseCount: matchedCases.length,
          caseIds: matchedCases.map(c => c.id),
          cases: matchedCases.map(c => ({
            id: c.id,
            caseNumber: c.caseNumber,
            subject: c.metadata.subject,
            from: c.metadata.from.address,
            riskScore: c.riskScore,
            classification: c.classification,
            date: c.createdAt,
          })),
          firstSeen: matchedCases[matchedCases.length - 1].createdAt,
          lastSeen: matchedCases[0].createdAt,
          targetedDepartments: depts,
          matchConfidence: 96,
          whyLinked: `Multiple recipients received emails leading to the identical credential harvesting server host: "${domain}".`,
          commonSenders,
          commonDomains: [domain],
          commonUrls: [domain],
          commonSubjects,
          commonIndicators: [domain, ...commonSenders.slice(0, 2)],
        });
      }
    }

    // 3. Cluster by Sending Relay IP
    const ipMap = new Map<string, CaseRecord[]>();
    for (const c of cases) {
      const originHop = c.hops.length > 0 ? c.hops[c.hops.length - 1] : undefined;
      if (originHop?.ip && !originHop.isPrivate && originHop.ip !== '127.0.0.1') {
        const list = ipMap.get(originHop.ip) || [];
        list.push(c);
        ipMap.set(originHop.ip, list);
      }
    }

    for (const [ip, matchedCases] of ipMap.entries()) {
      if (matchedCases.length >= 2) {
        // Only add if not already redundant
        const clusterId = `camp-ip-${ip.replace(/[^a-zA-Z0-9]/g, '-')}`;
        if (!clusters.some(cl => cl.id === clusterId)) {
          const depts = Array.from(new Set(matchedCases.map(inferDepartment)));
          const maxScore = Math.max(...matchedCases.map(c => c.riskScore));

          clusters.push({
            id: clusterId,
            name: `Hostile Relay Gateway [${ip}]`,
            threatType: matchedCases.some(c => c.classification === 'Phishing') ? 'Phishing' : matchedCases[0].classification,
            riskLevel: maxScore >= 81 ? 'Critical' : 'High Risk',
            description: `Multiple threat transmissions identified originating from the same observed external mail gateway ${ip}.`,
            commonIndicatorType: 'IP',
            commonIndicatorValue: ip,
            caseCount: matchedCases.length,
            caseIds: matchedCases.map(c => c.id),
            cases: matchedCases.map(c => ({
              id: c.id,
              caseNumber: c.caseNumber,
              subject: c.metadata.subject,
              from: c.metadata.from.address,
              riskScore: c.riskScore,
              classification: c.classification,
              date: c.createdAt,
            })),
            firstSeen: matchedCases[matchedCases.length - 1].createdAt,
            lastSeen: matchedCases[0].createdAt,
            targetedDepartments: depts,
            matchConfidence: 88,
            whyLinked: `Inbound messages share the same initial connecting relay host IP (${ip}) across different claimed sender envelopes.`,
            commonIndicators: [ip],
          });
        }
      }
    }

    return clusters;
  }

  /**
   * Retrieves all reports.
   */
  static getAllReports(): ReportRecord[] {
    const stmt = db.prepare(`
      SELECT id, case_id, case_number, dossier_id, classification,
             risk_score, risk_level, evidence_hash, report_hash,
             generated_at, size_bytes, title, summary
      FROM reports
      ORDER BY generated_at DESC
    `);
    const rows = stmt.all() as Array<{
      id: string;
      case_id: string;
      case_number: string;
      dossier_id: string;
      classification: string;
      risk_score: number;
      risk_level: string;
      evidence_hash: string;
      report_hash: string;
      generated_at: string;
      size_bytes: number;
      title: string;
      summary: string;
    }>;

    return rows.map(r => ({
      id: r.id,
      caseId: r.case_id,
      caseNumber: r.case_number,
      dossierId: r.dossier_id,
      classification: r.classification as ThreatClassification,
      riskScore: r.risk_score,
      riskLevel: r.risk_level as RiskLevel,
      evidenceHash: r.evidence_hash,
      reportHash: r.report_hash,
      generatedAt: r.generated_at,
      sizeBytes: r.size_bytes,
      title: r.title,
      summary: r.summary,
    }));
  }

  static getReportById(idOrDossier: string): (ReportRecord & { data: CaseRecord }) | null {
    const stmt = db.prepare(`
      SELECT id, case_id, case_number, dossier_id, classification,
             risk_score, risk_level, evidence_hash, report_hash,
             generated_at, size_bytes, title, summary, data_json
      FROM reports
      WHERE id = ? OR dossier_id = ? OR case_number = ? OR case_id = ?
      LIMIT 1
    `);
    const row = stmt.get(idOrDossier, idOrDossier, idOrDossier, idOrDossier) as {
      id: string;
      case_id: string;
      case_number: string;
      dossier_id: string;
      classification: string;
      risk_score: number;
      risk_level: string;
      evidence_hash: string;
      report_hash: string;
      generated_at: string;
      size_bytes: number;
      title: string;
      summary: string;
      data_json: string;
    } | undefined;

    if (!row) return null;

    return {
      id: row.id,
      caseId: row.case_id,
      caseNumber: row.case_number,
      dossierId: row.dossier_id,
      classification: row.classification as ThreatClassification,
      riskScore: row.risk_score,
      riskLevel: row.risk_level as RiskLevel,
      evidenceHash: row.evidence_hash,
      reportHash: row.report_hash,
      generatedAt: row.generated_at,
      sizeBytes: row.size_bytes,
      title: row.title,
      summary: row.summary,
      data: JSON.parse(row.data_json) as CaseRecord,
    };
  }

  /**
   * Saves and retrieves assistant messages for conversational context.
   */
  static saveAssistantMessage(msg: AssistantMessage): void {
    const stmt = db.prepare(`
      INSERT INTO assistant_messages (id, case_id, role, content, timestamp)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(msg.id, msg.caseId || null, msg.role, msg.content, msg.timestamp);
  }

  static getAssistantHistory(caseId?: string, limit = 20): AssistantMessage[] {
    let sql = `SELECT id, case_id, role, content, timestamp FROM assistant_messages`;
    const params: any[] = [];
    if (caseId) {
      sql += ` WHERE case_id = ?`;
      params.push(caseId);
    }
    sql += ` ORDER BY timestamp ASC LIMIT ?`;
    params.push(limit);

    const stmt = db.prepare(sql);
    const rows = stmt.all(...params) as Array<{
      id: string;
      case_id?: string;
      role: string;
      content: string;
      timestamp: string;
    }>;

    return rows.map(r => ({
      id: r.id,
      caseId: r.case_id,
      role: r.role as 'user' | 'assistant',
      content: r.content,
      timestamp: r.timestamp,
    }));
  }

  /**
   * Computes comprehensive Dashboard statistics strictly from stored cases.
   */
  static getDashboardStats(): DashboardStats {
    const cases = this.getAllCases();
    const totalScanned = cases.length;

    let threatsDetected = 0;
    let highRiskCount = 0;
    let criticalCount = 0;
    let quarantined = 0;
    let riskSum = 0;

    const riskDistribution = {
      safe: 0,
      suspicious: 0,
      highRisk: 0,
      critical: 0,
    };

    const classificationDistribution = {
      clean: 0,
      phishing: 0,
      bec: 0,
      impersonation: 0,
      malware: 0,
      suspicious: 0,
    };

    // Date-based trend aggregation
    const trendMap = new Map<string, { scanned: number; threats: number }>();

    for (const c of cases) {
      riskSum += c.riskScore;

      const isThreat = c.riskScore >= 61 || ['Phishing', 'BEC', 'Impersonation', 'Malware'].includes(c.classification);

      if (c.riskScore >= 81) {
        criticalCount++;
        threatsDetected++;
        quarantined++;
        riskDistribution.critical++;
      } else if (c.riskScore >= 61) {
        highRiskCount++;
        threatsDetected++;
        if (c.classification === 'Malware' || c.classification === 'Phishing' || c.classification === 'BEC') {
          quarantined++;
        }
        riskDistribution.highRisk++;
      } else if (c.riskScore >= 41) {
        if (isThreat) threatsDetected++;
        riskDistribution.suspicious++;
      } else {
        riskDistribution.safe++;
      }

      // Map classification
      const lowerClass = c.classification.toLowerCase();
      if (lowerClass === 'clean' || lowerClass === 'legitimate') {
        classificationDistribution.clean++;
      } else if (lowerClass === 'phishing') {
        classificationDistribution.phishing++;
      } else if (lowerClass === 'bec') {
        classificationDistribution.bec++;
      } else if (lowerClass === 'impersonation') {
        classificationDistribution.impersonation++;
      } else if (lowerClass === 'malware') {
        classificationDistribution.malware++;
      } else {
        classificationDistribution.suspicious++;
      }

      // Trend by date (YYYY-MM-DD)
      const dateKey = c.createdAt.split('T')[0] || new Date().toISOString().split('T')[0];
      const existingTrend = trendMap.get(dateKey) || { scanned: 0, threats: 0 };
      existingTrend.scanned++;
      if (isThreat) existingTrend.threats++;
      trendMap.set(dateKey, existingTrend);
    }

    const averageRisk = totalScanned > 0 ? Math.round(riskSum / totalScanned) : 0;

    // Build chronological trend array
    const sortedDates = Array.from(trendMap.keys()).sort();
    const threatActivityTrend = sortedDates.map(date => ({
      date,
      scanned: trendMap.get(date)!.scanned,
      threats: trendMap.get(date)!.threats,
    }));

    if (threatActivityTrend.length === 0) {
      const today = new Date().toISOString().split('T')[0];
      threatActivityTrend.push({ date: today, scanned: 0, threats: 0 });
    }

    const recentCases = cases.slice(0, 10).map((c) => ({
      id: c.id,
      caseNumber: c.caseNumber,
      from: c.metadata.from.name ? `${c.metadata.from.name} <${c.metadata.from.address}>` : c.metadata.from.address,
      subject: c.metadata.subject,
      classification: c.classification,
      riskScore: c.riskScore,
      riskLevel: c.riskLevel,
      date: c.createdAt,
      status: c.riskScore >= 80 ? 'Quarantined' : c.riskScore >= 55 ? 'Under Review' : 'Preserved Clean',
    }));

    return {
      totalScanned,
      emailsAnalyzed: totalScanned,
      threatsDetected,
      highRiskCount,
      criticalCount,
      quarantined,
      averageRisk,
      riskDistribution,
      classificationDistribution,
      threatActivityTrend,
      recentCases,
    };
  }

  static getNextCaseNumber(): string {
    const stmt = db.prepare(`SELECT COUNT(*) as count FROM cases`);
    const res = stmt.get() as { count: number };
    const count = (res?.count || 0) + 1;
    return `MT-2026-${String(count).padStart(4, '0')}`;
  }
}
