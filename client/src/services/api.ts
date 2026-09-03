import type {
  CaseRecord,
  DashboardStats,
  IOCItem,
  SystemEngineStatus,
  ThreatMapData,
  ReportRecord,
  CampaignCluster,
  AssistantMessage,
  UserProfile,
  AuthResponse,
} from '../types.js';

const API_BASE = ((import.meta as any).env?.VITE_API_URL || '').replace(/\/$/, '') + '/api';

export class ApiService {
  static async getDashboard(): Promise<DashboardStats> {
    const res = await fetch(`${API_BASE}/dashboard`);
    if (!res.ok) throw new Error('Failed to load dashboard statistics.');
    return res.json();
  }

  static async getStats(): Promise<DashboardStats> {
    return this.getDashboard();
  }

  static async getCases(search?: string, classification?: string): Promise<CaseRecord[]> {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (classification && classification !== 'ALL') params.append('classification', classification);

    const url = `${API_BASE}/cases?${params.toString()}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to load cases registry.');
    return res.json();
  }

  static async getCaseById(id: string): Promise<CaseRecord> {
    const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(id)}`);
    if (!res.ok) throw new Error(`Failed to load case "${id}".`);
    return res.json();
  }

  static async deleteCase(id: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error(`Failed to delete case "${id}".`);
    return res.json();
  }

  static async deleteAllCases(): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/cases`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error('Failed to clear cases.');
    return res.json();
  }

  static async getCaseReport(id: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(id)}/report`);
    if (!res.ok) throw new Error(`Failed to load report for case "${id}".`);
    return res.json();
  }

  static async getCaseIndicators(id: string): Promise<IOCItem[]> {
    const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(id)}/indicators`);
    if (!res.ok) throw new Error(`Failed to load indicators for case "${id}".`);
    return res.json();
  }

  static async analyzeEmail(payload: { rawEmail?: string; emailContent?: string }): Promise<CaseRecord> {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Analysis failed.' }));
      throw new Error(err.error || 'Server rejected email analysis request.');
    }

    return res.json();
  }

  static async analyzeRaw(rawEmail: string): Promise<CaseRecord> {
    const res = await fetch(`${API_BASE}/analyze/raw`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ rawEmail }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Raw analysis failed.' }));
      throw new Error(err.error || 'Server rejected raw email analysis request.');
    }

    return res.json();
  }

  static async getIocs(search?: string, type?: string): Promise<Array<{
    value: string;
    type: string;
    severity: string;
    count: number;
    cases: Array<{ id: string; caseNumber: string; riskScore: number }>;
    firstObserved: string;
    context: string;
  }>> {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (type && type !== 'ALL') params.append('type', type);

    const res = await fetch(`${API_BASE}/iocs?${params.toString()}`);
    if (!res.ok) throw new Error('Failed to load threat intelligence indicators.');
    return res.json();
  }

  static async getIocByValue(val: string): Promise<any> {
    const res = await fetch(`${API_BASE}/iocs/${encodeURIComponent(val)}`);
    if (!res.ok) throw new Error(`Indicator "${val}" not found.`);
    return res.json();
  }

  static async getThreatMap(): Promise<ThreatMapData> {
    const res = await fetch(`${API_BASE}/threat-map`);
    if (!res.ok) throw new Error('Failed to load threat map coordinates.');
    return res.json();
  }

  static async getReports(): Promise<ReportRecord[]> {
    const res = await fetch(`${API_BASE}/reports`);
    if (!res.ok) throw new Error('Failed to load reports dossier list.');
    return res.json();
  }

  static async getReportById(id: string): Promise<ReportRecord & { data: CaseRecord }> {
    const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(id)}`);
    if (!res.ok) throw new Error(`Failed to load forensic report "${id}".`);
    return res.json();
  }

  static async getCampaigns(): Promise<CampaignCluster[]> {
    const res = await fetch(`${API_BASE}/campaigns`);
    if (!res.ok) throw new Error('Failed to load campaigns.');
    return res.json();
  }

  static async askAssistant(question: string, caseId?: string): Promise<{
    answer: string;
    caseNumber?: string;
    caseId?: string;
    timestamp: string;
  }> {
    const res = await fetch(`${API_BASE}/assistant`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ question, caseId }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Assistant failed.' }));
      throw new Error(err.error || 'Security Assistant service error.');
    }

    return res.json();
  }

  static async getAssistantHistory(caseId?: string): Promise<AssistantMessage[]> {
    const params = new URLSearchParams();
    if (caseId) params.append('caseId', caseId);
    const res = await fetch(`${API_BASE}/assistant/history?${params.toString()}`);
    if (!res.ok) return [];
    return res.json();
  }

  static async getMonitoring(): Promise<any> {
    const res = await fetch(`${API_BASE}/monitoring`);
    if (!res.ok) throw new Error('Failed to query system monitoring status.');
    return res.json();
  }

  static async getSettings(): Promise<any> {
    const res = await fetch(`${API_BASE}/settings`);
    if (!res.ok) throw new Error('Failed to query settings configuration.');
    return res.json();
  }

  static async ingestEmail(rawEmail: string): Promise<CaseRecord> {
    const res = await fetch(`${API_BASE}/ingest/email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ rawEmail }),
    });
    if (!res.ok) throw new Error('Failed to ingest email.');
    return res.json();
  }



  static async getQuarantine(): Promise<CaseRecord[]> {
    const res = await fetch(`${API_BASE}/quarantine`);
    if (!res.ok) throw new Error('Failed to load quarantined emails.');
    return res.json();
  }

  static async releaseQuarantinedCase(id: string, reason?: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/quarantine/${encodeURIComponent(id)}/release`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) throw new Error(`Failed to release case "${id}" from quarantine.`);
    return res.json();
  }

  static async quarantineCase(id: string, reason?: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/quarantine/${encodeURIComponent(id)}/quarantine`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) throw new Error(`Failed to quarantine case "${id}".`);
    return res.json();
  }

  static async getSystemStatus(): Promise<SystemEngineStatus> {
    const res = await fetch(`${API_BASE}/status`);
    if (!res.ok) throw new Error('Failed to query engine status.');
    return res.json();
  }

  static async login(email: string, password: string): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Authentication failed.');
    return data;
  }

  static async getMe(token: string): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Session validation failed.');
    return data;
  }

  static async logout(token?: string | null): Promise<void> {
    if (!token) return;
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
    } catch {
      // Ignore network errors during logout
    }
  }
}
