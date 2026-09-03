import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar.js';
import { Header } from './components/layout/Header.js';
import { FloatingAssistant } from './components/assistant/FloatingAssistant.js';

// Pages
import { CommandCenter } from './pages/CommandCenter.js';
import { LiveMonitorPage } from './pages/LiveMonitorPage.js';
import { AnalyzeEmail } from './pages/AnalyzeEmail.js';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage.js';
import { ThreatMapPage } from './pages/ThreatMapPage.js';
import { CampaignsPage } from './pages/CampaignsPage.js';
import { ForensicCasesPage } from './pages/ForensicCasesPage.js';
import { ReportsPage } from './pages/ReportsPage.js';
import { InvestigationPage } from './pages/InvestigationPage.js';
import { SecurityAssistantPage } from './pages/SecurityAssistantPage.js';
import { MonitoringPage } from './pages/MonitoringPage.js';
import { SettingsPage } from './pages/SettingsPage.js';
import { QuarantinePage } from './pages/QuarantinePage.js';

import { AuthProvider } from './context/AuthContext.js';
import { ProtectedRoute } from './components/auth/ProtectedRoute.js';
import { LoginPage } from './pages/LoginPage.js';

// Authenticated SOC Operations Layout
const SocLayout: React.FC = () => {
  return (
    <div className="flex h-screen bg-[#F7F9FC] text-[#0B1F3A] overflow-hidden font-sans">
      {/* Left Sidebar (290px, white) */}
      <Sidebar />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header (68px, white) */}
        <Header />

        {/* Primary Viewport */}
        <main className="flex-1 overflow-y-auto bg-[#F7F9FC]">
          <Routes>
            {/* OVERVIEW */}
            <Route path="/" element={<CommandCenter />} />
            <Route path="/live-monitor" element={<LiveMonitorPage />} />
            <Route path="/exchange" element={<LiveMonitorPage />} />

            {/* ANALYSIS & INTEL */}
            <Route path="/analyze" element={<AnalyzeEmail />} />
            <Route path="/threat-intelligence" element={<ThreatIntelligencePage />} />
            <Route path="/threat-map" element={<ThreatMapPage />} />
            <Route path="/map" element={<ThreatMapPage />} />
            <Route path="/campaigns" element={<CampaignsPage />} />

            {/* INVESTIGATION */}
            <Route path="/cases" element={<ForensicCasesPage />} />
            <Route path="/quarantine" element={<QuarantinePage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/investigation" element={<InvestigationPage />} />
            <Route path="/investigation/:caseId" element={<InvestigationPage />} />

            {/* AI & SYSTEM */}
            <Route path="/assistant" element={<SecurityAssistantPage />} />
            <Route path="/monitoring" element={<MonitoringPage />} />
            <Route path="/settings" element={<SettingsPage />} />

            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>

      {/* Global Floating SOC AI Assistant Drawer */}
      <FloatingAssistant />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public Authentication Gateway */}
          <Route path="/login" element={<LoginPage />} />

          {/* Protected SOC Console Routes */}
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <SocLayout />
              </ProtectedRoute>
            }
          />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
