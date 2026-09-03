import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Search,
  RefreshCw,
  Bell,
  ChevronDown,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';

interface HeaderProps {
  onRefresh?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onRefresh }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [systemHealth, setSystemHealth] = useState<'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'>('HEALTHY');

  React.useEffect(() => {
    const checkStatus = async () => {
      try {
        const res = await fetch('/api/status');
        if (res.ok) {
          const data = await res.json();
          if (data.status === 'ONLINE' || data.status === 'HEALTHY') {
            setSystemHealth('HEALTHY');
          } else {
            setSystemHealth('DEGRADED');
          }
        } else {
          setSystemHealth('DEGRADED');
        }
      } catch {
        setSystemHealth('UNAVAILABLE');
      }
    };

    checkStatus();
    const timer = setInterval(checkStatus, 15000);
    return () => clearInterval(timer);
  }, []);

  const getPageTitle = (path: string) => {
    if (path === '/') return 'Dashboard';
    if (path.startsWith('/live-monitor')) return 'Live Threat Monitor';
    if (path.startsWith('/analyze')) return 'Email Threat Analysis';
    if (path.startsWith('/threat-intelligence')) return 'Threat Intelligence';
    if (path.startsWith('/threat-map')) return 'Origin Threat Infrastructure Map';
    if (path.startsWith('/campaigns')) return 'Attack Campaign Clusters';
    if (path.startsWith('/cases')) return 'Forensic Investigation Cases';
    if (path.startsWith('/investigation')) return 'Forensic Investigation';
    if (path.startsWith('/reports')) return 'Forensic Reports & Dossiers';
    if (path.startsWith('/assistant')) return 'AI Security Assistant';
    if (path.startsWith('/monitoring')) return 'System Health & Telemetry';
    if (path.startsWith('/settings')) return 'Platform Settings';
    return 'MailTrace AI Forensics';
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/cases?search=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  const handleRefreshClick = () => {
    setRefreshing(true);
    if (onRefresh) {
      onRefresh();
    } else {
      window.dispatchEvent(new CustomEvent('mailtrace:refresh'));
    }
    setTimeout(() => setRefreshing(false), 700);
  };

  return (
    <header className="h-[68px] bg-white border-b border-[#E5E9F2] px-8 flex items-center justify-between sticky top-0 z-20 shadow-[0_1px_3px_rgba(11,31,58,0.02)]">
      {/* Current Page Title */}
      <div className="flex items-center space-x-3">
        <h2 className="text-xl font-bold text-[#0B1F3A] tracking-tight">
          {getPageTitle(location.pathname)}
        </h2>
      </div>

      {/* Center Search Input */}
      <form onSubmit={handleSearch} className="relative w-80 lg:w-96 hidden md:block">
        <Search className="w-4 h-4 text-[#68809F] absolute left-3.5 top-3" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search emails, threats, IOCs..."
          className="w-full pl-10 pr-4 py-2 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2] text-xs text-[#0B1F3A] placeholder-[#68809F] focus:outline-none focus:ring-2 focus:ring-[#246BFE]/30 focus:border-[#246BFE] transition-all"
        />
      </form>

      {/* Right Controls */}
      <div className="flex items-center space-x-4">
        {/* System Health Status Pill */}
        <div className="hidden sm:flex items-center">
          {systemHealth === 'HEALTHY' && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-50 border border-emerald-200/80 text-xs font-semibold text-emerald-800">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>System Normal</span>
            </div>
          )}
          {systemHealth === 'DEGRADED' && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-amber-50 border border-amber-200/80 text-xs font-semibold text-amber-800">
              <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
              <span>System Degraded</span>
            </div>
          )}
          {systemHealth === 'UNAVAILABLE' && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-red-50 border border-red-200/80 text-xs font-semibold text-red-800">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              <span>Analysis Service Unavailable</span>
            </div>
          )}
        </div>

        {/* Mail Exchange Button */}
        <button
          onClick={() => navigate('/live-monitor')}
          className="hidden lg:inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-[#EEF4FF] hover:bg-blue-100/80 text-[#246BFE] text-xs font-bold transition-colors"
          title="Open Mail Exchange Monitor"
        >
          <span>Mail Exchange</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </button>

        {/* Refresh Icon */}
        <button
          onClick={handleRefreshClick}
          className="p-2 rounded-xl text-[#68809F] hover:text-[#0B1F3A] hover:bg-[#F7F9FC] border border-transparent hover:border-[#E5E9F2] transition-all"
          title="Refresh Telemetry"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-[#246BFE]' : ''}`} />
        </button>

        {/* Notification Bell */}
        <div className="relative">
          <button
            onClick={() => navigate('/cases')}
            className="p-2 rounded-xl text-[#68809F] hover:text-[#0B1F3A] hover:bg-[#F7F9FC] border border-transparent hover:border-[#E5E9F2] transition-all"
            title="Notifications"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-[#EF4444] rounded-full ring-2 ring-white" />
          </button>
        </div>

        {/* Vertical Divider */}
        <div className="h-6 w-px bg-[#E5E9F2]" />

        {/* Admin Profile Dropdown */}
        <div
          onClick={() => navigate('/settings')}
          className="flex items-center space-x-2.5 pl-1 cursor-pointer select-none group"
        >
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-[#0B1F3A] to-[#246BFE] text-white flex items-center justify-center font-bold text-xs shadow-xs">
            AD
          </div>
          <span className="text-xs font-bold text-[#0B1F3A] group-hover:text-[#246BFE] transition-colors hidden sm:inline">
            Admin
          </span>
          <ChevronDown className="w-3.5 h-3.5 text-[#68809F] group-hover:text-[#0B1F3A]" />
        </div>
      </div>
    </header>
  );
};
