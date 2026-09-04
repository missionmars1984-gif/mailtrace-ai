import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Search,
  RefreshCw,
  Bell,
  ChevronDown,
  ExternalLink,
  ShieldCheck,
  LogOut,
  User,
  Settings,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext.js';

interface HeaderProps {
  onRefresh?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onRefresh }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [systemHealth, setSystemHealth] = useState<'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'>('HEALTHY');
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const { user, logout } = useAuth();

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

  const getPageTitle = (path: string): string => {
    if (path === '/') return 'Dashboard';
    if (path.startsWith('/live-monitor') || path.startsWith('/exchange')) return 'Live Monitor';
    if (path.startsWith('/analyze')) return 'Analyze Email';
    if (path.startsWith('/threat-intelligence')) return 'Threat Intel';
    if (path.startsWith('/threat-map') || path.startsWith('/map')) return 'Threat Map';
    if (path.startsWith('/campaigns')) return 'Campaigns';
    if (path.startsWith('/cases')) return 'Cases';
    if (path.startsWith('/quarantine')) return 'Quarantine';
    if (path.startsWith('/reports')) return 'Reports';
    if (path.startsWith('/investigation')) return 'Investigation';
    if (path.startsWith('/methodology')) return 'Methodology';
    if (path.startsWith('/assistant')) return 'Security Assistant';
    if (path.startsWith('/monitoring')) return 'Monitoring';
    if (path.startsWith('/settings')) return 'Settings';
    return 'Dashboard';
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
    <header className="h-[68px] bg-white border-b border-[#E5E9F2] px-6 sm:px-8 flex items-center sticky top-0 z-20 shadow-[0_1px_3px_rgba(11,31,58,0.02)]">
      {/* 1. [PAGE TITLE AREA] - Fixed stable width so Search Area starts at identical position on all routes */}
      <div className="w-[170px] sm:w-[190px] lg:w-[220px] flex-shrink-0 flex items-center pr-3 sm:pr-4">
        <h1
          className="text-xl font-bold text-[#0B1F3A] tracking-tight truncate whitespace-nowrap"
          title={getPageTitle(location.pathname)}
        >
          {getPageTitle(location.pathname)}
        </h1>
      </div>

      {/* 2. [SEARCH AREA] - Constant horizontal starting offset, shrinks gracefully */}
      <div className="flex-1 max-w-md min-w-[180px] hidden md:block">
        <form onSubmit={handleSearch} className="relative w-full">
          <Search className="w-4 h-4 text-[#68809F] absolute left-3.5 top-3" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search emails, threats, IOCs..."
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2] text-xs text-[#0B1F3A] placeholder-[#68809F] focus:outline-none focus:ring-2 focus:ring-[#246BFE]/30 focus:border-[#246BFE] transition-all"
          />
        </form>
      </div>

      {/* 3. [RIGHT CONTROLS] - Consistently aligned on the right */}
      <div className="flex items-center space-x-3 sm:space-x-4 flex-shrink-0 ml-auto">
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
        <div className="relative">
          <button
            type="button"
            onClick={() => setProfileMenuOpen(!profileMenuOpen)}
            className="flex items-center space-x-2.5 pl-1 cursor-pointer select-none group focus:outline-none"
          >
            <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-[#0B1F3A] to-[#246BFE] text-white flex items-center justify-center font-bold text-xs shadow-xs">
              {user?.avatarInitials || 'AM'}
            </div>
            <div className="text-left hidden sm:block">
              <span className="text-xs font-bold text-[#0B1F3A] group-hover:text-[#246BFE] transition-colors block leading-tight">
                {user?.name || 'Alex Mercer'}
              </span>
              <span className="text-[10px] text-[#68809F] block leading-tight">
                {user?.role || 'Lead Analyst'}
              </span>
            </div>
            <ChevronDown className={`w-3.5 h-3.5 text-[#68809F] group-hover:text-[#0B1F3A] transition-transform ${profileMenuOpen ? 'rotate-180' : ''}`} />
          </button>

          {profileMenuOpen && (
            <>
              {/* Backdrop */}
              <div
                className="fixed inset-0 z-20"
                onClick={() => setProfileMenuOpen(false)}
              />

              {/* Dropdown Menu */}
              <div className="absolute right-0 mt-2 w-64 rounded-2xl bg-white border border-[#E5E9F2] shadow-xl shadow-slate-200/50 py-2 z-30">
                {/* User Info Header */}
                <div className="px-4 py-3 border-b border-[#E5E9F2]">
                  <div className="text-xs font-bold text-[#0B1F3A] truncate">
                    {user?.name || 'Alex Mercer'}
                  </div>
                  <div className="text-[11px] text-[#68809F] truncate mt-0.5">
                    {user?.email || 'admin@mailtrace.ai'}
                  </div>
                  <div className="mt-2 inline-flex items-center space-x-1.5 px-2 py-0.5 rounded-md bg-[#EEF4FF] border border-[#246BFE]/20 text-[10px] font-semibold text-[#246BFE]">
                    <ShieldCheck className="w-3 h-3" />
                    <span>{user?.role || 'Lead Security Analyst'}</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="py-1">
                  <button
                    type="button"
                    onClick={() => {
                      setProfileMenuOpen(false);
                      navigate('/settings');
                    }}
                    className="w-full px-4 py-2 text-left text-xs text-[#0B1F3A] hover:bg-[#F7F9FC] flex items-center space-x-2.5 transition-colors cursor-pointer"
                  >
                    <Settings className="w-4 h-4 text-[#68809F]" />
                    <span>Console Settings</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setProfileMenuOpen(false);
                      navigate('/monitoring');
                    }}
                    className="w-full px-4 py-2 text-left text-xs text-[#0B1F3A] hover:bg-[#F7F9FC] flex items-center space-x-2.5 transition-colors cursor-pointer"
                  >
                    <User className="w-4 h-4 text-[#68809F]" />
                    <span>Engine Telemetry</span>
                  </button>
                </div>

                {/* Sign Out */}
                <div className="pt-1 border-t border-[#E5E9F2]">
                  <button
                    type="button"
                    onClick={() => {
                      setProfileMenuOpen(false);
                      logout();
                      navigate('/login');
                    }}
                    className="w-full px-4 py-2 text-left text-xs text-red-600 hover:bg-red-50 flex items-center space-x-2.5 transition-colors font-medium cursor-pointer"
                  >
                    <LogOut className="w-4 h-4 text-red-500" />
                    <span>Lock Console / Sign Out</span>
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  );
};
