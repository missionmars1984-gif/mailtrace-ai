import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  ChevronRight,
  LayoutDashboard,
  Radio,
  Search,
  Crosshair,
  MapPin,
  Layers,
  FolderArchive,
  FileSpreadsheet,
  Bot,
  Activity,
  Settings,
  Lock,
} from 'lucide-react';

interface SidebarProps {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed = false, onToggleCollapse }) => {
  const sections = [
    {
      title: 'OVERVIEW',
      items: [
        { path: '/', label: 'Dashboard', icon: LayoutDashboard },
        { path: '/live-monitor', label: 'Live Monitor', icon: Radio },
      ],
    },
    {
      title: 'ANALYSIS & INTEL',
      items: [
        { path: '/analyze', label: 'Email Analysis', icon: Search },
        { path: '/threat-intelligence', label: 'Threat Intelligence', icon: Crosshair },
        { path: '/threat-map', label: 'Threat Map', icon: MapPin },
        { path: '/campaigns', label: 'Campaigns', icon: Layers },
      ],
    },
    {
      title: 'INVESTIGATION',
      items: [
        { path: '/cases', label: 'Forensic Cases', icon: FolderArchive },
        { path: '/quarantine', label: 'Quarantine', icon: Lock },
        { path: '/reports', label: 'Reports', icon: FileSpreadsheet },
      ],
    },
    {
      title: 'AI & SYSTEM',
      items: [
        { path: '/assistant', label: 'Security Assistant', icon: Bot },
        { path: '/monitoring', label: 'Monitoring', icon: Activity },
        { path: '/settings', label: 'Settings', icon: Settings },
      ],
    },
  ];

  return (
    <aside
      className={`bg-white text-[#0B1F3A] flex flex-col flex-shrink-0 h-screen sticky top-0 border-r border-[#E5E9F2] select-none z-30 shadow-[1px_0_4px_rgba(11,31,58,0.03)] transition-all duration-200 ease-in-out ${
        collapsed ? 'w-[76px]' : 'w-[290px]'
      }`}
    >
      {/* Brand Header */}
      <div
        className={`h-[68px] border-b border-[#E5E9F2] flex items-center relative transition-all duration-200 ${
          collapsed ? 'justify-center px-3' : 'justify-between px-6'
        }`}
      >
        <div className="flex items-center space-x-3 overflow-hidden">
          <div
            className="w-10 h-10 rounded-xl bg-[#246BFE] flex items-center justify-center text-white shadow-sm shadow-blue-500/30 flex-shrink-0"
            title="MailTrace AI Forensics"
          >
            <Shield className="w-5 h-5 fill-white/20" />
          </div>
          {!collapsed && (
            <div className="whitespace-nowrap overflow-hidden">
              <span className="font-bold text-lg tracking-tight text-[#0B1F3A]">
                MailTrace
              </span>
              <span className="text-[11px] font-semibold text-[#68809F] block -mt-0.5">
                AI Forensics Platform
              </span>
            </div>
          )}
        </div>

        {/* Existing Chevron Toggle Button */}
        <button
          onClick={onToggleCollapse}
          className={`text-[#68809F] hover:text-[#0B1F3A] hover:bg-slate-100 transition-colors cursor-pointer ${
            collapsed
              ? 'absolute -right-3.5 top-[20px] w-7 h-7 bg-white border border-[#E5E9F2] rounded-full shadow-xs flex items-center justify-center z-40'
              : 'p-1.5 rounded-md'
          }`}
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          aria-label={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          <ChevronRight
            className={`text-[#68809F] transition-transform duration-200 ${
              collapsed ? 'w-3.5 h-3.5' : 'w-4 h-4 rotate-180'
            }`}
          />
        </button>
      </div>

      {/* Navigation Sections */}
      <nav
        className={`flex-1 py-5 space-y-6 overflow-y-auto overflow-x-hidden ${
          collapsed ? 'px-2.5' : 'px-4'
        }`}
      >
        {sections.map((section) => (
          <div key={section.title} className="space-y-1">
            {!collapsed && (
              <div className="px-3 pb-1.5 text-[11px] font-bold text-[#68809F] tracking-wider uppercase truncate">
                {section.title}
              </div>
            )}
            {section.items.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === '/'}
                  title={item.label}
                  className={({ isActive }) =>
                    `flex items-center ${
                      collapsed
                        ? 'justify-center px-2 py-2.5'
                        : 'space-x-3 px-3.5 py-2.5'
                    } rounded-xl text-sm font-medium transition-all duration-150 ${
                      isActive
                        ? 'bg-[#EEF4FF] text-[#246BFE] font-bold shadow-xs'
                        : 'text-[#0B1F3A] hover:bg-[#F7F9FC] hover:text-[#246BFE]'
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      <Icon
                        className={`w-4 h-4 flex-shrink-0 transition-colors ${
                          isActive ? 'text-[#246BFE]' : 'text-[#68809F]'
                        }`}
                      />
                      {!collapsed && <span className="truncate">{item.label}</span>}
                    </>
                  )}
                </NavLink>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Bottom Footer */}
      {!collapsed ? (
        <div className="p-4 mx-4 mb-4 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2] flex items-center justify-between overflow-hidden">
          <div className="truncate">
            <div className="text-xs font-bold text-[#0B1F3A] truncate">Enterprise Edition</div>
            <div className="text-[11px] font-mono text-[#68809F] truncate">v2.4 Active</div>
          </div>
          <div
            className="w-2.5 h-2.5 rounded-full bg-emerald-500 ring-4 ring-emerald-100 flex-shrink-0 ml-2"
            title="System Operational"
          />
        </div>
      ) : (
        <div
          className="mb-5 flex flex-col items-center justify-center"
          title="Enterprise Edition v2.4 — Operational"
        >
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 ring-4 ring-emerald-100" />
        </div>
      )}
    </aside>
  );
};
