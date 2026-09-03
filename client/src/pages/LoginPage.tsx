import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.js';
import {
  Shield,
  Lock,
  Mail,
  Eye,
  EyeOff,
  CheckCircle2,
  AlertCircle,
  KeyRound,
  Fingerprint,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, isAuthenticated } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // If already authenticated, redirect immediately
  const from = (location.state as any)?.from?.pathname || '/';
  React.useEffect(() => {
    if (isAuthenticated) {
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, from]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setError('Please enter both your work email and password.');
      return;
    }

    setError(null);
    setSubmitting(true);

    try {
      await login(email.trim(), password.trim(), rememberMe);
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please check your credentials.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleQuickFill = (demoEmail: string, demoPass: string) => {
    setEmail(demoEmail);
    setPassword(demoPass);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-[#071325] flex flex-col justify-between relative overflow-hidden font-sans select-none">
      {/* Dynamic Background Glows */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-[#246BFE]/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 right-1/4 w-[32rem] h-[32rem] bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />
      
      {/* Subtle Grid Overlay */}
      <div 
        className="absolute inset-0 opacity-[0.03] pointer-events-none" 
        style={{ backgroundImage: 'radial-gradient(#ffffff 1px, transparent 1px)', backgroundSize: '24px 24px' }} 
      />

      {/* Top Bar Branding */}
      <header className="relative z-10 px-8 py-6 flex items-center justify-between border-b border-white/5 bg-[#0B1F3A]/40 backdrop-blur-md">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[#246BFE] to-[#60A5FA] flex items-center justify-center shadow-lg shadow-blue-500/20 ring-1 ring-white/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-base font-black text-white tracking-tight">MAILTRACE</span>
              <span className="text-xs font-mono font-bold px-1.5 py-0.5 rounded bg-[#246BFE]/20 text-[#60A5FA] border border-[#246BFE]/30">
                AI 2.4
              </span>
            </div>
            <p className="text-[10px] text-[#8EA3BE] font-medium tracking-wide">
              Security Operations Center & Digital Forensics
            </p>
          </div>
        </div>

        <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-white/5 border border-white/10 text-[11px] text-[#A0B4CC]">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>Gateway Active (TLS 1.3)</span>
        </div>
      </header>

      {/* Main Authentication Card */}
      <main className="relative z-10 flex-1 flex items-center justify-center p-4 sm:p-6 my-4">
        <div className="w-full max-w-md bg-[#0C1D36] border border-white/10 rounded-2xl shadow-2xl shadow-black/50 p-6 sm:p-8 backdrop-blur-xl">
          {/* Card Header */}
          <div className="text-center mb-6">
            <div className="inline-flex p-3 rounded-2xl bg-[#246BFE]/10 border border-[#246BFE]/20 text-[#60A5FA] mb-3">
              <KeyRound className="w-6 h-6" />
            </div>
            <h1 className="text-xl font-bold text-white tracking-tight">
              Analyst Console Access
            </h1>
            <p className="text-xs text-[#8EA3BE] mt-1">
              Enter your authorized security credentials to access the forensics terminal.
            </p>
          </div>

          {/* Error Banner */}
          {error && (
            <div className="mb-5 p-3.5 rounded-xl bg-red-500/10 border border-red-500/20 flex items-start space-x-2.5 text-xs text-red-400 animate-shake">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div className="flex-1 font-medium">{error}</div>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email Field */}
            <div>
              <label className="block text-xs font-semibold text-[#A0B4CC] mb-1.5">
                Work Email / Analyst ID
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-[#68809F] absolute left-3.5 top-3" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@mailtrace.ai"
                  required
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#081527] border border-white/10 text-xs text-white placeholder-[#5A7394] focus:outline-none focus:border-[#246BFE] focus:ring-1 focus:ring-[#246BFE] transition-all"
                />
              </div>
            </div>

            {/* Password Field */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-semibold text-[#A0B4CC]">
                  Console Passkey
                </label>
                <span className="text-[11px] text-[#60A5FA] hover:underline cursor-pointer">
                  Forgot key?
                </span>
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 text-[#68809F] absolute left-3.5 top-3" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full pl-10 pr-10 py-2.5 rounded-xl bg-[#081527] border border-white/10 text-xs text-white placeholder-[#5A7394] focus:outline-none focus:border-[#246BFE] focus:ring-1 focus:ring-[#246BFE] transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-2.5 text-[#68809F] hover:text-white transition-colors"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Remember Me */}
            <div className="flex items-center justify-between pt-1">
              <label className="flex items-center space-x-2 text-xs text-[#8EA3BE] cursor-pointer">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="w-3.5 h-3.5 rounded border-white/20 bg-[#081527] text-[#246BFE] focus:ring-0 focus:ring-offset-0 cursor-pointer"
                />
                <span>Remember this workstation</span>
              </label>
              <div className="flex items-center space-x-1 text-[11px] text-emerald-400">
                <Fingerprint className="w-3.5 h-3.5" />
                <span>MFA Enforced</span>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2.5 px-4 rounded-xl bg-[#246BFE] hover:bg-[#1E5AD8] active:scale-[0.99] text-white font-bold text-xs tracking-wide shadow-lg shadow-blue-600/30 transition-all flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {submitting ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Verifying Authorization...</span>
                </>
              ) : (
                <>
                  <span>Sign In to Forensic Console</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Quick Access / Demo Analyst Profiles */}
          <div className="mt-6 pt-5 border-t border-white/10">
            <div className="text-[11px] font-semibold text-[#8EA3BE] uppercase tracking-wider mb-2.5 text-center">
              Quick-Select Demo Analyst Credentials
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => handleQuickFill('admin@mailtrace.ai', 'password123')}
                className="p-2.5 rounded-xl bg-[#081527] hover:bg-[#112440] border border-white/5 hover:border-[#246BFE]/40 text-left transition-all group cursor-pointer"
              >
                <div className="flex items-center space-x-1.5 text-xs font-bold text-white group-hover:text-[#60A5FA]">
                  <span>Lead Analyst</span>
                  <CheckCircle2 className="w-3 h-3 text-[#246BFE] opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
                <div className="text-[10px] text-[#68809F] truncate mt-0.5">admin@mailtrace.ai</div>
              </button>

              <button
                type="button"
                onClick={() => handleQuickFill('forensics@mailtrace.ai', 'password123')}
                className="p-2.5 rounded-xl bg-[#081527] hover:bg-[#112440] border border-white/5 hover:border-[#246BFE]/40 text-left transition-all group cursor-pointer"
              >
                <div className="flex items-center space-x-1.5 text-xs font-bold text-white group-hover:text-[#60A5FA]">
                  <span>DFIR Specialist</span>
                  <CheckCircle2 className="w-3 h-3 text-[#246BFE] opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
                <div className="text-[10px] text-[#68809F] truncate mt-0.5">forensics@mailtrace.ai</div>
              </button>
            </div>
          </div>
        </div>
      </main>

      {/* Footer Compliance Badges */}
      <footer className="relative z-10 py-5 px-8 border-t border-white/5 bg-[#0B1F3A]/40 backdrop-blur-md">
        <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] text-[#68809F]">
          <div className="flex items-center space-x-4">
            <span className="flex items-center space-x-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>FIPS 140-3 Validated</span>
            </span>
            <span>•</span>
            <span>SOC 2 Type II Certified</span>
            <span>•</span>
            <span>Zero Trust Architecture</span>
          </div>
          <div>© 2026 MailTrace AI. All forensic transmissions cryptographically sealed.</div>
        </div>
      </footer>
    </div>
  );
};
