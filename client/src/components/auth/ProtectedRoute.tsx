import React from 'react';
import { Navigate, useLocation, Outlet } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext.js';
import { ShieldCheck } from 'lucide-react';

interface ProtectedRouteProps {
  children?: React.ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-[#F7F9FC]">
        <div className="flex flex-col items-center space-y-4">
          <div className="w-14 h-14 rounded-2xl bg-[#0B1F3A] flex items-center justify-center shadow-lg shadow-blue-500/10 border border-[#246BFE]/30 animate-pulse">
            <ShieldCheck className="w-8 h-8 text-[#246BFE]" />
          </div>
          <div className="text-center">
            <h3 className="text-sm font-bold text-[#0B1F3A] tracking-wider uppercase">Authenticating SOC Session</h3>
            <p className="text-xs text-[#68809F] mt-1">Verifying cryptographic credentials...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children ? <>{children}</> : <Outlet />;
};
