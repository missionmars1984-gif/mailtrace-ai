import React, { createContext, useContext, useState, useEffect } from 'react';
import type { UserProfile } from '../types.js';
import { ApiService } from '../services/api.js';

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<UserProfile>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_KEY = 'mailtrace_auth_token';
const USER_KEY = 'mailtrace_auth_user';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    try {
      const storedToken = localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY);
      const storedUser = localStorage.getItem(USER_KEY) || sessionStorage.getItem(USER_KEY);

      if (storedToken && storedUser) {
        setToken(storedToken);
        setUser(JSON.parse(storedUser));
      }
    } catch {
      // Ignore parse errors
    } finally {
      setIsLoading(false);
    }
  }, []);

  const login = async (email: string, password: string, rememberMe: boolean = true): Promise<UserProfile> => {
    setIsLoading(true);
    try {
      const response = await ApiService.login(email, password);
      if (!response.success || !response.user) {
        throw new Error(response.error || 'Authentication rejected by security gateway');
      }

      const authenticatedUser = response.user;
      setUser(authenticatedUser);
      setToken(authenticatedUser.token);

      const storage = rememberMe ? localStorage : sessionStorage;
      storage.setItem(TOKEN_KEY, authenticatedUser.token);
      storage.setItem(USER_KEY, JSON.stringify(authenticatedUser));

      return authenticatedUser;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    if (token) {
      ApiService.logout(token);
    }
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
    setUser(null);
    setToken(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: Boolean(user && token),
        isLoading,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
