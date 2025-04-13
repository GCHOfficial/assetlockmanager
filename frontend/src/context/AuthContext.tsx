import React, { createContext, useState, useContext, useEffect, ReactNode } from 'react';
import * as api from '../services/api'; // Import api service

interface User {
  id: number;
  username: string;
  email: string;
  is_admin: boolean;
}

interface AuthContextType {
  token: string | null;
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean; // To handle initial auth check
  login: (token: string, userData: User) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [token, setToken] = useState<string | null>(localStorage.getItem('authToken'));
  const [user, setUser] = useState<User | null>(null); // Initialize user as null
  const [isLoading, setIsLoading] = useState(true); // Start loading

  useEffect(() => {
    const validateTokenAndFetchUser = async () => {
      const storedToken = localStorage.getItem('authToken');
      if (storedToken) {
        console.log("Auth Check: Token found in storage. Validating...");
        // Set token in state immediately for API calls
        setToken(storedToken);
        try {
          // Call an endpoint that requires authentication (like /currentuser)
          // We need to define getCurrentUser in api.ts if it doesn't exist
          // Or re-use logic similar to the login function
          // Adding a dedicated getCurrentUser function is cleaner:
          const currentUser = await api.getCurrentUser(); // Needs to be added to api.ts
          setUser(currentUser);
          console.log("Auth Check: Token validated, user data fetched.");
        } catch (error) {
          console.error("Auth Check: Token validation failed or user fetch failed.", error);
          // Token is invalid or expired, clear it
          localStorage.removeItem('authToken');
          setToken(null);
          setUser(null);
        }
      } else {
        console.log("Auth Check: No token found.");
      }
      setIsLoading(false);
    };

    validateTokenAndFetchUser();
  }, []); // Run only once on initial mount

  const login = (newToken: string, userData: User) => {
    localStorage.setItem('authToken', newToken);
    setToken(newToken);
    setUser(userData);
    // Optionally store user data in localStorage too
    // localStorage.setItem('userData', JSON.stringify(userData));
  };

  const logout = () => {
    localStorage.removeItem('authToken');
    // Optionally remove user data from localStorage
    // localStorage.removeItem('userData'); 
    setToken(null);
    setUser(null);
    // TODO: Potentially call backend logout endpoint if it exists
  };

  const value = {
    token,
    user,
    isAuthenticated: !!token, // Simple check based on token presence
    isLoading,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}; 