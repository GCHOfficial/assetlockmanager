import React from 'react'; // Add React import for JSX namespace
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate
} from "react-router-dom";
import LoginPage from './pages/LoginPage';
import MainLayout from './layouts/MainLayout';
import DashboardPage from './pages/Dashboard/DashboardPage'; // Import the actual DashboardPage
import SettingsPage from './pages/Settings/SettingsPage'; // Import SettingsPage
import AdminPage from './pages/Admin/AdminPage'; // Import AdminPage
import { useAuth } from './context/AuthContext'; // Import useAuth
import { Loader2 } from "lucide-react"; // Use lucide icon for loading indicator
import { ThemeProvider } from "./components/theme-provider"; // Import the ThemeProvider

// Placeholder Dashboard component - REMOVE
// const DashboardPage = () => <Typography variant="h5">Dashboard</Typography>;

// Simple ProtectedRoute component
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    // Show loading indicator while checking auth status
    return (
      <div className="flex justify-center items-center min-h-screen">
        <Loader2 className="h-16 w-16 animate-spin" />
      </div>
    );
  }

  return isAuthenticated ? children : <Navigate to="/login" replace />;
};

// Admin Route HOC
const AdminRoute = ({ children }: { children: React.ReactNode }) => {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    // Show loading indicator while checking auth status
    return (
      <div className="flex justify-center items-center min-h-screen">
        <Loader2 className="h-16 w-16 animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated) {
    // If not authenticated, redirect to login
    return <Navigate to="/login" replace />;
  }

  if (!user?.is_admin) {
    // If authenticated but not an admin, redirect to dashboard (or show an error page)
    // Showing dashboard is less disruptive
    console.warn('Admin access denied for non-admin user.');
    return <Navigate to="/" replace />;
  }

  // If authenticated and is an admin, render the children
  return <>{children}</>; // Use Fragment shorthand
};

function App() {
  const { isAuthenticated, isLoading } = useAuth(); // Use the hook here as well for the /login route logic

  // Optional: Central loading state removed as it's handled by individual route components

  return (
    <Router>
      <ThemeProvider defaultTheme="dark" storageKey="vite-ui-theme">
        <Routes>
          {/* If loading, show nothing or loader for login route, otherwise check auth */}
          <Route 
            path="/login" 
            element={isLoading ? (
              <div className="flex justify-center items-center min-h-screen">
                <Loader2 className="h-16 w-16 animate-spin" />
              </div>
            ) : isAuthenticated ? <Navigate to="/" replace /> : <LoginPage />} 
          />
          <Route 
            path="/*" 
            element={ // ProtectedRoute will show loader if isLoading
              <ProtectedRoute>
                <MainLayout />
              </ProtectedRoute>
            }
          >
            {/* Nested routes within MainLayout will be protected by ProtectedRoute */}
            <Route index element={<DashboardPage />} /> {/* Default route */}
            <Route path="settings" element={<SettingsPage />} /> {/* Settings route */}
            {/* Admin Routes */}
            <Route 
              path="admin/*" // Use trailing wildcard for nested admin routes
              element={ // AdminRoute will show loader if isLoading
                <AdminRoute>
                  <AdminPage />
                </AdminRoute>
              }
            />
          </Route>
        </Routes>
      </ThemeProvider>
    </Router>
  );
}

export default App;
