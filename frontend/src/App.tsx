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
import ConfirmEmailPage from './pages/ConfirmEmailPage'; // Import Confirmation Page
import ConfirmPasswordPage from './pages/ConfirmPasswordPage'; // Import Confirmation Page
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
  // Remove unused auth state checks from here
  // const { isAuthenticated, isLoading } = useAuth(); 

  return (
    <Router>
      <ThemeProvider defaultTheme="dark" storageKey="vite-ui-theme">
        <Routes>
          {/* Public Routes - No auth check needed here */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/confirm-email" element={<ConfirmEmailPage />} />
          <Route path="/confirm-password" element={<ConfirmPasswordPage />} />

          {/* Protected Routes Wrapped in MainLayout */}
          <Route
            path="/" // Matches root and any nested paths not caught by public routes
            element={
              <ProtectedRoute>
                <MainLayout />
              </ProtectedRoute>
            }
          >
            {/* Routes rendered inside MainLayout's Outlet */}
            <Route index element={<DashboardPage />} /> {/* Default route at "/" */}
            <Route path="settings" element={<SettingsPage />} />
            <Route
              path="admin/*"
              element={ // AdminRoute adds an additional layer of protection
                <AdminRoute>
                  <AdminPage />
                </AdminRoute>
              }
            />
            {/* Add a catch-all for any other paths inside MainLayout? Optional. */}
            {/* <Route path="*" element={<Navigate to="/" replace />} /> */}
          </Route>

          {/* Optional: Add a top-level catch-all for truly unmatched routes */}
          {/* <Route path="*" element={<Navigate to="/login" replace />} /> */}

        </Routes>
      </ThemeProvider>
    </Router>
  );
}

export default App;
