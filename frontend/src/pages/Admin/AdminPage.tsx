import React from 'react';
import { Routes, Route, Link as RouterLink, useLocation, useNavigate } from 'react-router-dom';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import AdminUserManagementPage from './AdminUserManagementPage'; // To be created
import AdminConfigurationPage from './AdminConfigurationPage'; // To be created

// Helper to map paths to tab value (which is the path itself)
function useRouteMatch(patterns: readonly string[]) {
  const { pathname } = useLocation();
  for (let i = 0; i < patterns.length; i += 1) {
    // Use startsWith for nested routes under admin/
    if (pathname.startsWith(patterns[i])) {
      return patterns[i]; // Return the matched path as the value
    }
  }
  return '/admin/users'; // Default to the first tab value if no match
}

const AdminPage: React.FC = () => {
  const navigate = useNavigate();
  // Determine the current tab based on the URL path
  // Use absolute paths for matching
  const currentTabValue = useRouteMatch(['/admin/users', '/admin/config']);

  // Handle tab changes by navigating
  const onTabChange = (value: string) => {
    navigate(value);
  };

  return (
    <div className="w-full space-y-4 p-6 max-w-6xl mx-auto">
      <h1 className="text-3xl font-bold mt-2">Admin Panel</h1>
      <Tabs value={currentTabValue} onValueChange={onTabChange} className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="/admin/users">User Management</TabsTrigger>
          <TabsTrigger value="/admin/config">Configuration</TabsTrigger>
        </TabsList>
        {/* Content is now handled by the React Router Routes below */}
      </Tabs>
      
      {/* Nested Routes for Admin Sections - Render based on router, not TabsContent */}
      <div className="pt-3">
        <Routes>
          <Route path="users" element={<AdminUserManagementPage />} />
          <Route path="config" element={<AdminConfigurationPage />} />
           {/* Default content if neither 'users' nor 'config' matches */}
           <Route index element={<p>Select an admin section.</p>} /> 
        </Routes>
      </div>
    </div>
  );
};

export default AdminPage;
