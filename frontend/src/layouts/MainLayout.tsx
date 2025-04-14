import React from 'react';
import { Outlet, Link as RouterLink, useNavigate } from 'react-router-dom';
import { Button } from "@/components/ui/button"; // Import shadcn Button
import { useAuth } from '../context/AuthContext'; // Import useAuth for logout
import { ShieldCheck } from 'lucide-react'; // Import ShieldCheck icon

const MainLayout: React.FC = () => {
  const { logout, user } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login'); // Redirect to login after logout
  };

  return (
    <div className="flex flex-col min-h-screen">
      {/* Header/Navigation Bar */}
      <header className="sticky top-0 z-50 w-full bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <nav className="flex h-14 items-center px-4 sm:px-6 lg:px-8">
          <div className="mr-4 flex items-center">
            <RouterLink to="/" className="mr-6 flex items-center space-x-2">
               {/* <Icons.logo className="h-6 w-6" /> Replace with your logo icon if you have one */}
               <span className="hidden font-bold sm:inline-block">
                 Asset Lock Manager 
                 {user?.is_admin && ( // Conditionally render icon
                   <ShieldCheck className="h-5 w-5 ml-1.5 inline-block text-primary align-middle" />
                 )}
               </span>
            </RouterLink>
           </div>
           {/* Navigation Links - Adjust styling as needed */}
          <div className="flex flex-1 items-center justify-end space-x-2">
             <Button variant="ghost" asChild>
               <RouterLink to="/">Dashboard</RouterLink>
             </Button>
             <Button variant="ghost" asChild>
               <RouterLink to="/settings">Settings</RouterLink>
             </Button>
             {user?.is_admin && (
               <Button variant="ghost" asChild>
                  <RouterLink to="/admin/users">Admin</RouterLink>
                </Button>
             )}
             <Button variant="outline" onClick={handleLogout}>Logout</Button>
          </div>
        </nav>
      </header>
      
      {/* Main Content Area */}
      <main className="flex-1 container mt-8 mb-8 px-4 max-w-7xl mx-auto">
        <Outlet /> {/* Child routes will render here */}
      </main>
      
      {/* Optional Footer */}
      {/* <footer className="py-6 md:px-8 md:py-0 border-t bg-background">
        <div className="container flex flex-col items-center justify-between gap-4 md:h-24 md:flex-row">
          <p className="text-center text-sm leading-loose text-muted-foreground md:text-left">
            Built by YourName/Company. Copyright © {new Date().getFullYear()}
          </p>
        </div>
      </footer> */}
    </div>
  );
};

export default MainLayout; 