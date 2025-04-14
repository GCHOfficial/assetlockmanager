import React, { useState, useEffect, useCallback, useMemo } from 'react';
import * as api from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { 
    Table, TableBody, TableCell, TableHead, TableHeader, TableRow 
} from "@/components/ui/table";
import { 
    Dialog, DialogContent, DialogDescription, DialogFooter, 
    DialogHeader, DialogTitle, 
    DialogPortal,
    DialogOverlay,
} from "@/components/ui/dialog";
import { 
    Tooltip, TooltipContent, TooltipProvider, TooltipTrigger 
} from "@/components/ui/tooltip";
import { Plus, Edit, Trash2, RefreshCw, Loader2, Terminal } from 'lucide-react'; // Use lucide icons

// Re-define User type for clarity within this component
interface User {
  id: number;
  username: string;
  email: string;
  is_admin: boolean;
}

type DialogMode = 'create' | 'edit';

const AdminUserManagementPage: React.FC = () => {
  const { user: currentUser } = useAuth(); // Get current admin user
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState(''); // State for search term

  // Dialog State
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogMode, setDialogMode] = useState<DialogMode>('create');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [formData, setFormData] = useState({ 
      username: '', email: '', password: '', isAdmin: false 
  });
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [dialogLoading, setDialogLoading] = useState(false);

  // Fetch Users Function
  const fetchUsers = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.adminListUsers();
      // Sort users by ID ascendingly before setting state
      const sortedData = data.sort((a, b) => a.id - b.id);
      setUsers(sortedData);
    } catch (err) {
      console.error("Failed to fetch users:", err);
      setError("Failed to load users.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  // --- Dialog Handling ---
  // Note: DialogTrigger manages open state automatically, but we need manual control
  // for edit/create logic. So we manage `dialogOpen` state.
  const handleOpenDialog = (mode: DialogMode, user: User | null = null) => {
    setDialogMode(mode);
    setSelectedUser(user);
    setDialogError(null);
    setDialogLoading(false);
    if (mode === 'edit' && user) {
      setFormData({ 
          username: user.username, // Usually username is not editable
          email: user.email,
          password: '', // Password field for reset option
          isAdmin: user.is_admin 
      });
    } else {
      // Reset for create mode
      setFormData({ username: '', email: '', password: '', isAdmin: false });
    }
    setDialogOpen(true); // Manually open the dialog
  };

  const handleDialogClose = () => {
    if (dialogLoading) return; // Prevent closing while loading
    setDialogOpen(false);
    // Optionally reset selectedUser after animation
    // setTimeout(() => setSelectedUser(null), 150); 
  };

  const handleFormChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = event.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleAdminSwitchChange = (checked: boolean) => {
     setFormData(prev => ({ ...prev, isAdmin: checked }));
  };

  const handleDialogSubmit = async () => {
    setDialogError(null);
    setDialogLoading(true);
    try {
      if (dialogMode === 'create') {
        if (!formData.username || !formData.email || !formData.password) {
            throw new Error("Username, Email, and Password are required for new user.");
        }
        const payload = {
          username: formData.username,
          email: formData.email,
          password: formData.password,
          is_admin: formData.isAdmin // Assuming API supports this on creation
        };
        console.log("Creating user with payload:", payload);
        await api.adminCreateUser(payload); // Ensure API accepts is_admin

      } else if (dialogMode === 'edit' && selectedUser) {
        // Update Email if changed
        if (formData.email !== selectedUser.email) {
            await api.adminChangeUserEmail(selectedUser.id, { new_email: formData.email });
        }
        // Update Password if provided
        if (formData.password) { 
            await api.adminChangeUserPassword(selectedUser.id, { new_password: formData.password });
        }
        // Update Admin Status if changed
        if (formData.isAdmin !== selectedUser.is_admin) {
            await api.adminUpdateUserStatus(selectedUser.id, { is_admin: formData.isAdmin });
        }
      }
      handleDialogClose();
      fetchUsers(); // Refresh user list
    } catch (err: any) {
      console.error(`Failed to ${dialogMode} user:`, err);
      setDialogError(err.response?.data?.message || err.message || `Failed to ${dialogMode} user.`);
    } finally {
        setDialogLoading(false);
    }
  };

  // --- Delete Handling --- (Using a separate Dialog for confirmation)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const openDeleteConfirm = (user: User) => {
    if (user.id === currentUser?.id) {
      setError("You cannot delete your own account."); // Show error in main area
      return;
    }
    setUserToDelete(user);
    setDeleteConfirmOpen(true);
  };

  const closeDeleteConfirm = () => {
    if (deleteLoading) return;
    setDeleteConfirmOpen(false);
    setTimeout(() => setUserToDelete(null), 150); // Delay clearing state
  };

  const confirmDeleteUser = async () => {
    if (!userToDelete) return;
    setError(null);
    setDeleteLoading(true);
    try {
      await api.adminDeleteUser(userToDelete.id);
      closeDeleteConfirm();
      fetchUsers(); // Refresh list on success
    } catch (err: any) {
      console.error(`Failed to delete user ${userToDelete.id}:`, err);
      setError(err.response?.data?.message || `Failed to delete user ${userToDelete.username}.`);
      // Keep delete dialog open on error?
      closeDeleteConfirm(); // Close confirm dialog even on error for now
    } finally {
      setDeleteLoading(false);
    }
  };

  // Filtered Users based on search term
  const filteredUsers = useMemo(() => {
    if (!searchTerm) {
      return users; // Return all users if no search term
    }
    return users.filter(user =>
      user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase())
    );
  }, [users, searchTerm]);

  // --- Render ---
  if (isLoading) {
    return <div className="flex justify-center my-3"><Loader2 className="h-8 w-8 animate-spin" /></div>;
  }

  return (
    <TooltipProvider>
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center mb-4"> {/* Added margin-bottom */} 
            <CardTitle>Users</CardTitle>
            <div className="flex items-center space-x-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" size="icon" onClick={fetchUsers} disabled={isLoading}>
                    <RefreshCw className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent><p>Refresh List</p></TooltipContent>
              </Tooltip>
              <Button onClick={() => handleOpenDialog('create')}>
                <Plus className="mr-2 h-4 w-4" /> Add User
              </Button>
            </div>
          </div>
          {/* Search Input */}
          <div className="w-full max-w-sm">
             <Input 
               type="text"
               placeholder="Search by username or email..."
               value={searchTerm}
               onChange={(e) => setSearchTerm(e.target.value)}
               className="mb-4" // Add margin below search
             />
          </div>
        </CardHeader>
        <CardContent>
          {error && (
            <Alert variant="destructive" className="mb-4">
              <Terminal className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[50px]">ID</TableHead>
                <TableHead>Username</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Admin Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredUsers.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="font-medium">{user.id}</TableCell>
                  <TableCell>{user.username}</TableCell>
                  <TableCell>{user.email}</TableCell>
                  <TableCell>
                    <Checkbox checked={user.is_admin} disabled />
                  </TableCell>
                  <TableCell className="text-right">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button variant="ghost" size="icon" onClick={() => handleOpenDialog('edit', user)}>
                          <Edit className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent><p>Edit User</p></TooltipContent>
                    </Tooltip>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        {/* Disable button directly */}
                        <Button 
                            variant="ghost" 
                            size="icon" 
                            onClick={() => openDeleteConfirm(user)}
                            disabled={user.id === currentUser?.id} 
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent><p>Delete User</p></TooltipContent>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* --- Dialogs --- */} 

      {/* Create/Edit User Dialog */} 
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogPortal>
          <DialogOverlay />
          <DialogContent className="sm:max-w-[425px]" onInteractOutside={handleDialogClose} onEscapeKeyDown={handleDialogClose}>
            <DialogHeader>
              <DialogTitle>{dialogMode === 'create' ? 'Create New User' : 'Edit User'}</DialogTitle>
              <DialogDescription>
                {dialogMode === 'create' ? 'Fill in the details for the new user.' : `Editing user: ${selectedUser?.username}`}
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              {dialogError && (
                  <Alert variant="destructive" className="mb-4">
                  <Terminal className="h-4 w-4" />
                  <AlertTitle>Error</AlertTitle>
                  <AlertDescription>{dialogError}</AlertDescription>
                  </Alert>
              )}
              {/* Refactor form layout: Use vertical stacking */}
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input 
                    id="username" 
                    name="username" 
                    value={formData.username} 
                    onChange={handleFormChange}
                    disabled={dialogLoading || dialogMode === 'edit'}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input 
                    id="email" 
                    name="email" 
                    type="email" 
                    value={formData.email} 
                    onChange={handleFormChange}
                    disabled={dialogLoading}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">
                    {dialogMode === 'create' ? 'Password' : 'New Password (Optional)'}
                  </Label>
                  <Input 
                    id="password" 
                    name="password" 
                    type="password" 
                    value={formData.password} 
                    onChange={handleFormChange}
                    placeholder={dialogMode === 'create' ? 'Required' : 'Leave blank to keep current'}
                    disabled={dialogLoading}
                  />
                </div>
                 <div className="flex items-center space-x-2 pt-2"> {/* Keep flex, add top padding */} 
                    <Switch 
                        id="isAdmin" 
                        checked={formData.isAdmin} 
                        onCheckedChange={handleAdminSwitchChange} 
                        disabled={dialogLoading || selectedUser?.id === currentUser?.id}
                    />
                    <Label htmlFor="isAdmin" >Administrator Status</Label>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={handleDialogClose} disabled={dialogLoading}>Cancel</Button>
              <Button onClick={handleDialogSubmit} disabled={dialogLoading}>
                 {dialogLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                 {dialogLoading ? (dialogMode === 'create' ? 'Creating...' : 'Saving...') : (dialogMode === 'create' ? 'Create User' : 'Save Changes')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </DialogPortal>
      </Dialog>

       {/* Delete Confirmation Dialog */} 
       <Dialog open={deleteConfirmOpen} onOpenChange={setDeleteConfirmOpen}>
        <DialogPortal>
          <DialogOverlay />
          <DialogContent onInteractOutside={closeDeleteConfirm} onEscapeKeyDown={closeDeleteConfirm}>
            <DialogHeader>
              <DialogTitle>Confirm Deletion</DialogTitle>
              <DialogDescription>
                Are you sure you want to delete user {userToDelete?.username} (ID: {userToDelete?.id})? This action cannot be undone.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
               <Button variant="outline" onClick={closeDeleteConfirm} disabled={deleteLoading}>Cancel</Button>
               <Button variant="destructive" onClick={confirmDeleteUser} disabled={deleteLoading}>
                  {deleteLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  {deleteLoading ? 'Deleting...' : 'Delete User'}
               </Button>
            </DialogFooter>
          </DialogContent>
        </DialogPortal>
      </Dialog>

    </TooltipProvider>
  );
};

export default AdminUserManagementPage; 