import React, { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import * as api from '../../services/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, Terminal, Send } from "lucide-react";
import { toast } from "sonner";
import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";

// Define Lock type mirroring api.ts
interface Lock {
    id: number;
    asset_path: string;
    branch: string;
    comment: string | null;
    locked_by: string; // Username
    timestamp: string; // ISO date string
}

// Define type for public config status
interface PublicConfigStatus {
  mail_enabled: boolean;
}

const DashboardPage: React.FC = () => {
  const { user } = useAuth(); // Get logged-in user details
  const [allLocks, setAllLocks] = useState<Lock[]>([]); // Store all locks
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notifyLoading, setNotifyLoading] = useState<{[key: string]: boolean}>({}); // Loading state per lock path
  const [notifyFeedback, setNotifyFeedback] = useState<{ [key: string]: { type: 'success' | 'error', message: string } | null }>({}); // Feedback per lock path
  const [publicConfigStatus, setPublicConfigStatus] = useState<PublicConfigStatus | null>(null);
  const [isPublicConfigLoading, setIsPublicConfigLoading] = useState(true);
  const [notifyDialogOpen, setNotifyDialogOpen] = useState<{[key: string]: boolean}>({}); // State for dialog open status per lock
  const [notifyMessage, setNotifyMessage] = useState<string>(''); // State for message in the open dialog

  // Fetch Locks
  useEffect(() => {
    const fetchAllLocks = async () => {
      if (!user) return;
      setIsLoading(true);
      setError(null);
      try {
        const fetchedLocks = await api.getLocks();
        setAllLocks(fetchedLocks);
      } catch (err) {
        console.error("Failed to fetch locks:", err);
        setError("Failed to load lock data. Please try again later.");
      } finally {
        setIsLoading(false);
      }
    };
    fetchAllLocks();
  }, [user]);

  // Fetch Public Config Status (for mail_enabled)
  useEffect(() => {
    const fetchPublicConfig = async () => {
      setIsPublicConfigLoading(true);
      try {
        const status = await api.getConfigStatus(); // Use the new API function
        setPublicConfigStatus(status);
        console.log("Fetched public config status:", status);
      } catch (err: any) {
        console.error("Failed to fetch public config status:", err);
        toast.error("Error fetching system status", {
            description: "Could not load email system status. Notify button may be incorrectly enabled."
        });
        setPublicConfigStatus(null);
      } finally {
        setIsPublicConfigLoading(false);
      }
    };
    if(user) {
       fetchPublicConfig();
    }
  }, [user]);

  const handleReleaseLock = async (lockId: number, assetPath: string) => {
    // Find the specific lock in the current state to show feedback if needed
    const lockToRelease = allLocks.find(lock => lock.id === lockId);
    if (!lockToRelease) return; 

    // Optional: Add specific loading state for the button/card being released
    console.log(`Attempting release for lock ID: ${lockId}, Path: ${assetPath}`); // Log attempt
    setError(null); // Clear previous general errors

    try {
      await api.releaseLock(assetPath);
      // Log state update details
      setAllLocks(currentLocks => {
        console.log(`Current locks before filter (ID: ${lockId}):`, currentLocks.length, currentLocks.map(l => l.id));
        const nextLocks = currentLocks.filter(lock => lock.id !== lockId);
        console.log(`Next locks after filter (ID: ${lockId}):`, nextLocks.length, nextLocks.map(l => l.id));
        return nextLocks;
      });
      toast.success("Lock Released", { description: `Successfully released lock for ${assetPath}.` });
    } catch (err: any) {
      console.error(`Failed to release lock ${lockId} (${assetPath}):`, err);
      toast.error("Error Releasing Lock", { description: err.response?.data?.msg || `Failed to release lock for ${assetPath}.` });
    }
  };

  const handleNotifyLockHolder = async (assetPath: string) => {
    // Message comes from notifyMessage state
    const messageToSend = notifyMessage.trim() || undefined; // Send undefined if empty/whitespace
    
    setNotifyLoading(prev => ({ ...prev, [assetPath]: true }));
    setNotifyFeedback(prev => ({ ...prev, [assetPath]: null })); // Clear previous feedback
    
    try {
      // Pass the message to the API call
      const response = await api.notifyLockHolder(assetPath, messageToSend);
      setNotifyFeedback(prev => ({ ...prev, [assetPath]: { type: 'success', message: response.msg || "Notification sent!" } }));
      // Auto-clear success message after a few seconds
      setTimeout(() => {
         setNotifyFeedback(prev => ({ ...prev, [assetPath]: null }));
      }, 5000);
      setNotifyDialogOpen(prev => ({ ...prev, [assetPath]: false })); // Close dialog on success
      setNotifyMessage(''); // Clear message input
    } catch (err: any) {
        console.error(`Failed to send notification for ${assetPath}:`, err);
        setNotifyFeedback(prev => ({ ...prev, [assetPath]: { type: 'error', message: err.response?.data?.msg || "Failed to send notification." } }));
        // Do not close dialog on error, let user see feedback
        // Optional: auto-clear error message too
        setTimeout(() => {
            setNotifyFeedback(prev => ({ ...prev, [assetPath]: null }));
        }, 7000);
    } finally {
        setNotifyLoading(prev => ({ ...prev, [assetPath]: false }));
    }
  };

  // Function to handle opening the dialog and resetting state
  const handleOpenNotifyDialog = (assetPath: string) => {
    setNotifyMessage(''); // Clear message from previous dialogs
    setNotifyFeedback(prev => ({ ...prev, [assetPath]: null })); // Clear feedback
    setNotifyDialogOpen(prev => ({ ...prev, [assetPath]: true }));
  };

  // Filter locks inside the component body before rendering
  const userLocks = allLocks.filter(lock => lock.locked_by === user?.username);
  const otherLocks = allLocks.filter(lock => lock.locked_by !== user?.username);
  
  // Determine if mail is enabled from fetched public config status
  const isMailEnabled = !isPublicConfigLoading && publicConfigStatus?.mail_enabled === true;

  // Determine combined loading state for initial display
  const isInitiallyLoading = isLoading || isPublicConfigLoading;

  if (!user) {
    // Should ideally be handled by ProtectedRoute, but provides fallback
    // Use shadcn Alert for consistency
    return (
      <Alert variant="destructive" className="mt-4">
        <Terminal className="h-4 w-4" />
        <AlertTitle>Authentication Error</AlertTitle>
        <AlertDescription>Please log in to view the dashboard.</AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="mt-2 space-y-6 p-6 max-w-5xl mx-auto">
      <h1 className="text-3xl font-bold">
        Welcome, {user.username}!
      </h1>
      <p className="text-sm text-muted-foreground">
        Email: {user.email}
      </p>
      <p className="text-sm text-muted-foreground">
        Status: {user.is_admin ? 'Administrator' : 'User'}
      </p>

      <Separator className="my-6" /> 

      {isInitiallyLoading && (
        <div className="flex justify-center my-3">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      )}

      {error && (
        <Alert variant="destructive" className="my-2">
           <Terminal className="h-4 w-4" /> 
           <AlertTitle>Error Loading Locks</AlertTitle>
           <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {!isInitiallyLoading && (
        <>
          <h2 className="text-2xl font-semibold">
            Your Locked Assets ({userLocks.length})
          </h2>
          {userLocks.length === 0 ? (
            <p className="text-muted-foreground">You currently have no assets locked.</p>
          ) : (
            <div className="space-y-4">
              {userLocks.map((lock) => (
                <Card key={lock.id}>
                  <CardHeader>
                    <CardTitle className="text-lg break-all">{lock.asset_path}</CardTitle>
                     <CardDescription>
                        Locked on branch: {lock.branch} at {new Date(lock.timestamp).toLocaleString()}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {lock.comment && (
                      <p className="text-sm text-muted-foreground">
                        Comment: {lock.comment}
                      </p>
                    )}
                    <Button 
                      size="sm" 
                      onClick={() => handleReleaseLock(lock.id, lock.asset_path)}
                    >
                      Release Lock
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          <Separator className="my-6" /> 

          <h2 className="text-2xl font-semibold">
            Other Locked Assets ({otherLocks.length})
          </h2>
          {otherLocks.length === 0 ? (
            <p className="text-muted-foreground">No other users currently have assets locked.</p>
          ) : (
            <div className="space-y-4">
              {otherLocks.map((lock) => (
                <Dialog key={lock.id} open={notifyDialogOpen[lock.asset_path] || false} onOpenChange={(open) => setNotifyDialogOpen(prev => ({ ...prev, [lock.asset_path]: open }))}>
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-lg break-all">{lock.asset_path}</CardTitle>
                      <CardDescription>
                        Locked by: {lock.locked_by} on branch: {lock.branch} at {new Date(lock.timestamp).toLocaleString()}
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      {lock.comment && (
                        <p className="text-sm text-muted-foreground">Comment: {lock.comment}</p>
                      )}
                      <div className="flex items-center space-x-2">
                        <DialogTrigger asChild>
                          <Button
                            size="sm"
                            disabled={!isMailEnabled}
                            title={!isMailEnabled ? "Email system is disabled in configuration." : "Send a notification email to the lock holder"}
                            onClick={() => handleOpenNotifyDialog(lock.asset_path)} // Prepare dialog state on click
                          >
                            <Send className="mr-2 h-4 w-4" />
                            Notify User
                          </Button>
                        </DialogTrigger>
                      </div>
                    </CardContent>
                  </Card>
                  <DialogContent className="sm:max-w-[425px]">
                    <DialogHeader>
                      <DialogTitle>Notify {lock.locked_by}</DialogTitle>
                      <DialogDescription>
                        Send an email notification regarding the lock on <span className="font-medium break-all">{lock.asset_path}</span>. You can add an optional message.
                      </DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor={`message-${lock.id}`} className="text-right">
                          Message
                        </Label>
                        <Textarea
                          id={`message-${lock.id}`}
                          value={notifyMessage}
                          onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setNotifyMessage(e.target.value)}
                          placeholder="(Optional) Add a reason for the notification..."
                          className="col-span-3"
                          rows={4}
                        />
                      </div>
                      {/* Display feedback inside the dialog */}
                      {notifyFeedback[lock.asset_path] && (
                         <div className={`col-span-4 text-sm ${notifyFeedback[lock.asset_path]?.type === 'error' ? 'text-red-600' : 'text-green-600'}`}>
                             {notifyFeedback[lock.asset_path]?.message}
                         </div>
                      )}
                    </div>
                    <DialogFooter>
                      <DialogClose asChild>
                         <Button type="button" variant="secondary">Cancel</Button>
                      </DialogClose>
                      <Button 
                        type="submit" 
                        onClick={() => handleNotifyLockHolder(lock.asset_path)}
                        disabled={notifyLoading[lock.asset_path]}
                      >
                        {notifyLoading[lock.asset_path] ? (
                           <Loader2 className="mr-2 h-4 w-4 animate-spin" /> 
                        ) : null}
                        Send Notification
                      </Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default DashboardPage; 