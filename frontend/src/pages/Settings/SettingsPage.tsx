import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import * as api from '../../services/api';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, Terminal } from "lucide-react";

const SettingsPage: React.FC = () => {
  const { user } = useAuth(); // Need user for context

  // State for Change Password
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordSuccess, setPasswordSuccess] = useState<string | null>(null);

  // State for Change Email
  const [newEmail, setNewEmail] = useState('');
  const [emailPassword, setEmailPassword] = useState(''); // Password required for email change
  const [emailLoading, setEmailLoading] = useState(false);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [emailSuccess, setEmailSuccess] = useState<string | null>(null);

  const handlePasswordChange = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPasswordError(null);
    setPasswordSuccess(null);

    if (newPassword !== confirmPassword) {
      setPasswordError('New passwords do not match.');
      return;
    }
    if (!currentPassword || !newPassword) {
        setPasswordError('All password fields are required.');
        return;
    }

    setPasswordLoading(true);
    try {
      const response = await api.changePasswordSelf({ current_password: currentPassword, new_password: newPassword });
      setPasswordSuccess(response.msg || 'Confirmation email sent. Please check your inbox.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      console.error("Password change failed:", err);
      const errorMsg = err.response?.data?.msg || 'Failed to initiate password change.';
      setPasswordError(errorMsg);
    } finally {
      setPasswordLoading(false);
    }
  };

  const handleEmailChange = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setEmailError(null);
    setEmailSuccess(null);

    if (!newEmail || !emailPassword) {
        setEmailError('New email and current password are required.');
        return;
    }

    setEmailLoading(true);
    try {
      const response = await api.changeEmailSelf({ new_email: newEmail, current_password: emailPassword });
      setEmailSuccess(response.msg || 'Confirmation email sent. Please check your inbox.');
      setNewEmail('');
      setEmailPassword('');
    } catch (err: any) {
      console.error("Email change failed:", err);
      const errorMsg = err.response?.data?.msg || 'Failed to initiate email change.';
      setEmailError(errorMsg);
    } finally {
      setEmailLoading(false);
    }
  };

  return (
    <div className="mt-2 space-y-6 p-6 max-w-5xl mx-auto">
      <h1 className="text-3xl font-bold">
        User Settings
      </h1>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Change Password Card */}
        <Card>
          <form onSubmit={handlePasswordChange}>
            <CardHeader>
              <CardTitle className="text-2xl mb-6">Change Password</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {passwordError && (
                  <Alert variant="destructive">
                    <Terminal className="h-4 w-4" />
                    <AlertTitle>Error</AlertTitle>
                    <AlertDescription>{passwordError}</AlertDescription>
                  </Alert>
              )}
              {passwordSuccess && (
                  <Alert>
                    <Terminal className="h-4 w-4" />
                    <AlertTitle>Success</AlertTitle>
                    <AlertDescription>{passwordSuccess}</AlertDescription>
                  </Alert>
              )}
              <div className="space-y-2">
                <Label htmlFor="currentPassword">Current Password</Label>
                <Input
                  id="currentPassword"
                  required
                  name="currentPassword"
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  disabled={passwordLoading}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="newPassword">New Password</Label>
                <Input
                  id="newPassword"
                  required
                  name="newPassword"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  disabled={passwordLoading}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirmPassword">Confirm New Password</Label>
                <Input
                  id="confirmPassword"
                  required
                  name="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={passwordLoading}
                />
              </div>
            </CardContent>
            <CardFooter className="pt-4">
              <Button type="submit" disabled={passwordLoading} className="w-full">
                {passwordLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                {passwordLoading ? 'Changing...' : 'Change Password'}
              </Button>
            </CardFooter>
          </form>
        </Card>

        {/* Change Email Card */}
        <Card>
           <form onSubmit={handleEmailChange}>
            <CardHeader>
              <CardTitle className="text-2xl mb-6">Change Email</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {emailError && (
                <Alert variant="destructive">
                  <Terminal className="h-4 w-4" />
                  <AlertTitle>Error</AlertTitle>
                  <AlertDescription>{emailError}</AlertDescription>
                </Alert>
              )}
              {emailSuccess && (
                  <Alert>
                    <Terminal className="h-4 w-4" />
                    <AlertTitle>Success</AlertTitle>
                    <AlertDescription>{emailSuccess}</AlertDescription>
                  </Alert>
              )}
              <div className="space-y-2">
                <Label htmlFor="currentEmail">Current Email Address</Label>
                <Input
                  id="currentEmail"
                  name="currentEmail"
                  type="email"
                  value={user?.email || ''}
                  readOnly
                  className="bg-muted cursor-default"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="newEmail">New Email Address</Label>
                <Input
                  id="newEmail"
                  required
                  name="newEmail"
                  type="email"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  disabled={emailLoading}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="emailPassword">Current Password (for verification)</Label>
                <Input
                  id="emailPassword"
                  required
                  name="emailPassword"
                  type="password"
                  value={emailPassword}
                  onChange={(e) => setEmailPassword(e.target.value)}
                  disabled={emailLoading}
                />
              </div>
            </CardContent>
            <CardFooter className="pt-4">
              <Button type="submit" disabled={emailLoading} className="w-full">
                {emailLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                {emailLoading ? 'Changing...' : 'Change Email'}
              </Button>
            </CardFooter>
           </form>
        </Card>
      </div>
    </div>
  );
};

export default SettingsPage; 