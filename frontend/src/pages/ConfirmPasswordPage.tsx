import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, KeyRound, AlertCircle } from 'lucide-react';
import apiClient from '../services/api'; // Correct path
import { Button } from "@/components/ui/button";

const ConfirmPasswordPage: React.FC = () => {
  console.log("ConfirmPasswordPage: Rendering component");
  const location = useLocation();
  const navigate = useNavigate();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState<string>('');

  useEffect(() => {
    console.log("ConfirmPasswordPage: useEffect triggered");
    const queryParams = new URLSearchParams(location.search);
    console.log("ConfirmPasswordPage: Query params:", location.search);
    const token = queryParams.get('token');
    console.log("ConfirmPasswordPage: Parsed token:", token);

    if (!token) {
      console.log("ConfirmPasswordPage: No token found, setting error status.");
      setStatus('error');
      setMessage('No confirmation token found in URL.');
      return;
    }

    const confirmPassword = async () => {
      console.log("ConfirmPasswordPage: confirmPassword async function entered");
      try {
        console.log(`ConfirmPasswordPage: Attempting API call to /api/confirm-password/${token}`);
        const response = await apiClient.get(`/confirm-password/${token}`);
        console.log("ConfirmPasswordPage: API call successful", response);
        setStatus('success');
        setMessage(response.data.msg || 'Password change confirmed successfully! You can now log in with your new password.');
      } catch (err: any) {
        console.error("Password confirmation error:", err);
        console.log("ConfirmPasswordPage: API call failed", err);
        setStatus('error');
        setMessage(err.response?.data?.message || 'Failed to confirm password change. The link may be invalid or expired.');
      }
    };

    console.log("ConfirmPasswordPage: Calling confirmPassword async function");
    confirmPassword();

  }, [location.search]);

  console.log(`ConfirmPasswordPage: Rendering with status: ${status}, message: ${message}`);

  const handleLoginRedirect = () => {
    navigate('/login');
  };

  return (
    <div className="flex items-center justify-center min-h-screen">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-center">Password Confirmation</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {status === 'loading' && (
            <div className="flex justify-center items-center space-x-2">
              <Loader2 className="h-6 w-6 animate-spin" />
              <span>Verifying password change...</span>
            </div>
          )}
          {status === 'success' && (
            <Alert variant="default" className="bg-green-100 dark:bg-green-900 border-green-300 dark:border-green-700">
              <KeyRound className="h-5 w-5 text-green-600 dark:text-green-400" />
              <AlertTitle className="text-green-800 dark:text-green-200">Success!</AlertTitle>
              <AlertDescription className="text-green-700 dark:text-green-300">
                {message}
              </AlertDescription>
            </Alert>
          )}
          {status === 'error' && (
            <Alert variant="destructive">
              <AlertCircle className="h-5 w-5" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{message}</AlertDescription>
            </Alert>
          )}
          {(status === 'success' || status === 'error') && (
              <Button onClick={handleLoginRedirect} className="w-full">Proceed to Login</Button>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default ConfirmPasswordPage; 