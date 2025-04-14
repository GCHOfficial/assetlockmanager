import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, MailCheck, AlertCircle } from 'lucide-react';
import apiClient from '../services/api'; // Corrected path
import { Button } from "@/components/ui/button";

const ConfirmEmailPage: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState<string>('');

  useEffect(() => {
    const queryParams = new URLSearchParams(location.search);
    const token = queryParams.get('token');

    if (!token) {
      setStatus('error');
      setMessage('No confirmation token found in URL.');
      return;
    }

    const confirmEmail = async () => {
      try {
        // Use apiClient which has the correct base URL (/api)
        const response = await apiClient.get(`/confirm-email/${token}`);
        setStatus('success');
        setMessage(response.data.msg || 'Email confirmed successfully! You can now log in.');
      } catch (err: any) {
        setStatus('error');
        console.error("Email confirmation error:", err);
        setMessage(err.response?.data?.message || 'Failed to confirm email. The link may be invalid or expired.');
      }
    };

    confirmEmail();
  }, [location.search]);

  const handleLoginRedirect = () => {
    navigate('/login');
  };

  return (
    <div className="flex items-center justify-center min-h-screen">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-center">Email Confirmation</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {status === 'loading' && (
            <div className="flex justify-center items-center space-x-2">
              <Loader2 className="h-6 w-6 animate-spin" />
              <span>Verifying your email...</span>
            </div>
          )}
          {status === 'success' && (
            <Alert variant="default" className="bg-green-100 dark:bg-green-900 border-green-300 dark:border-green-700">
              <MailCheck className="h-5 w-5 text-green-600 dark:text-green-400" />
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

export default ConfirmEmailPage; 