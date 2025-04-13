import React, { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, Terminal, Mail } from "lucide-react"; // Using lucide icons
import { Separator } from "@/components/ui/separator"; // Import Separator

import * as api from '../../services/api';

// Interface for the config object (add mail fields)
interface AdminConfig {
    jwt_expiry_enabled: boolean;
    jwt_expiry_minutes: number;
    auto_release_enabled: boolean;
    auto_release_hours: number;
    mail_enabled: boolean;
    mail_server: string;
    mail_port: number;
    mail_use_tls: boolean;
    mail_use_ssl: boolean;
    mail_username: string;
    mail_sender: string;
}

// Placeholder component for Admin Configuration
const AdminConfigurationPage: React.FC = () => {

  // State for config values
  const [config, setConfig] = useState<AdminConfig | null>(null);
  
  // State for UI feedback
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Fetch current configuration on component mount
  useEffect(() => {
    const fetchConfig = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const fetchedConfig: Partial<AdminConfig> = await api.getAdminConfig(); 
        setConfig({
          jwt_expiry_enabled: fetchedConfig.jwt_expiry_enabled ?? false,
          jwt_expiry_minutes: fetchedConfig.jwt_expiry_minutes ?? 0,
          auto_release_enabled: fetchedConfig.auto_release_enabled ?? false,
          auto_release_hours: fetchedConfig.auto_release_hours ?? 0,
          mail_enabled: fetchedConfig.mail_enabled ?? false,
          mail_server: fetchedConfig.mail_server ?? '',
          mail_port: fetchedConfig.mail_port ?? 0,
          mail_use_tls: fetchedConfig.mail_use_tls ?? false,
          mail_use_ssl: fetchedConfig.mail_use_ssl ?? false,
          mail_username: fetchedConfig.mail_username ?? '',
          mail_sender: fetchedConfig.mail_sender ?? '',
        });
      } catch (err) {
        console.error("Failed to load config:", err);
        setError("Failed to load current configuration.");
      } finally {
        setIsLoading(false);
      }
    };
    fetchConfig();
  }, []);

  const handleConfigChange = (key: keyof AdminConfig, value: any) => {
    setConfig(prevConfig => prevConfig ? { ...prevConfig, [key]: value } : null);
  };

  const handleSaveConfig = async () => {
    if (!config) return;

    setError(null);
    setSuccess(null);
    setIsSaving(true);
    
    // Prepare payload, only send values if relevant switch is enabled
    const payload = {
      jwt_expiry_enabled: config.jwt_expiry_enabled,
      jwt_expiry_minutes: config.jwt_expiry_enabled ? config.jwt_expiry_minutes : undefined,
      auto_release_enabled: config.auto_release_enabled,
      auto_release_hours: config.auto_release_enabled ? config.auto_release_hours : undefined,
      // Send mail settings only if mail is enabled (or being enabled)
      mail_enabled: config.mail_enabled,
      mail_server: config.mail_enabled ? config.mail_server : undefined,
      mail_port: config.mail_enabled ? config.mail_port : undefined,
      mail_use_tls: config.mail_enabled ? config.mail_use_tls : undefined,
      mail_use_ssl: config.mail_enabled ? config.mail_use_ssl : undefined,
      mail_username: config.mail_enabled ? config.mail_username : undefined,
      mail_sender: config.mail_enabled ? config.mail_sender : undefined,
      // Password is not set via this UI
    };

    console.log("Attempting to save configuration:", payload);

    try {
      await api.updateAdminConfig(payload); 
      setSuccess("Configuration saved successfully!");
    } catch (err: any) {
       console.error("Failed to save config:", err);
       setError(err.response?.data?.message || "Failed to save configuration.");
    } finally {
       setIsSaving(false);
    }
  };

  // Render loading state while fetching initial config
  if (isLoading || !config) { // Also check if config is null
     return <div className="flex justify-center my-3"><Loader2 className="h-8 w-8 animate-spin" /></div>;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>System Configuration</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {/* JWT Settings */}
          <div className="space-y-3">
            <h3 className="text-lg font-medium">JWT Settings</h3>
            <div className="flex items-center space-x-2">
              <Switch
                  id="jwt-expiry-switch"
                  checked={config.jwt_expiry_enabled}
                  onCheckedChange={(checked) => handleConfigChange('jwt_expiry_enabled', checked)}
              />
              <Label htmlFor="jwt-expiry-switch">Enable JWT Expiration</Label>
            </div>
            <div className="grid w-full max-w-sm items-center gap-1.5">
              <Label htmlFor="jwt-expiry-minutes">Token Expiry (minutes)</Label>
              <Input
                  id="jwt-expiry-minutes"
                  type="number"
                  value={config.jwt_expiry_minutes || 0}
                  onChange={(e) => handleConfigChange('jwt_expiry_minutes', parseInt(e.target.value, 10) || 0)}
                  disabled={!config.jwt_expiry_enabled}
                  min={1}
              />
            </div>
          </div>

          <Separator />

          {/* Automatic Lock Release Settings */}
          <div className="space-y-3">
            <h3 className="text-lg font-medium">Automatic Lock Release</h3>
            <div className="flex items-center space-x-2">
               <Switch
                  id="auto-release-switch"
                  checked={config.auto_release_enabled}
                  onCheckedChange={(checked) => handleConfigChange('auto_release_enabled', checked)}
               />
              <Label htmlFor="auto-release-switch">Enable Automatic Release of Old Locks</Label>
            </div>
            <div className="grid w-full max-w-sm items-center gap-1.5">
              <Label htmlFor="auto-release-hours">Release Locks Older Than (hours)</Label>
              <Input
                  id="auto-release-hours"
                  type="number"
                  value={config.auto_release_hours || 0}
                  onChange={(e) => handleConfigChange('auto_release_hours', parseInt(e.target.value, 10) || 0)}
                  disabled={!config.auto_release_enabled}
                  min={1}
              />
            </div>
          </div>

          <Separator />

          {/* Email Settings - New Section */}
          <div className="space-y-3">
            <h3 className="text-lg font-medium">Email (SMTP) Settings</h3>
            <div className="flex items-center space-x-2">
              <Switch
                id="mail-enabled-switch"
                checked={config.mail_enabled}
                onCheckedChange={(checked) => handleConfigChange('mail_enabled', checked)}
              />
              <Label htmlFor="mail-enabled-switch">Enable Email Sending</Label>
            </div>

            <div className={`space-y-3 ${!config.mail_enabled ? 'opacity-50 pointer-events-none' : ''}`}>
              <div className="grid w-full max-w-sm items-center gap-1.5">
                <Label htmlFor="mail-server">SMTP Server</Label>
                <Input
                  id="mail-server"
                  value={config.mail_server || ''}
                  onChange={(e) => handleConfigChange('mail_server', e.target.value)}
                  placeholder="smtp.example.com"
                  disabled={!config.mail_enabled}
                />
              </div>
              <div className="grid w-full max-w-sm items-center gap-1.5">
                <Label htmlFor="mail-port">SMTP Port</Label>
                <Input
                  id="mail-port"
                  type="number"
                  value={config.mail_port || ''}
                  onChange={(e) => handleConfigChange('mail_port', parseInt(e.target.value, 10) || 0)}
                  placeholder="587"
                  disabled={!config.mail_enabled}
                />
              </div>
              <div className="grid w-full max-w-sm items-center gap-1.5">
                <Label htmlFor="mail-username">SMTP Username</Label>
                <Input
                  id="mail-username"
                  value={config.mail_username || ''}
                  onChange={(e) => handleConfigChange('mail_username', e.target.value)}
                  placeholder="your-email@example.com"
                  disabled={!config.mail_enabled}
                />
              </div>
              {/* Password Input is Omitted for Security - Should be set via .env */}
              <div className="grid w-full max-w-sm items-center gap-1.5">
                <Label htmlFor="mail-sender">Default Sender Address</Label>
                <Input
                  id="mail-sender"
                  type="email"
                  value={config.mail_sender || ''}
                  onChange={(e) => handleConfigChange('mail_sender', e.target.value)}
                  placeholder="App Name <noreply@example.com>"
                  disabled={!config.mail_enabled}
                />
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="mail-use-tls-switch"
                  checked={config.mail_use_tls}
                  onCheckedChange={(checked) => handleConfigChange('mail_use_tls', checked)}
                  disabled={!config.mail_enabled}
                />
                <Label htmlFor="mail-use-tls-switch">Use TLS</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="mail-use-ssl-switch"
                  checked={config.mail_use_ssl}
                  onCheckedChange={(checked) => handleConfigChange('mail_use_ssl', checked)}
                  disabled={!config.mail_enabled}
                />
                <Label htmlFor="mail-use-ssl-switch">Use SSL</Label>
              </div>
              <Alert variant="default">
                  <Mail className="h-4 w-4" />
                  <AlertTitle>Note</AlertTitle>
                  <AlertDescription>
                    The SMTP Password cannot be set via this UI for security reasons. Please configure it using the MAIL_PASSWORD environment variable for the server container.
                  </AlertDescription>
              </Alert>
            </div>
          </div>

          {error && (
             <Alert variant="destructive">
               <Terminal className="h-4 w-4" /> 
               <AlertTitle>Error</AlertTitle>
               <AlertDescription>{error}</AlertDescription>
             </Alert>
           )}
           {success && (
             <Alert>
               <Terminal className="h-4 w-4" /> {/* Using Terminal icon for general alerts */}
               <AlertTitle>Success</AlertTitle>
               <AlertDescription>{success}</AlertDescription>
             </Alert>
           )}
        </div>
      </CardContent>
      <CardFooter>
        <Button onClick={handleSaveConfig} disabled={isSaving}>
            {isSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            {isSaving ? 'Saving...' : 'Save Configuration'}
        </Button>
      </CardFooter>
    </Card>
  );
};

export default AdminConfigurationPage; 