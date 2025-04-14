import React, { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, Terminal, Mail } from "lucide-react"; // Using lucide icons
import { Separator } from "@/components/ui/separator"; // Import Separator
import { Badge } from "@/components/ui/badge"; // Import Badge

import * as api from '../../services/api';

// Interface for the config object
interface AdminConfig {
    jwt_expiry_enabled: boolean;
    jwt_expiry_minutes: number;
    auto_release_enabled: boolean;
    auto_release_hours: number;
    mail_enabled: boolean; // Added back for display
    startup_mail_test_status: string; // Added for display
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
        // Fetch the full config including the new fields
        const fetchedConfig: Partial<AdminConfig> = await api.getAdminConfig(); 
        setConfig({
          jwt_expiry_enabled: fetchedConfig.jwt_expiry_enabled ?? false,
          jwt_expiry_minutes: fetchedConfig.jwt_expiry_minutes ?? 0,
          auto_release_enabled: fetchedConfig.auto_release_enabled ?? false,
          auto_release_hours: fetchedConfig.auto_release_hours ?? 0,
          mail_enabled: fetchedConfig.mail_enabled ?? false, // Populate mail_enabled
          startup_mail_test_status: fetchedConfig.startup_mail_test_status ?? 'UNKNOWN', // Populate test status
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
    // Don't allow changing read-only status fields
    if (key === 'startup_mail_test_status') return; 
    setConfig(prevConfig => prevConfig ? { ...prevConfig, [key]: value } : null);
  };

  const handleSaveConfig = async () => {
    if (!config) return;

    setError(null);
    setSuccess(null);
    setIsSaving(true);
    
    // Prepare payload - include all editable fields
    const payload: Partial<AdminConfig> = {
      jwt_expiry_enabled: config.jwt_expiry_enabled,
      jwt_expiry_minutes: config.jwt_expiry_enabled ? config.jwt_expiry_minutes : undefined,
      auto_release_enabled: config.auto_release_enabled,
      auto_release_hours: config.auto_release_enabled ? config.auto_release_hours : undefined,
      mail_enabled: config.mail_enabled,
      // startup_mail_test_status is read-only, not sent
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
        <CardTitle>Admin Configuration</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Display general error/success messages */} 
        {error && (
            <Alert variant="destructive">
                <Terminal className="h-4 w-4" />
                <AlertTitle>Error Saving</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
            </Alert>
        )}
        {success && (
            <Alert variant="default"> {/* Assuming success variant exists or use default */} 
                <Terminal className="h-4 w-4" />
                <AlertTitle>Success</AlertTitle>
                <AlertDescription>{success}</AlertDescription>
            </Alert>
        )}

        {/* JWT Settings */}
        <div className="space-y-3">
          <h3 className="text-lg font-medium">JWT Settings</h3>
          <div className="flex items-center space-x-2">
            <Switch
              id="jwt-expiry-switch"
              checked={config.jwt_expiry_enabled}
              onCheckedChange={(checked) => handleConfigChange('jwt_expiry_enabled', checked)}
            />
            <Label htmlFor="jwt-expiry-switch">Enable JWT Expiry</Label>
          </div>
          <div className="grid w-full max-w-sm items-center gap-1.5">
              <Label htmlFor="jwt-expiry-minutes">JWT Expiry Time (minutes)</Label>
              <Input
                  id="jwt-expiry-minutes"
                  type="number"
                  value={config.jwt_expiry_minutes || 0} // Use 0 for infinite
                  onChange={(e) => handleConfigChange('jwt_expiry_minutes', parseInt(e.target.value, 10) || 0)}
                  disabled={!config.jwt_expiry_enabled}
                  min={0} // Allow 0 for infinite
                  placeholder="0 (Infinite)"
              />
              <p className="text-sm text-muted-foreground">Set to 0 for no expiry.</p>
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

        {/* Email Settings - Modified Section */}
        <div className="space-y-3">
          <h3 className="text-lg font-medium">Email Settings</h3>
          <div className="flex items-center space-x-2 mb-2">
            <Switch
              id="mail-enabled-switch"
              checked={config.mail_enabled}
              onCheckedChange={(checked) => handleConfigChange('mail_enabled', checked)}
            />
            <Label htmlFor="mail-enabled-switch">Enable Email System (DB Override)</Label>
          </div>
          <div className="flex items-center space-x-2">
            <span className="font-medium">Startup Test:</span>
            <Badge 
              variant={
                config.startup_mail_test_status === 'SUCCESS' ? 'default' :
                config.startup_mail_test_status === 'FAILED' ? 'destructive' :
                'secondary'
              }
            >
              {config.startup_mail_test_status}
            </Badge>
          </div>
          <Alert variant="default" className="mt-4">
            <Mail className="h-4 w-4" />
            <AlertTitle>Configuration Behavior</AlertTitle>
            <AlertDescription>
              Settings here (JWT Expiry, Auto Release, Mail Enabled) are saved to the database and override the defaults set by environment variables on the server. Email server details (Server, Port, User, Pass, etc.) must still be configured via environment variables.
            </AlertDescription>
          </Alert>
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