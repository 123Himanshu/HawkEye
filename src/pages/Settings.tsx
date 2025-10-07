import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import DashboardLayout from "@/components/layout/DashboardLayout";
import { Bell, Shield, Database, Zap } from "lucide-react";

const Settings = () => {
  return (
    <DashboardLayout>
      <div className="space-y-6 animate-fade-in">
        <div>
          <h1 className="text-4xl font-bold mb-2">Settings</h1>
          <p className="text-muted-foreground">Configure your security preferences</p>
        </div>

        <div className="grid gap-6">
          <Card className="border-border">
            <CardHeader>
              <div className="flex items-center gap-3">
                <Bell className="h-5 w-5 text-primary" />
                <div>
                  <CardTitle>Notifications</CardTitle>
                  <CardDescription>Manage alert preferences</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Button variant="outline">Configure Alerts</Button>
            </CardContent>
          </Card>

          <Card className="border-border">
            <CardHeader>
              <div className="flex items-center gap-3">
                <Shield className="h-5 w-5 text-primary" />
                <div>
                  <CardTitle>Security Policies</CardTitle>
                  <CardDescription>Define scanning rules and thresholds</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Button variant="outline">Manage Policies</Button>
            </CardContent>
          </Card>

          <Card className="border-border">
            <CardHeader>
              <div className="flex items-center gap-3">
                <Database className="h-5 w-5 text-primary" />
                <div>
                  <CardTitle>Integrations</CardTitle>
                  <CardDescription>Connect external tools and services</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Button variant="outline">View Integrations</Button>
            </CardContent>
          </Card>

          <Card className="border-border">
            <CardHeader>
              <div className="flex items-center gap-3">
                <Zap className="h-5 w-5 text-primary" />
                <div>
                  <CardTitle>API Access</CardTitle>
                  <CardDescription>Manage API keys and webhooks</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Button variant="outline">API Settings</Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Settings;
