import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, AlertTriangle, Activity, CheckCircle, TrendingUp, TrendingDown, Clock, Target, Zap, Server, Globe, Database, ArrowUpRight, ArrowDownRight, RefreshCw, ExternalLink, Eye, Play } from "lucide-react";
import { StatCard } from "@/components/ui/stat-card";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid, LineChart, Line, Legend, Area, AreaChart } from "recharts";
import { mockChartData, mockVulnerabilities } from "@/data/mockData";
import DashboardLayout from "@/components/layout/DashboardLayout";

const Dashboard = () => {
  const navigate = useNavigate();
  const [selectedVuln, setSelectedVuln] = useState<any>(null);
  const [selectedAsset, setSelectedAsset] = useState<any>(null);
  const [showVulnDialog, setShowVulnDialog] = useState(false);
  const [showAssetDialog, setShowAssetDialog] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const criticalCount = mockVulnerabilities.filter((v) => v.severity === "Critical").length;
  const highCount = mockVulnerabilities.filter((v) => v.severity === "High").length;
  const mediumCount = mockVulnerabilities.filter((v) => v.severity === "Medium").length;
  const lowCount = mockVulnerabilities.filter((v) => v.severity === "Low").length;
  const totalScans = 47;
  const activeScans = 3;
  const resolvedIssues = 156;
  const totalAssets = 23;

  const weeklyTrendData = [
    { day: "Mon", scans: 4, vulnerabilities: 12, resolved: 8 },
    { day: "Tue", scans: 3, vulnerabilities: 8, resolved: 10 },
    { day: "Wed", scans: 5, vulnerabilities: 15, resolved: 12 },
    { day: "Thu", scans: 2, vulnerabilities: 6, resolved: 9 },
    { day: "Fri", scans: 6, vulnerabilities: 18, resolved: 15 },
    { day: "Sat", scans: 1, vulnerabilities: 3, resolved: 5 },
    { day: "Sun", scans: 2, vulnerabilities: 5, resolved: 4 },
  ];

  const monthlyTrendData = [
    { month: "Jan", critical: 5, high: 12, medium: 23, low: 45 },
    { month: "Feb", critical: 3, high: 10, medium: 20, low: 40 },
    { month: "Mar", critical: 4, high: 8, medium: 18, low: 35 },
    { month: "Apr", critical: 2, high: 6, medium: 15, low: 30 },
  ];

  const assetsByType = [
    { name: "Web Servers", value: 8, color: "#8b5cf6" },
    { name: "Databases", value: 5, color: "#3b82f6" },
    { name: "APIs", value: 6, color: "#10b981" },
    { name: "Networks", value: 4, color: "#f59e0b" },
  ];

  const recentActivity = [
    { id: 1, action: "Scan completed", target: "api.example.com", time: "2 minutes ago", status: "success" },
    { id: 2, action: "Critical vulnerability detected", target: "db.example.com", time: "15 minutes ago", status: "critical" },
    { id: 3, action: "Scan started", target: "web.example.com", time: "1 hour ago", status: "running" },
    { id: 4, action: "Vulnerability resolved", target: "api.example.com", time: "2 hours ago", status: "success" },
    { id: 5, action: "New target added", target: "staging.example.com", time: "3 hours ago", status: "info" },
  ];

  const topVulnerableAssets = [
    { name: "api.example.com", critical: 3, high: 5, medium: 8, total: 16 },
    { name: "db.example.com", critical: 2, high: 4, medium: 6, total: 12 },
    { name: "web.example.com", critical: 1, high: 3, medium: 5, total: 9 },
    { name: "staging.example.com", critical: 0, high: 2, medium: 4, total: 6 },
  ];

  const complianceStatus = [
    { framework: "PCI DSS", score: 85, status: "good", change: "+5%" },
    { framework: "GDPR", score: 78, status: "warning", change: "+2%" },
    { framework: "SOC 2", score: 92, status: "excellent", change: "+8%" },
    { framework: "ISO 27001", score: 88, status: "good", change: "+3%" },
  ];

  return (
    <DashboardLayout>
      <div className="space-y-8 animate-fade-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold mb-2">Security Dashboard</h1>
            <p className="text-muted-foreground">Real-time security monitoring and threat intelligence</p>
          </div>
          <div className="flex gap-2">
            <Button 
              variant="outline" 
              className="gap-2"
              onClick={() => navigate("/scan-config")}
            >
              <Play className="h-4 w-4" />
              New Scan
            </Button>
            <Button 
              className="gap-2"
              onClick={() => {
                setIsRefreshing(true);
                setTimeout(() => setIsRefreshing(false), 2000);
              }}
              disabled={isRefreshing}
            >
              <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
              Refresh Data
            </Button>
          </div>
        </div>

        {/* Primary Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div onClick={() => navigate("/scan-config")} className="cursor-pointer transform hover:scale-105 transition-transform">
            <StatCard
              title="Total Scans"
              value={totalScans}
              icon={Shield}
              trend="+12 this week"
            />
          </div>
          <div onClick={() => navigate("/scan-config")} className="cursor-pointer transform hover:scale-105 transition-transform">
            <StatCard
              title="Active Scans"
              value={activeScans}
              icon={Activity}
              variant="default"
            />
          </div>
          <div onClick={() => {
            const criticalVulns = mockVulnerabilities.filter(v => v.severity === "Critical");
            if (criticalVulns.length > 0) {
              setSelectedVuln(criticalVulns[0]);
              setShowVulnDialog(true);
            }
          }} className="cursor-pointer transform hover:scale-105 transition-transform">
            <StatCard
              title="Critical Vulnerabilities"
              value={criticalCount}
              icon={AlertTriangle}
              variant="critical"
              trend="Requires immediate attention"
            />
          </div>
          <div className="cursor-pointer transform hover:scale-105 transition-transform">
            <StatCard
              title="Resolved Issues"
              value={resolvedIssues}
              icon={CheckCircle}
              variant="success"
              trend="+34 this month"
            />
          </div>
        </div>

        {/* Secondary Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card className="border-border cursor-pointer hover:border-primary/50 transition-all transform hover:scale-105">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Total Assets</p>
                  <p className="text-3xl font-bold mt-1">{totalAssets}</p>
                  <p className="text-xs text-green-500 flex items-center gap-1 mt-2">
                    <TrendingUp className="h-3 w-3" />
                    +3 this month
                  </p>
                </div>
                <div className="h-12 w-12 rounded-full bg-blue-500/10 flex items-center justify-center">
                  <Target className="h-6 w-6 text-blue-500" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-border">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Avg Scan Time</p>
                  <p className="text-3xl font-bold mt-1">18m</p>
                  <p className="text-xs text-green-500 flex items-center gap-1 mt-2">
                    <ArrowDownRight className="h-3 w-3" />
                    -5m faster
                  </p>
                </div>
                <div className="h-12 w-12 rounded-full bg-purple-500/10 flex items-center justify-center">
                  <Clock className="h-6 w-6 text-purple-500" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-border">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Security Score</p>
                  <p className="text-3xl font-bold mt-1">7.8/10</p>
                  <p className="text-xs text-green-500 flex items-center gap-1 mt-2">
                    <TrendingUp className="h-3 w-3" />
                    +0.5 improved
                  </p>
                </div>
                <div className="h-12 w-12 rounded-full bg-green-500/10 flex items-center justify-center">
                  <Shield className="h-6 w-6 text-green-500" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-border">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Scan Coverage</p>
                  <p className="text-3xl font-bold mt-1">94%</p>
                  <p className="text-xs text-green-500 flex items-center gap-1 mt-2">
                    <TrendingUp className="h-3 w-3" />
                    +6% increase
                  </p>
                </div>
                <div className="h-12 w-12 rounded-full bg-orange-500/10 flex items-center justify-center">
                  <Zap className="h-6 w-6 text-orange-500" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Charts Row 1 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="border-border">
            <CardHeader>
              <CardTitle>Vulnerabilities by Severity</CardTitle>
              <CardDescription>Current distribution of security issues</CardDescription>
            </CardHeader>
            <CardContent className="p-6 lg:p-10">
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={mockChartData}
                    cx="50%"
                    cy="50%"
                    labelLine={{ stroke: "hsl(var(--foreground))" }}
                    label={({ cx, cy, midAngle, outerRadius, name, value }) => {
                      const RADIAN = Math.PI / 180;
                      const radius = outerRadius + 16;
                      const x = (cx as number) + radius * Math.cos(-midAngle * RADIAN);
                      const y = (cy as number) + radius * Math.sin(-midAngle * RADIAN);
                      return (
                        <text
                          x={x}
                          y={y}
                          fill="hsl(var(--foreground))"
                          textAnchor={x > (cx as number) ? 'start' : 'end'}
                          dominantBaseline="central"
                        >
                          {`${name}: ${value}`}
                        </text>
                      );
                    }}
                    outerRadius={90}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {mockChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      color: "hsl(var(--foreground))",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <Card className="border-border">
            <CardHeader>
              <CardTitle>Assets by Type</CardTitle>
              <CardDescription>Infrastructure distribution</CardDescription>
            </CardHeader>
            <CardContent className="p-6">
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={assetsByType}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    fill="#8884d8"
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {assetsByType.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      color: "hsl(var(--foreground))",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>

        {/* Charts Row 2 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="border-border">
            <CardHeader>
              <CardTitle>Weekly Activity Trends</CardTitle>
              <CardDescription>Scans, vulnerabilities, and resolutions</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={weeklyTrendData}>
                  <defs>
                    <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorVulns" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorResolved" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="day" stroke="hsl(var(--foreground))" />
                  <YAxis stroke="hsl(var(--foreground))" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                    }}
                  />
                  <Legend />
                  <Area type="monotone" dataKey="scans" stroke="#8b5cf6" fillOpacity={1} fill="url(#colorScans)" />
                  <Area type="monotone" dataKey="vulnerabilities" stroke="#ef4444" fillOpacity={1} fill="url(#colorVulns)" />
                  <Area type="monotone" dataKey="resolved" stroke="#10b981" fillOpacity={1} fill="url(#colorResolved)" />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <Card className="border-border">
            <CardHeader>
              <CardTitle>Monthly Vulnerability Trends</CardTitle>
              <CardDescription>Severity distribution over time</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={monthlyTrendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="month" stroke="hsl(var(--foreground))" />
                  <YAxis stroke="hsl(var(--foreground))" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                    }}
                  />
                  <Legend />
                  <Bar dataKey="critical" stackId="a" fill="#dc2626" />
                  <Bar dataKey="high" stackId="a" fill="#f97316" />
                  <Bar dataKey="medium" stackId="a" fill="#eab308" />
                  <Bar dataKey="low" stackId="a" fill="#3b82f6" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>

        {/* Top Vulnerable Assets & Compliance */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="border-border">
            <CardHeader>
              <CardTitle>Top Vulnerable Assets</CardTitle>
              <CardDescription>Assets requiring immediate attention</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {topVulnerableAssets.map((asset, index) => (
                  <div key={index} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Server className="h-4 w-4 text-muted-foreground" />
                        <span className="font-mono text-sm">{asset.name}</span>
                      </div>
                      <span className="text-sm font-semibold">{asset.total} issues</span>
                    </div>
                    <div className="flex gap-2">
                      {asset.critical > 0 && (
                        <Badge variant="destructive" className="text-xs">
                          {asset.critical} Critical
                        </Badge>
                      )}
                      {asset.high > 0 && (
                        <Badge className="bg-orange-500 text-xs">
                          {asset.high} High
                        </Badge>
                      )}
                      {asset.medium > 0 && (
                        <Badge className="bg-yellow-500 text-xs">
                          {asset.medium} Medium
                        </Badge>
                      )}
                    </div>
                    <Progress value={(asset.total / 20) * 100} className="h-2" />
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="border-border">
            <CardHeader>
              <CardTitle>Compliance Status</CardTitle>
              <CardDescription>Security framework compliance scores</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {complianceStatus.map((item, index) => (
                  <div key={index} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold">{item.framework}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-green-500">{item.change}</span>
                        <span className="text-2xl font-bold">{item.score}%</span>
                      </div>
                    </div>
                    <Progress 
                      value={item.score} 
                      className={`h-2 ${
                        item.status === 'excellent' ? '[&>div]:bg-green-500' :
                        item.status === 'good' ? '[&>div]:bg-blue-500' :
                        '[&>div]:bg-yellow-500'
                      }`}
                    />
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Recent Activity & Vulnerabilities */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="border-border">
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
              <CardDescription>Latest security events and actions</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {recentActivity.map((activity) => (
                  <div
                    key={activity.id}
                    className="flex items-start gap-3 p-3 rounded-lg bg-muted/30 border border-border hover:border-primary/50 transition-colors"
                  >
                    <div className={`h-2 w-2 rounded-full mt-2 ${
                      activity.status === 'success' ? 'bg-green-500' :
                      activity.status === 'critical' ? 'bg-red-500 animate-pulse' :
                      activity.status === 'running' ? 'bg-blue-500 animate-pulse' :
                      'bg-gray-500'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium">{activity.action}</p>
                      <p className="text-xs text-muted-foreground font-mono truncate">{activity.target}</p>
                    </div>
                    <span className="text-xs text-muted-foreground whitespace-nowrap">{activity.time}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="border-border">
            <CardHeader>
              <CardTitle>Critical Vulnerabilities</CardTitle>
              <CardDescription>Requires immediate remediation</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {mockVulnerabilities.slice(0, 4).map((vuln) => (
                  <div
                    key={vuln.id}
                    className="flex items-center justify-between p-4 rounded-lg bg-muted/50 border border-border hover:border-primary/50 transition-colors cursor-pointer"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <p className="font-semibold font-mono text-sm">{vuln.cve_id}</p>
                        <Badge variant={
                          vuln.severity === "Critical" ? "destructive" :
                          vuln.severity === "High" ? "destructive" :
                          "secondary"
                        } className="text-xs">
                          {vuln.severity}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground truncate">{vuln.description}</p>
                    </div>
                    <div className="flex items-center gap-2 ml-4">
                      <span className="text-sm font-mono font-semibold">CVSS: {vuln.cvss}</span>
                      <ArrowUpRight className="h-4 w-4 text-muted-foreground" />
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Dashboard;
