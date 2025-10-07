import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import DashboardLayout from "@/components/layout/DashboardLayout";
import { mockTargets } from "@/data/mockData";
import { Search, Plus, Filter, Download, Eye, Trash2, Play, Pause, MoreVertical, AlertTriangle, CheckCircle, Clock, XCircle, Server, Globe, Database, Shield, TrendingUp, Calendar, Activity } from "lucide-react";

const Targets = () => {
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [toolFilter, setToolFilter] = useState("all");
  const [selectedTarget, setSelectedTarget] = useState<any>(null);
  const [showDetails, setShowDetails] = useState(false);
  const [showAddTarget, setShowAddTarget] = useState(false);

  const filteredTargets = mockTargets.filter((target) => {
    const matchesSearch = target.target.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === "all" || target.status === statusFilter;
    const matchesTool = toolFilter === "all" || target.tool === toolFilter;
    return matchesSearch && matchesStatus && matchesTool;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case "Completed":
        return "bg-green-500 text-white";
      case "Running":
        return "bg-blue-500 text-white animate-pulse";
      case "Pending":
        return "bg-yellow-500 text-white";
      case "Failed":
        return "bg-red-500 text-white";
      default:
        return "bg-muted";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "Completed":
        return <CheckCircle className="h-4 w-4" />;
      case "Running":
        return <Activity className="h-4 w-4 animate-pulse" />;
      case "Pending":
        return <Clock className="h-4 w-4" />;
      case "Failed":
        return <XCircle className="h-4 w-4" />;
      default:
        return null;
    }
  };

  const handleViewDetails = (target: any) => {
    setSelectedTarget(target);
    setShowDetails(true);
  };

  const stats = {
    total: mockTargets.length,
    running: mockTargets.filter(t => t.status === "Running").length,
    completed: mockTargets.filter(t => t.status === "Completed").length,
    failed: mockTargets.filter(t => t.status === "Failed").length,
  };

  const targetDetails = selectedTarget ? {
    ...selectedTarget,
    lastScan: "2024-04-15 14:30:00",
    nextScan: "2024-04-16 14:30:00",
    scanFrequency: "Daily",
    totalScans: 47,
    avgScanTime: "18m 32s",
    criticalVulns: 3,
    highVulns: 8,
    mediumVulns: 12,
    lowVulns: 23,
    riskScore: 7.2,
    complianceScore: 85,
    openPorts: [22, 80, 443, 3306, 8080],
    services: ["SSH", "HTTP", "HTTPS", "MySQL", "Tomcat"],
    technologies: ["nginx 1.18.0", "Node.js 16.14", "MySQL 8.0", "Redis 6.2"],
    scanHistory: [
      { date: "2024-04-15", vulnerabilities: 46, status: "Completed" },
      { date: "2024-04-14", vulnerabilities: 42, status: "Completed" },
      { date: "2024-04-13", vulnerabilities: 45, status: "Completed" },
      { date: "2024-04-12", vulnerabilities: 48, status: "Completed" },
    ]
  } : null;

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Scan Targets</h1>
            <p className="text-muted-foreground">Manage and monitor your security scan targets</p>
          </div>
          <Button onClick={() => setShowAddTarget(true)} className="gap-2">
            <Plus className="h-4 w-4" />
            Add Target
          </Button>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Total Targets</p>
                  <p className="text-2xl font-bold">{stats.total}</p>
                </div>
                <Server className="h-8 w-8 text-muted-foreground" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Running</p>
                  <p className="text-2xl font-bold text-blue-500">{stats.running}</p>
                </div>
                <Activity className="h-8 w-8 text-blue-500 animate-pulse" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Completed</p>
                  <p className="text-2xl font-bold text-green-500">{stats.completed}</p>
                </div>
                <CheckCircle className="h-8 w-8 text-green-500" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Failed</p>
                  <p className="text-2xl font-bold text-red-500">{stats.failed}</p>
                </div>
                <XCircle className="h-8 w-8 text-red-500" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Filters and Search */}
        <Card>
          <CardHeader>
            <CardTitle>Targets</CardTitle>
            <CardDescription>View and manage all scan targets</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col md:flex-row gap-4 mb-6">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search targets..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-full md:w-[180px]">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="Completed">Completed</SelectItem>
                  <SelectItem value="Running">Running</SelectItem>
                  <SelectItem value="Pending">Pending</SelectItem>
                  <SelectItem value="Failed">Failed</SelectItem>
                </SelectContent>
              </Select>
              <Select value={toolFilter} onValueChange={setToolFilter}>
                <SelectTrigger className="w-full md:w-[180px]">
                  <SelectValue placeholder="Tool" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Tools</SelectItem>
                  <SelectItem value="Nmap">Nmap</SelectItem>
                  <SelectItem value="Nuclei">Nuclei</SelectItem>
                  <SelectItem value="Nessus">Nessus</SelectItem>
                  <SelectItem value="OpenVAS">OpenVAS</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" className="gap-2">
                <Download className="h-4 w-4" />
                Export
              </Button>
            </div>

            {/* Targets Table */}
            <div className="border rounded-lg">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Target</TableHead>
                    <TableHead>Tool</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead className="text-right">Vulnerabilities</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredTargets.map((target) => (
                    <TableRow key={target.id} className="cursor-pointer hover:bg-muted/50">
                      <TableCell className="font-mono font-semibold">{target.target}</TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {target.tool}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={getStatusColor(target.status)}>
                          {target.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{target.started_at}</TableCell>
                      <TableCell className="text-right font-semibold">
                        {target.vulnerabilities || 0}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleViewDetails(target)}
                          className="gap-2"
                        >
                          <Eye className="h-4 w-4" />
                          View
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Target Details Dialog */}
        <Dialog open={showDetails} onOpenChange={setShowDetails}>
          <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="text-2xl">Target Details</DialogTitle>
              <DialogDescription>
                Comprehensive information about {selectedTarget?.target}
              </DialogDescription>
            </DialogHeader>

            {targetDetails && (
              <Tabs defaultValue="overview" className="mt-4">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                  <TabsTrigger value="services">Services</TabsTrigger>
                  <TabsTrigger value="history">History</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Risk Score</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="text-3xl font-bold text-orange-500">{targetDetails.riskScore}/10</div>
                        <Progress value={targetDetails.riskScore * 10} className="mt-2" />
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Compliance Score</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="text-3xl font-bold text-green-500">{targetDetails.complianceScore}%</div>
                        <Progress value={targetDetails.complianceScore} className="mt-2" />
                      </CardContent>
                    </Card>
                  </div>

                  <Card>
                    <CardHeader>
                      <CardTitle>Scan Information</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Last Scan:</span>
                        <span className="font-semibold">{targetDetails.lastScan}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Next Scan:</span>
                        <span className="font-semibold">{targetDetails.nextScan}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Frequency:</span>
                        <span className="font-semibold">{targetDetails.scanFrequency}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Total Scans:</span>
                        <span className="font-semibold">{targetDetails.totalScans}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Avg Scan Time:</span>
                        <span className="font-semibold">{targetDetails.avgScanTime}</span>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="vulnerabilities" className="space-y-4">
                  <div className="grid grid-cols-4 gap-4">
                    <Card>
                      <CardContent className="pt-6">
                        <div className="text-center">
                          <p className="text-sm text-muted-foreground">Critical</p>
                          <p className="text-2xl font-bold text-red-500">{targetDetails.criticalVulns}</p>
                        </div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="pt-6">
                        <div className="text-center">
                          <p className="text-sm text-muted-foreground">High</p>
                          <p className="text-2xl font-bold text-orange-500">{targetDetails.highVulns}</p>
                        </div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="pt-6">
                        <div className="text-center">
                          <p className="text-sm text-muted-foreground">Medium</p>
                          <p className="text-2xl font-bold text-yellow-500">{targetDetails.mediumVulns}</p>
                        </div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardContent className="pt-6">
                        <div className="text-center">
                          <p className="text-sm text-muted-foreground">Low</p>
                          <p className="text-2xl font-bold text-blue-500">{targetDetails.lowVulns}</p>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>

                <TabsContent value="services" className="space-y-4">
                  <Card>
                    <CardHeader>
                      <CardTitle>Open Ports</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {targetDetails.openPorts.map((port) => (
                          <Badge key={port} variant="outline">{port}</Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle>Services</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {targetDetails.services.map((service) => (
                          <Badge key={service}>{service}</Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle>Technologies</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {targetDetails.technologies.map((tech) => (
                          <div key={tech} className="flex items-center gap-2">
                            <Server className="h-4 w-4 text-muted-foreground" />
                            <span>{tech}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="history" className="space-y-4">
                  <Card>
                    <CardHeader>
                      <CardTitle>Scan History</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {targetDetails.scanHistory.map((scan, index) => (
                          <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                            <div className="flex items-center gap-3">
                              <Calendar className="h-4 w-4 text-muted-foreground" />
                              <span className="font-semibold">{scan.date}</span>
                            </div>
                            <div className="flex items-center gap-3">
                              <span className="text-sm text-muted-foreground">
                                {scan.vulnerabilities} vulnerabilities
                              </span>
                              <Badge className="bg-green-500">{scan.status}</Badge>
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </DashboardLayout>
  );
};

export default Targets;
