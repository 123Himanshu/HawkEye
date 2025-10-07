import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SeverityBadge } from "@/components/ui/severity-badge";
import DashboardLayout from "@/components/layout/DashboardLayout";
import { mockVulnerabilities } from "@/data/mockData";
import { Search, Download, FileJson, FileText } from "lucide-react";
import { toast } from "sonner";

const Reports = () => {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");

  const filteredVulns = mockVulnerabilities.filter((vuln) => {
    const matchesSearch = 
      vuln.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      vuln.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === "all" || vuln.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const handleExport = (format: string) => {
    toast.success(`Exporting report as ${format.toUpperCase()}...`);
  };

  return (
    <DashboardLayout>
      <div className="space-y-6 animate-fade-in">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold mb-2">Vulnerability Reports</h1>
            <p className="text-muted-foreground">Detailed analysis of discovered vulnerabilities</p>
          </div>
          <div className="flex gap-2">
            <Button 
              variant="outline" 
              className="gap-2"
              onClick={() => handleExport("json")}
            >
              <FileJson className="h-4 w-4" />
              Export JSON
            </Button>
            <Button 
              variant="outline" 
              className="gap-2"
              onClick={() => handleExport("pdf")}
            >
              <FileText className="h-4 w-4" />
              Export PDF
            </Button>
          </div>
        </div>

        <Card className="border-border">
          <CardHeader>
            <CardTitle>All Vulnerabilities</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4 mb-6">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search CVE or description..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 bg-input border-border"
                />
              </div>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-48 bg-input border-border">
                  <SelectValue placeholder="Filter by severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="Critical">Critical</SelectItem>
                  <SelectItem value="High">High</SelectItem>
                  <SelectItem value="Medium">Medium</SelectItem>
                  <SelectItem value="Low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="rounded-lg border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/50">
                    <TableHead>CVE ID</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>CVSS</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>Component</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Discovered</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredVulns.map((vuln) => (
                    <TableRow key={vuln.id} className="hover:bg-muted/30 transition-colors">
                      <TableCell className="font-mono font-semibold">{vuln.cve_id}</TableCell>
                      <TableCell>
                        <SeverityBadge severity={vuln.severity} />
                      </TableCell>
                      <TableCell>
                        <span className={`font-bold ${
                          vuln.cvss >= 9 ? 'text-critical' :
                          vuln.cvss >= 7 ? 'text-high' :
                          vuln.cvss >= 4 ? 'text-medium' :
                          'text-low'
                        }`}>
                          {vuln.cvss}
                        </span>
                      </TableCell>
                      <TableCell className="max-w-md">{vuln.description}</TableCell>
                      <TableCell className="font-mono text-sm">{vuln.component}</TableCell>
                      <TableCell className="font-mono text-sm">{vuln.target}</TableCell>
                      <TableCell className="text-muted-foreground">{vuln.discovered_at}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>

            <div className="mt-6 p-4 rounded-lg bg-muted/50 border border-border">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">Total Vulnerabilities: {filteredVulns.length}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Critical: {filteredVulns.filter(v => v.severity === "Critical").length} | 
                    High: {filteredVulns.filter(v => v.severity === "High").length} | 
                    Medium: {filteredVulns.filter(v => v.severity === "Medium").length} | 
                    Low: {filteredVulns.filter(v => v.severity === "Low").length}
                  </p>
                </div>
                <Button className="gap-2 bg-primary hover:bg-primary/90">
                  <Download className="h-4 w-4" />
                  Download Full Report
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Reports;
