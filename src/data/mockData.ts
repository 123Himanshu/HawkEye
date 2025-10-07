export interface Vulnerability {
  id: string;
  cve_id: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  cvss: number;
  description: string;
  component: string;
  target: string;
  discovered_at: string;
}

export interface Target {
  id: number;
  target: string;
  tool: string;
  status: "Pending" | "Running" | "Completed" | "Failed";
  started_at: string;
  vulnerabilities?: number;
}

export const mockVulnerabilities: Vulnerability[] = [
  {
    id: "1",
    cve_id: "CVE-2023-12345",
    severity: "Critical",
    cvss: 9.8,
    description: "Remote Code Execution in Apache Struts",
    component: "struts-core",
    target: "example.com",
    discovered_at: "2025-10-04",
  },
  {
    id: "2",
    cve_id: "CVE-2022-78901",
    severity: "High",
    cvss: 8.5,
    description: "SQL Injection in login form",
    component: "auth-module",
    target: "example.com",
    discovered_at: "2025-10-03",
  },
  {
    id: "3",
    cve_id: "CVE-2023-45678",
    severity: "Medium",
    cvss: 6.5,
    description: "Cross-Site Scripting (XSS) vulnerability",
    component: "web-ui",
    target: "10.0.0.1",
    discovered_at: "2025-10-02",
  },
  {
    id: "4",
    cve_id: "CVE-2023-11111",
    severity: "High",
    cvss: 7.8,
    description: "Privilege Escalation vulnerability",
    component: "kernel",
    target: "10.0.0.1",
    discovered_at: "2025-10-01",
  },
  {
    id: "5",
    cve_id: "CVE-2023-22222",
    severity: "Low",
    cvss: 3.2,
    description: "Information disclosure",
    component: "api-service",
    target: "api.example.com",
    discovered_at: "2025-09-30",
  },
];

export const mockTargets: Target[] = [
  { id: 1, target: "example.com", tool: "Nmap", status: "Completed", started_at: "2025-10-04", vulnerabilities: 2 },
  { id: 2, target: "10.0.0.1", tool: "Nuclei", status: "Running", started_at: "2025-10-04", vulnerabilities: 0 },
  { id: 3, target: "api.example.com", tool: "Nessus", status: "Completed", started_at: "2025-10-03", vulnerabilities: 1 },
  { id: 4, target: "staging.example.com", tool: "Nikto", status: "Pending", started_at: "2025-10-02", vulnerabilities: 0 },
  { id: 5, target: "192.168.1.100", tool: "OWASP ZAP", status: "Failed", started_at: "2025-10-01", vulnerabilities: 0 },
];

export const mockChartData = [
  { name: "Critical", value: 3, color: "hsl(var(--critical))" },
  { name: "High", value: 8, color: "hsl(var(--high))" },
  { name: "Medium", value: 15, color: "hsl(var(--medium))" },
  { name: "Low", value: 24, color: "hsl(var(--low))" },
];

export const mockAttackPath = {
  nodes: [
    { id: "1", label: "Web Server", type: "entry" },
    { id: "2", label: "Application Layer", type: "intermediate" },
    { id: "3", label: "Database Server", type: "intermediate" },
    { id: "4", label: "Sensitive Data", type: "target" },
  ],
  edges: [
    { from: "1", to: "2", vulnerability: "CVE-2023-12345" },
    { from: "2", to: "3", vulnerability: "CVE-2022-78901" },
    { from: "3", to: "4", vulnerability: "CVE-2023-11111" },
  ],
};
