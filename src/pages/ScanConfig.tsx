import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import DashboardLayout from "@/components/layout/DashboardLayout";
import AIChat from "@/components/AIChat";
import {
  Network,
  Shield,
  Globe,
  Zap,
  Search,
  AlertTriangle,
  Clock,
  Target,
  CheckCircle2,
  Play,
  Check,
  Loader2,
  CheckCircle,
  Activity,
  Brain,
  FileText,
  TrendingUp,
  X,
  Download,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Eye,
  Copy,
  Info
} from "lucide-react";

interface ScanTool {
  id: string;
  name: string;
  description: string;
  icon: any;
  category: string;
  estimatedTime: string;
  severity: "low" | "medium" | "high";
}

interface ScanProgress {
  toolId: string;
  status: 'pending' | 'running' | 'completed';
  progress: number;
  currentStep: string;
}

interface DetailedScanTool extends ScanTool {
  features: string[];
  detectionCapabilities: string[];
  outputFormats: string[];
  recommendedFor: string[];
}

const scanTools: DetailedScanTool[] = [
  {
    id: "nmap",
    name: "Nmap",
    description: "Advanced network discovery and security auditing tool for comprehensive port scanning and service detection",
    icon: Network,
    category: "Network Scanner",
    estimatedTime: "5-10 min",
    severity: "low",
    features: ["Port Scanning", "Service Detection", "OS Fingerprinting", "Script Engine", "Stealth Scanning"],
    detectionCapabilities: ["Open/Closed Ports", "Service Versions", "Operating System", "Network Topology", "Firewall Detection"],
    outputFormats: ["XML", "JSON", "Grepable", "Normal"],
    recommendedFor: ["Network Discovery", "Asset Inventory", "Security Auditing", "Penetration Testing"]
  },
  {
    id: "openvas",
    name: "OpenVAS",
    description: "Enterprise-grade vulnerability assessment and management solution with comprehensive CVE database coverage",
    icon: Shield,
    category: "Vulnerability Scanner",
    estimatedTime: "15-25 min",
    severity: "medium",
    features: ["CVE Database", "Compliance Checks", "Risk Assessment", "Patch Management", "Custom Policies"],
    detectionCapabilities: ["Known Vulnerabilities", "Misconfigurations", "Compliance Issues", "Patch Status", "Risk Scoring"],
    outputFormats: ["PDF", "XML", "CSV", "HTML"],
    recommendedFor: ["Compliance Auditing", "Vulnerability Management", "Risk Assessment", "Enterprise Security"]
  },
  {
    id: "nessus",
    name: "Nessus",
    description: "Industry-leading vulnerability scanner with advanced threat detection and comprehensive security analysis",
    icon: Search,
    category: "Vulnerability Scanner",
    estimatedTime: "20-30 min",
    severity: "medium",
    features: ["Advanced Scanning", "Malware Detection", "Web App Testing", "Database Auditing", "Cloud Security"],
    detectionCapabilities: ["Zero-day Vulnerabilities", "Malware", "Configuration Issues", "Weak Passwords", "Missing Patches"],
    outputFormats: ["PDF", "HTML", "CSV", "XML", "NESSUS"],
    recommendedFor: ["Enterprise Security", "Compliance", "Threat Hunting", "Security Operations"]
  },
  {
    id: "nikto",
    name: "Nikto",
    description: "Specialized web server scanner for identifying dangerous files, outdated software, and server misconfigurations",
    icon: Globe,
    category: "Web Scanner",
    estimatedTime: "10-15 min",
    severity: "low",
    features: ["CGI Scanning", "Server Identification", "Plugin System", "SSL Testing", "Cookie Analysis"],
    detectionCapabilities: ["Dangerous Files", "Outdated Software", "Server Misconfigurations", "Default Files", "Security Headers"],
    outputFormats: ["Text", "HTML", "XML", "CSV"],
    recommendedFor: ["Web Security", "Server Hardening", "Quick Assessment", "Baseline Security"]
  },
  {
    id: "nuclei",
    name: "Nuclei",
    description: "Modern vulnerability scanner with community-driven templates for fast and accurate security testing",
    icon: Zap,
    category: "Fast Scanner",
    estimatedTime: "3-8 min",
    severity: "low",
    features: ["Template Engine", "Community Templates", "Custom Workflows", "Rate Limiting", "Multi-threading"],
    detectionCapabilities: ["CVE Detection", "Misconfigurations", "Exposed Services", "Technology Stack", "Security Issues"],
    outputFormats: ["JSON", "YAML", "Markdown", "SARIF"],
    recommendedFor: ["CI/CD Integration", "Bug Bounty", "Quick Scans", "Automation"]
  },
  {
    id: "owasp-zap",
    name: "OWASP ZAP",
    description: "Comprehensive web application security scanner with advanced crawling and active/passive testing capabilities",
    icon: AlertTriangle,
    category: "Web App Scanner",
    estimatedTime: "15-20 min",
    severity: "high",
    features: ["Active/Passive Scanning", "Spider/Crawler", "Fuzzing", "Authentication", "API Testing"],
    detectionCapabilities: ["OWASP Top 10", "Injection Flaws", "XSS", "Authentication Issues", "Session Management"],
    outputFormats: ["HTML", "XML", "JSON", "PDF"],
    recommendedFor: ["Web App Security", "OWASP Compliance", "API Security", "DevSecOps"]
  }
];

const ScanConfig = () => {
  // Initialize with some tools selected
  const [selectedTools, setSelectedTools] = useState<string[]>(["nmap", "nessus", "nuclei"]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgress[]>([]);
  const [currentScanningTool, setCurrentScanningTool] = useState<string | null>(null);
  const [showResults, setShowResults] = useState(false);
  const [scanResults, setScanResults] = useState<any>(null);
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set());
  const [selectedVuln, setSelectedVuln] = useState<any>(null);
  const [showVulnDetail, setShowVulnDetail] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const [showAIChat, setShowAIChat] = useState(false);
  const [targetUrl, setTargetUrl] = useState("");
  const [useAutoUrl, setUseAutoUrl] = useState(false);
  const [targetType, setTargetType] = useState<"domain" | "ip">("domain");
  const [scanDepth, setScanDepth] = useState<"quick" | "standard" | "deep">("standard");
  const [activeScanMode, setActiveScanMode] = useState(false);
  const [portRange, setPortRange] = useState("1-1000");
  const [urlError, setUrlError] = useState("");

  const validateUrl = (url: string) => {
    if (!url) return false;
    
    // IP address pattern
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    // Domain pattern
    const domainPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    
    if (ipPattern.test(url)) {
      return true;
    }
    
    if (domainPattern.test(url)) {
      return true;
    }
    
    return false;
  };

  const handleToolToggle = (toolId: string) => {
    setSelectedTools(prev =>
      prev.includes(toolId)
        ? prev.filter(id => id !== toolId)
        : [...prev, toolId]
    );
  };

  const handleSelectAll = () => {
    if (selectedTools.length === scanTools.length) {
      setSelectedTools([]);
    } else {
      setSelectedTools(scanTools.map(tool => tool.id));
    }
  };

  const getScanSteps = (toolId: string) => {
    const steps = {
      nmap: [
        "Initializing network scanner...",
        "Discovering live hosts...",
        "Port scanning in progress...",
        "Service detection running...",
        "OS fingerprinting...",
        "Scan completed successfully"
      ],
      openvas: [
        "Starting OpenVAS scanner...",
        "Loading vulnerability database...",
        "Performing network discovery...",
        "Running vulnerability tests...",
        "Analyzing security issues...",
        "Generating vulnerability report..."
      ],
      nessus: [
        "Initializing Nessus engine...",
        "Loading plugin database...",
        "Scanning for vulnerabilities...",
        "Analyzing security weaknesses...",
        "Cross-referencing CVE database...",
        "Finalizing security assessment..."
      ],
      nikto: [
        "Starting web server scanner...",
        "Checking server configuration...",
        "Testing for common vulnerabilities...",
        "Analyzing web application security...",
        "Checking for outdated components...",
        "Web scan completed"
      ],
      nuclei: [
        "Loading Nuclei templates...",
        "Initializing fast scanner...",
        "Running security templates...",
        "Checking for known vulnerabilities...",
        "Validating security issues...",
        "Nuclei scan finished"
      ],
      "owasp-zap": [
        "Starting OWASP ZAP...",
        "Configuring proxy settings...",
        "Passive vulnerability scanning...",
        "Active security testing...",
        "Analyzing web application...",
        "ZAP security scan complete"
      ]
    };
    return steps[toolId as keyof typeof steps] || ["Scanning...", "Completed"];
  };

  const startScan = () => {
    // Validate target URL
    if (!targetUrl && !useAutoUrl) {
      setUrlError("Please enter a target URL or enable Auto URL");
      return;
    }

    if (!useAutoUrl && !validateUrl(targetUrl)) {
      setUrlError("Please enter a valid URL or IP address");
      return;
    }

    if (selectedTools.length === 0) {
      return;
    }

    setUrlError("");
    setIsScanning(true);
    const initialProgress = selectedTools.map(toolId => ({
      toolId,
      status: 'pending' as const,
      progress: 0,
      currentStep: 'Waiting to start...'
    }));
    setScanProgress(initialProgress);

    // Start scanning tools sequentially
    runScanSequence(selectedTools, 0);
  };

  const generateScanResults = (completedTools: string[]) => {
    const results = {
      target: targetUrl || "https://tryhackme.com",
      scanDate: new Date().toISOString(),
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      toolResults: {} as any
    };

    const staticResults = {
      nmap: {
        scanStats: {
          hostsUp: 1,
          hostsTotal: 1,
          portsScanned: 65535,
          openPorts: 12,
          closedPorts: 65523,
          filteredPorts: 0,
          scanDuration: "8m 23s"
        },
        openPorts: [
          { port: 22, service: "SSH", version: "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5", state: "open", protocol: "tcp", banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" },
          { port: 53, service: "DNS", version: "dnsmasq 2.80", state: "open", protocol: "tcp", banner: "DNS response" },
          { port: 80, service: "HTTP", version: "nginx 1.18.0 (Ubuntu)", state: "open", protocol: "tcp", banner: "HTTP/1.1 200 OK Server: nginx/1.18.0" },
          { port: 443, service: "HTTPS", version: "nginx 1.18.0 (Ubuntu)", state: "open", protocol: "tcp", banner: "HTTP/1.1 200 OK Server: nginx/1.18.0" },
          { port: 3000, service: "HTTP", version: "Node.js Express framework", state: "open", protocol: "tcp", banner: "HTTP/1.1 200 OK X-Powered-By: Express" },
          { port: 3306, service: "MySQL", version: "MySQL 8.0.28-0ubuntu0.20.04.3", state: "open", protocol: "tcp", banner: "MySQL 8.0.28" },
          { port: 5432, service: "PostgreSQL", version: "PostgreSQL DB 12.9", state: "open", protocol: "tcp", banner: "PostgreSQL 12.9" },
          { port: 6379, service: "Redis", version: "Redis 6.0.16", state: "open", protocol: "tcp", banner: "Redis 6.0.16" },
          { port: 8080, service: "HTTP", version: "Jetty 9.4.44.v20210927", state: "open", protocol: "tcp", banner: "HTTP/1.1 200 OK Server: Jetty" },
          { port: 8443, service: "HTTPS", version: "Apache Tomcat 9.0.56", state: "open", protocol: "tcp", banner: "HTTP/1.1 200 OK Server: Apache-Coyote/1.1" },
          { port: 9200, service: "HTTP", version: "Elasticsearch 7.15.2", state: "open", protocol: "tcp", banner: "HTTP/1.1 200 OK X-elastic-product: Elasticsearch" },
          { port: 27017, service: "MongoDB", version: "MongoDB 5.0.5", state: "open", protocol: "tcp", banner: "MongoDB 5.0.5" }
        ],
        osDetection: {
          os: "Linux 5.4.0-91-generic",
          distribution: "Ubuntu 20.04.3 LTS (Focal Fossa)",
          kernel: "5.4.0-91-generic",
          architecture: "x86_64",
          confidence: 95
        },
        hostScripts: [
          { script: "smb-os-discovery", output: "OS: Linux; Samba: 4.11.6-Ubuntu" },
          { script: "ssh-hostkey", output: "2048 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 (RSA)" }
        ]
      },
      nessus: {
        scanInfo: {
          pluginsUsed: 156789,
          hostsScanned: 1,
          vulnerabilitiesFound: 47,
          scanDuration: "22m 15s",
          credentialedChecks: true
        },
        vulnerabilities: [
          {
            id: "CVE-2023-4911",
            severity: "critical",
            description: "Buffer overflow in GNU C Library's dynamic loader",
            cvss: 9.8,
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            solution: "Update glibc to version 2.38-1 or later",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-4911", "https://www.cve.org/CVERecord?id=CVE-2023-4911"],
            exploitAvailable: true,
            patchAvailable: true
          },
          {
            id: "CVE-2023-1234",
            severity: "high",
            description: "Remote code execution vulnerability in nginx HTTP/2 module",
            cvss: 8.1,
            vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            solution: "Upgrade nginx to version 1.20.2 or later",
            references: ["https://nginx.org/en/security_advisories.html"],
            exploitAvailable: false,
            patchAvailable: true
          },
          {
            id: "CVE-2023-5678",
            severity: "high",
            description: "SQL injection vulnerability in authentication module",
            cvss: 7.5,
            vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            solution: "Apply security patch or upgrade to latest version",
            references: ["https://example.com/security-advisory"],
            exploitAvailable: true,
            patchAvailable: true
          },
          {
            id: "CVE-2022-9999",
            severity: "medium",
            description: "Weak SSL/TLS cipher suites enabled",
            cvss: 5.3,
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            solution: "Disable weak cipher suites and enable only strong encryption",
            references: ["https://ssl-config.mozilla.org/"],
            exploitAvailable: false,
            patchAvailable: false
          }
        ],
        compliance: {
          passed: 142,
          failed: 23,
          total: 165,
          frameworks: ["PCI DSS", "NIST", "CIS", "GDPR"]
        },
        riskDistribution: {
          critical: 1,
          high: 3,
          medium: 12,
          low: 31,
          info: 89
        }
      },
      nuclei: {
        scanInfo: {
          templates: 4847,
          matched: 23,
          requests: 15678,
          duration: "4m 32s"
        },
        matched: [
          {
            template: "CVE-2023-1234",
            severity: "high",
            description: "nginx HTTP/2 vulnerability detected",
            matcher: "status_code",
            url: "https://tryhackme.com/",
            tags: ["cve", "nginx", "http2"]
          },
          {
            template: "tech-detect",
            severity: "info",
            description: "Technology stack: nginx, Node.js, MySQL, Redis",
            matcher: "header",
            url: "https://tryhackme.com/",
            tags: ["tech", "fingerprint"]
          },
          {
            template: "ssl-weak-cipher",
            severity: "medium",
            description: "Weak SSL cipher suites detected: TLS_RSA_WITH_AES_128_CBC_SHA",
            matcher: "ssl",
            url: "https://tryhackme.com:443",
            tags: ["ssl", "weak-cipher"]
          },
          {
            template: "cors-misconfig",
            severity: "low",
            description: "CORS misconfiguration allows wildcard origin",
            matcher: "header",
            url: "https://tryhackme.com/api/",
            tags: ["cors", "misconfig"]
          },
          {
            template: "exposed-git",
            severity: "medium",
            description: "Git repository exposed at /.git/",
            matcher: "status_code",
            url: "https://tryhackme.com/.git/",
            tags: ["exposure", "git"]
          }
        ],
        categories: {
          "cve": 5,
          "misconfig": 8,
          "exposure": 4,
          "tech": 3,
          "ssl": 3
        }
      },
      nikto: {
        scanInfo: {
          itemsChecked: 6728,
          itemsFound: 18,
          duration: "12m 8s",
          targetIP: "104.26.10.78"
        },
        findings: [
          {
            id: "OSVDB-3092",
            severity: "medium",
            description: "/admin/: Admin login page found. May allow brute force attacks.",
            url: "/admin/",
            method: "GET",
            references: ["OSVDB-3092"]
          },
          {
            id: "OSVDB-3233",
            severity: "low",
            description: "/icons/: Directory indexing is enabled, exposing server structure",
            url: "/icons/",
            method: "GET",
            references: ["OSVDB-3233"]
          },
          {
            id: "OSVDB-630",
            severity: "low",
            description: "Server may reveal its internal IP address in error messages",
            url: "/nonexistent",
            method: "GET",
            references: ["OSVDB-630"]
          },
          {
            id: "OSVDB-3268",
            severity: "medium",
            description: "/config/: Configuration directory found",
            url: "/config/",
            method: "GET",
            references: ["OSVDB-3268"]
          },
          {
            id: "OSVDB-3093",
            severity: "high",
            description: "/cgi-bin/: CGI directory found. May contain vulnerable scripts.",
            url: "/cgi-bin/",
            method: "GET",
            references: ["OSVDB-3093"]
          }
        ],
        serverInfo: {
          server: "nginx/1.18.0",
          poweredBy: "Express",
          cookies: 3,
          headers: 12
        }
      },
      openvas: {
        scanInfo: {
          nvtsUsed: 78456,
          hostsScanned: 1,
          duration: "18m 45s",
          credentialedScan: true
        },
        vulnerabilities: [
          {
            oid: "1.3.6.1.4.1.25623.1.0.100315",
            severity: "high",
            description: "Buffer overflow vulnerability in HTTP server component",
            cvss: 7.8,
            solution: "Update to the latest version or apply security patches",
            affected: "nginx 1.18.0",
            family: "Buffer overflow"
          },
          {
            oid: "1.3.6.1.4.1.25623.1.0.108542",
            severity: "medium",
            description: "Missing security headers (HSTS, CSP, X-Frame-Options)",
            cvss: 4.3,
            solution: "Configure proper security headers in web server",
            affected: "Web Server",
            family: "Web application abuses"
          },
          {
            oid: "1.3.6.1.4.1.25623.1.0.117665",
            severity: "medium",
            description: "SSH weak encryption algorithms enabled",
            cvss: 5.3,
            solution: "Disable weak encryption algorithms in SSH configuration",
            affected: "OpenSSH 8.2p1",
            family: "General"
          }
        ],
        summary: {
          critical: 0,
          high: 4,
          medium: 8,
          low: 15,
          info: 23
        },
        compliance: {
          pciDss: { passed: 45, failed: 8, score: 85 },
          nist: { passed: 67, failed: 12, score: 85 },
          iso27001: { passed: 89, failed: 15, score: 86 }
        }
      },
      "owasp-zap": {
        scanInfo: {
          urlsFound: 247,
          formsFound: 15,
          duration: "16m 22s",
          alertsRaised: 34
        },
        alerts: [
          {
            risk: "High",
            confidence: "High",
            name: "SQL Injection",
            description: "SQL injection vulnerability found in login form parameter 'username'",
            url: "https://tryhackme.com/login",
            parameter: "username",
            attack: "' OR '1'='1",
            evidence: "MySQL error message detected",
            solution: "Use parameterized queries and input validation",
            reference: "https://owasp.org/www-community/attacks/SQL_Injection"
          },
          {
            risk: "High",
            confidence: "Medium",
            name: "Cross Site Scripting (Reflected)",
            description: "Reflected XSS vulnerability in search functionality",
            url: "https://tryhackme.com/search",
            parameter: "q",
            attack: "<script>alert('XSS')</script>",
            evidence: "Script tag reflected in response",
            solution: "Encode output and validate input",
            reference: "https://owasp.org/www-community/attacks/xss/"
          },
          {
            risk: "Medium",
            confidence: "High",
            name: "Missing Anti-CSRF Tokens",
            description: "Forms do not contain anti-CSRF tokens",
            url: "https://tryhackme.com/profile",
            parameter: "N/A",
            attack: "CSRF attack possible",
            evidence: "No CSRF token found in form",
            solution: "Implement anti-CSRF tokens",
            reference: "https://owasp.org/www-community/attacks/csrf"
          },
          {
            risk: "Low",
            confidence: "Medium",
            name: "Cookie Security",
            description: "Secure flag not set on sensitive cookies",
            url: "https://tryhackme.com/",
            parameter: "session_id",
            attack: "Cookie interception possible",
            evidence: "Secure flag missing",
            solution: "Set Secure and HttpOnly flags on cookies",
            reference: "https://owasp.org/www-community/controls/SecureCookieAttribute"
          }
        ],
        spider: {
          urlsFound: 247,
          formsFound: 15,
          coverage: "85%",
          depth: 5
        },
        owaspTop10: {
          "A01:2021 – Broken Access Control": 2,
          "A02:2021 – Cryptographic Failures": 1,
          "A03:2021 – Injection": 3,
          "A04:2021 – Insecure Design": 0,
          "A05:2021 – Security Misconfiguration": 4,
          "A06:2021 – Vulnerable Components": 2,
          "A07:2021 – Identity/Authentication Failures": 1,
          "A08:2021 – Software/Data Integrity Failures": 0,
          "A09:2021 – Security Logging/Monitoring Failures": 1,
          "A10:2021 – Server-Side Request Forgery": 0
        }
      }
    };

    completedTools.forEach(toolId => {
      if (staticResults[toolId as keyof typeof staticResults]) {
        results.toolResults[toolId] = staticResults[toolId as keyof typeof staticResults];
      }
    });

    // Calculate totals
    results.criticalCount = 0;
    results.highCount = (completedTools.includes('nessus') ? 1 : 0) + (completedTools.includes('openvas') ? 1 : 0) + (completedTools.includes('owasp-zap') ? 1 : 0);
    results.mediumCount = completedTools.length * 2;
    results.lowCount = completedTools.length * 1;
    results.totalVulnerabilities = results.criticalCount + results.highCount + results.mediumCount + results.lowCount;

    return results;
  };

  const performAiAnalysis = async () => {
    setIsAnalyzing(true);

    // Simulate AI analysis
    await new Promise(resolve => setTimeout(resolve, 2000));

    const analysis = `
# 🔍 Comprehensive AI Security Analysis for ${targetUrl || "target"}

## Executive Summary
Our advanced AI analysis has identified **${scanResults?.totalVulnerabilities || 0} security vulnerabilities** across ${selectedTools.length} scanning tools. The assessment reveals a **MODERATE-HIGH** risk profile with several critical vulnerabilities requiring immediate attention.

**🎯 Overall Security Score: 6.2/10**
**🚨 Risk Level: MODERATE-HIGH**
**⚡ Immediate Action Required: YES**

---

## 🚨 CRITICAL FINDINGS (Immediate Action Required)

### 1. Buffer Overflow in GNU C Library (CVE-2023-4911)
**🔥 CRITICAL SEVERITY - CVSS 9.8**
- **Attack Vector:** Network-based, no authentication required
- **Impact:** Complete system compromise, remote code execution
- **Exploitability:** Public exploits available (Looney Tunables)
- **Affected Component:** glibc dynamic loader (ld.so)
- **Business Impact:** Complete server takeover, data breach, service disruption
- **Remediation:** URGENT - Update glibc to 2.38-1+ within 24 hours
- **Temporary Mitigation:** Disable SUID programs if possible

### 2. SQL Injection in Authentication System
**🔥 HIGH SEVERITY - CVSS 7.5**
- **Location:** /login endpoint, 'username' parameter
- **Attack Vector:** Authenticated SQL injection via login form
- **Impact:** Database compromise, credential theft, privilege escalation
- **Evidence:** MySQL error messages exposed, successful injection confirmed
- **Business Impact:** Customer data breach, regulatory violations (GDPR/PCI)
- **Remediation:** Implement parameterized queries within 48 hours
- **Temporary Mitigation:** Enable WAF rules for SQL injection patterns

### 3. Reflected XSS in Search Functionality
**🔥 HIGH SEVERITY - CVSS 6.1**
- **Location:** /search endpoint, 'q' parameter
- **Attack Vector:** Reflected cross-site scripting
- **Impact:** Session hijacking, credential theft, malware distribution
- **Evidence:** Script execution confirmed in response
- **Business Impact:** User account compromise, reputation damage
- **Remediation:** Implement output encoding and CSP headers
- **Temporary Mitigation:** Input validation and sanitization

---

## �️ DeETAILED VULNERABILITY BREAKDOWN

### Network Infrastructure (Nmap Analysis)
**Exposed Services Risk Assessment:**
- **12 open ports detected** - Above recommended baseline (5-7 ports)
- **High-risk services:** MySQL (3306), PostgreSQL (5432), MongoDB (27017)
- **Database exposure:** Multiple database services accessible externally
- **Recommendation:** Implement network segmentation and firewall rules

**Service Version Analysis:**
- **OpenSSH 8.2p1:** Vulnerable to timing attacks (CVE-2021-28041)
- **nginx 1.18.0:** Multiple known vulnerabilities, update to 1.20.2+
- **MySQL 8.0.28:** Requires security patches for privilege escalation issues

### Web Application Security (OWASP ZAP Analysis)
**OWASP Top 10 Compliance:**
- ❌ **A03 - Injection:** 3 vulnerabilities found (SQL, NoSQL, Command)
- ❌ **A05 - Security Misconfiguration:** 4 issues (headers, CORS, cookies)
- ❌ **A01 - Broken Access Control:** 2 vulnerabilities (admin panel, API)
- ⚠️ **A07 - Authentication Failures:** 1 issue (weak session management)

**Security Headers Analysis:**
- Missing: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- Impact: Clickjacking, MIME sniffing, protocol downgrade attacks
- Priority: HIGH - Implement within 1 week

### Vulnerability Management (Nessus/OpenVAS Analysis)
**Patch Management Status:**
- **23 missing security patches** identified
- **Critical patches:** 1 (glibc buffer overflow)
- **High priority patches:** 4 (nginx, SSH, database components)
- **Compliance impact:** PCI DSS (85%), NIST (85%), ISO 27001 (86%)

---

## 📊 RISK MATRIX & BUSINESS IMPACT

### Financial Impact Assessment
- **Data Breach Cost:** $4.35M average (IBM 2023 report)
- **Downtime Cost:** $5,600/minute for e-learning platforms
- **Regulatory Fines:** Up to 4% annual revenue (GDPR)
- **Reputation Damage:** 25% customer churn post-breach average

### Attack Probability Analysis
- **SQL Injection:** 85% - Common attack vector, tools readily available
- **XSS Exploitation:** 70% - Moderate skill required, high impact
- **Buffer Overflow:** 60% - Requires advanced skills but critical impact
- **Network Intrusion:** 45% - Multiple entry points available

---

## 🎯 STRATEGIC REMEDIATION ROADMAP

### Phase 1: Emergency Response (0-72 hours)
**Priority 1 - Critical Vulnerabilities:**
1. **Patch glibc immediately** - Deploy emergency update
2. **Fix SQL injection** - Implement parameterized queries
3. **Deploy WAF rules** - Block common attack patterns
4. **Enable security monitoring** - Deploy SIEM alerts

**Estimated Cost:** $15,000 - $25,000
**Resource Requirements:** 2 senior developers, 1 security engineer

### Phase 2: Security Hardening (1-4 weeks)
**Priority 2 - High/Medium Vulnerabilities:**
1. **Update all software components** - nginx, databases, OS packages
2. **Implement security headers** - HSTS, CSP, security headers suite
3. **Network segmentation** - Isolate database servers
4. **Access control review** - Remove unnecessary admin interfaces

**Estimated Cost:** $35,000 - $50,000
**Resource Requirements:** DevOps team, security consultant

### Phase 3: Security Program Enhancement (1-3 months)
**Priority 3 - Long-term Security:**
1. **Automated vulnerability scanning** - CI/CD integration
2. **Security training program** - Developer security awareness
3. **Incident response plan** - Breach response procedures
4. **Regular penetration testing** - Quarterly assessments

**Estimated Cost:** $75,000 - $100,000 annually
**Resource Requirements:** Security team expansion

---

## 🔧 TECHNICAL IMPLEMENTATION GUIDE

### Immediate SQL Injection Fix (Code Example)
\`\`\`python
# VULNERABLE CODE (Current)
query = f"SELECT * FROM users WHERE username = '{username}'"

# SECURE CODE (Recommended)
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))
\`\`\`

### Security Headers Implementation
\`\`\`nginx
# Add to nginx configuration
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'";
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
\`\`\`

### Database Security Hardening
\`\`\`bash
# MySQL security configuration
mysql_secure_installation
# Disable remote root access
# Remove test databases
# Set strong passwords
\`\`\`

---

## 📈 CONTINUOUS MONITORING RECOMMENDATIONS

### Security Metrics to Track
1. **Vulnerability Density:** Target <5 high/critical per 1000 LOC
2. **Mean Time to Patch:** Target <48 hours for critical vulnerabilities
3. **Security Test Coverage:** Target >80% of application functionality
4. **Incident Response Time:** Target <2 hours for critical incidents

### Recommended Security Tools
- **SAST:** SonarQube, Checkmarx for code analysis
- **DAST:** OWASP ZAP, Burp Suite for runtime testing
- **Dependency Scanning:** Snyk, WhiteSource for third-party vulnerabilities
- **Infrastructure:** Nessus, OpenVAS for system vulnerabilities

---

## 🎯 COMPLIANCE & REGULATORY CONSIDERATIONS

### Current Compliance Status
- **PCI DSS:** 85% compliant (15 failed controls)
- **GDPR:** 78% compliant (data protection gaps)
- **SOC 2:** 82% compliant (access control issues)
- **ISO 27001:** 86% compliant (incident response gaps)

### Required Actions for Compliance
1. **Data encryption at rest and in transit**
2. **Access logging and monitoring**
3. **Regular security assessments**
4. **Incident response procedures**
5. **Employee security training**

---

## 💡 EXECUTIVE RECOMMENDATIONS

### Board-Level Actions Required
1. **Allocate emergency security budget** ($150K-200K)
2. **Approve security team expansion** (2-3 FTE)
3. **Establish security governance committee**
4. **Mandate quarterly security reviews**

### Success Metrics (90-day targets)
- Reduce critical vulnerabilities to 0
- Achieve 95%+ compliance scores
- Implement automated security testing
- Complete security training for all developers

**Next Review Date:** 30 days from remediation start
**Emergency Contact:** security-team@company.com
**Escalation Path:** CTO → CISO → CEO → Board

---

*This analysis was generated using advanced AI security intelligence combining threat intelligence, vulnerability databases, and industry best practices. For questions or clarification, contact the security team.*
    `;

    setAiAnalysis(analysis);
    setIsAnalyzing(false);
    setShowResults(false); // Close the scan results dialog
    setShowAIChat(true); // Open AI chat
  };

  const runScanSequence = async (tools: string[], index: number) => {
    if (index >= tools.length) {
      // All scans completed - generate results
      const results = generateScanResults(tools);
      setScanResults(results);

      setTimeout(() => {
        setIsScanning(false);
        setScanProgress([]);
        setCurrentScanningTool(null);
        setShowResults(true);
      }, 2000);
      return;
    }

    const currentTool = tools[index];
    setCurrentScanningTool(currentTool);
    const steps = getScanSteps(currentTool);

    // Update status to running
    setScanProgress(prev => prev.map(p =>
      p.toolId === currentTool
        ? { ...p, status: 'running', currentStep: steps[0] }
        : p
    ));

    // Simulate scan progress
    for (let step = 0; step < steps.length; step++) {
      await new Promise(resolve => setTimeout(resolve, 1500)); // 1.5s per step

      const progress = ((step + 1) / steps.length) * 100;
      const isCompleted = step === steps.length - 1;

      setScanProgress(prev => prev.map(p =>
        p.toolId === currentTool
          ? {
            ...p,
            progress,
            currentStep: steps[step],
            status: isCompleted ? 'completed' : 'running'
          }
          : p
      ));
    }

    // Move to next tool
    setTimeout(() => runScanSequence(tools, index + 1), 500);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "low": return "bg-green-500/10 text-green-500 border-green-500/20";
      case "medium": return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
      case "high": return "bg-red-500/10 text-red-500 border-red-500/20";
      case "critical": return "bg-red-600/10 text-red-600 border-red-600/20";
      default: return "bg-gray-500/10 text-gray-500 border-gray-500/20";
    }
  };

  const toggleVulnExpand = (id: string) => {
    setExpandedVulns(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const viewVulnDetail = (vuln: any, toolName: string) => {
    setSelectedVuln({ ...vuln, toolName });
    setShowVulnDetail(true);
  };

  const exportReport = (format: 'pdf' | 'json' | 'csv') => {
    // Simulate export
    const data = JSON.stringify(scanResults, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerability-report-${new Date().toISOString().split('T')[0]}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const selectedCount = selectedTools.length;
  const totalTime = scanTools
    .filter(tool => selectedTools.includes(tool.id))
    .reduce((total, tool) => {
      const avg = tool.estimatedTime.split("-").map(t => parseInt(t));
      return total + (avg[0] + avg[1]) / 2;
    }, 0);

  return (
    <DashboardLayout>
      <div className="max-w-6xl mx-auto animate-fade-in space-y-6">
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
            <Target className="h-10 w-10 text-primary" />
            Configure New Scan
          </h1>
          <p className="text-muted-foreground">Set up a comprehensive vulnerability scan for your target</p>
        </div>

        <div className="space-y-6">
          {/* Target Configuration */}
          <Card className="border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5" />
                Target Configuration
              </CardTitle>
              <CardDescription>Specify the domain or IP address to scan</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Target URL Input */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label htmlFor="target" className="text-base font-semibold">Target (Domain/IP) *</Label>
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="autoUrl"
                      checked={useAutoUrl}
                      onChange={(e) => {
                        setUseAutoUrl(e.target.checked);
                        if (e.target.checked) {
                          setTargetUrl("https://tryhackme.com");
                          setUrlError("");
                        } else {
                          setTargetUrl("");
                        }
                      }}
                      className="h-4 w-4 rounded border-border text-primary focus:ring-primary cursor-pointer"
                    />
                    <Label htmlFor="autoUrl" className="text-sm font-normal cursor-pointer text-muted-foreground hover:text-foreground transition-colors">
                      Use Demo URL
                    </Label>
                  </div>
                </div>
                
                <div className="relative">
                  <Input
                    id="target"
                    placeholder="https://example.com or 192.168.1.1"
                    value={useAutoUrl ? "https://tryhackme.com" : targetUrl}
                    onChange={(e) => {
                      if (!useAutoUrl) {
                        setTargetUrl(e.target.value);
                        setUrlError("");
                        // Auto-detect type
                        const value = e.target.value;
                        if (/^\d+\.\d+\.\d+\.\d+/.test(value)) {
                          setTargetType("ip");
                        } else {
                          setTargetType("domain");
                        }
                      }
                    }}
                    disabled={useAutoUrl}
                    className={`bg-input border-border text-lg pr-20 ${useAutoUrl ? 'opacity-60 cursor-not-allowed' : ''} ${urlError ? 'border-red-500' : ''}`}
                  />
                  <Badge 
                    variant="outline" 
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-xs"
                  >
                    {targetType === "ip" ? "IP" : "Domain"}
                  </Badge>
                </div>

                {useAutoUrl && (
                  <div className="flex items-center gap-2 p-2 rounded-md bg-blue-500/10 border border-blue-500/20">
                    <Info className="h-4 w-4 text-blue-500" />
                    <p className="text-xs text-blue-600 dark:text-blue-400">
                      Using demo URL for testing purposes
                    </p>
                  </div>
                )}

                {urlError && (
                  <div className="flex items-center gap-2 p-2 rounded-md bg-red-500/10 border border-red-500/20">
                    <AlertTriangle className="h-4 w-4 text-red-500" />
                    <p className="text-xs text-red-600 dark:text-red-400">{urlError}</p>
                  </div>
                )}

                {targetUrl && !urlError && !useAutoUrl && (
                  <div className="flex items-center gap-2 p-2 rounded-md bg-green-500/10 border border-green-500/20">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <p className="text-xs text-green-600 dark:text-green-400">
                      Target validated successfully
                    </p>
                  </div>
                )}
              </div>

              {/* Scan Depth Selection */}
              <div className="space-y-3">
                <Label className="text-base font-semibold">Scan Depth</Label>
                <div className="grid grid-cols-3 gap-3">
                  <button
                    type="button"
                    onClick={() => setScanDepth("quick")}
                    className={`p-4 rounded-lg border-2 transition-all ${
                      scanDepth === "quick"
                        ? "border-primary bg-primary/10"
                        : "border-border hover:border-primary/50"
                    }`}
                  >
                    <Zap className={`h-5 w-5 mx-auto mb-2 ${scanDepth === "quick" ? "text-primary" : "text-muted-foreground"}`} />
                    <p className="font-semibold text-sm">Quick</p>
                    <p className="text-xs text-muted-foreground mt-1">~5-10 min</p>
                  </button>
                  
                  <button
                    type="button"
                    onClick={() => setScanDepth("standard")}
                    className={`p-4 rounded-lg border-2 transition-all ${
                      scanDepth === "standard"
                        ? "border-primary bg-primary/10"
                        : "border-border hover:border-primary/50"
                    }`}
                  >
                    <Target className={`h-5 w-5 mx-auto mb-2 ${scanDepth === "standard" ? "text-primary" : "text-muted-foreground"}`} />
                    <p className="font-semibold text-sm">Standard</p>
                    <p className="text-xs text-muted-foreground mt-1">~15-25 min</p>
                  </button>
                  
                  <button
                    type="button"
                    onClick={() => setScanDepth("deep")}
                    className={`p-4 rounded-lg border-2 transition-all ${
                      scanDepth === "deep"
                        ? "border-primary bg-primary/10"
                        : "border-border hover:border-primary/50"
                    }`}
                  >
                    <Search className={`h-5 w-5 mx-auto mb-2 ${scanDepth === "deep" ? "text-primary" : "text-muted-foreground"}`} />
                    <p className="font-semibold text-sm">Deep</p>
                    <p className="text-xs text-muted-foreground mt-1">~30-45 min</p>
                  </button>
                </div>
              </div>

              {/* Advanced Options */}
              <div className="space-y-3">
                <Label className="text-base font-semibold">Advanced Options</Label>
                
                {/* Active Scan Mode */}
                <div className="flex items-center justify-between p-4 rounded-lg bg-muted/50 border border-border hover:bg-muted/70 transition-colors">
                  <div className="space-y-0.5">
                    <Label className="flex items-center gap-2 cursor-pointer">
                      <AlertTriangle className="h-4 w-4 text-orange-500" />
                      Active Scan Mode
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      Enable intrusive testing (may affect target performance)
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveScanMode(!activeScanMode)}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                      activeScanMode ? "bg-primary" : "bg-muted border-2 border-border"
                    }`}
                  >
                    <span
                      className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-lg transition-transform ${
                        activeScanMode ? "translate-x-6" : "translate-x-1"
                      }`}
                    />
                  </button>
                </div>

                {/* Port Range */}
                <div className="space-y-2">
                  <Label htmlFor="portRange" className="text-sm">Port Range</Label>
                  <div className="flex gap-2">
                    <Input
                      id="portRange"
                      placeholder="1-1000"
                      value={portRange}
                      onChange={(e) => setPortRange(e.target.value)}
                      className="bg-input border-border"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => setPortRange("1-65535")}
                      className="whitespace-nowrap"
                    >
                      All Ports
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Specify port range (e.g., 1-1000, 80,443, or 1-65535 for all)
                  </p>
                </div>
              </div>

              {/* Quick Stats */}
              <div className="grid grid-cols-3 gap-3 pt-2">
                <div className="p-3 rounded-lg bg-primary/5 border border-primary/20">
                  <p className="text-xs text-muted-foreground mb-1">Tools Selected</p>
                  <p className="text-2xl font-bold text-primary">{selectedTools.length}</p>
                </div>
                <div className="p-3 rounded-lg bg-blue-500/5 border border-blue-500/20">
                  <p className="text-xs text-muted-foreground mb-1">Est. Time</p>
                  <p className="text-2xl font-bold text-blue-600">
                    {scanDepth === "quick" ? "10m" : scanDepth === "standard" ? "25m" : "45m"}
                  </p>
                </div>
                <div className="p-3 rounded-lg bg-green-500/5 border border-green-500/20">
                  <p className="text-xs text-muted-foreground mb-1">Scan Depth</p>
                  <p className="text-2xl font-bold text-green-600 capitalize">{scanDepth}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Scanning Tools Selection */}
          <Card className="border-border">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Select Scanning Tools
                  </CardTitle>
                  <CardDescription>Choose which tools to run on your target</CardDescription>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleSelectAll}
                  className="gap-2"
                >
                  <CheckCircle2 className="h-4 w-4" />
                  {selectedTools.length === scanTools.length ? "Deselect All" : "Select All"}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {scanTools.map((tool) => {
                  const Icon = tool.icon;
                  const isSelected = selectedTools.includes(tool.id);

                  return (
                    <div
                      key={tool.id}
                      className={`
                        relative p-4 rounded-lg border-2 cursor-pointer transition-all
                        ${isSelected
                          ? "border-primary bg-primary/5 shadow-md"
                          : "border-border hover:border-primary/50 hover:bg-muted/50"
                        }
                      `}
                      onClick={() => handleToolToggle(tool.id)}
                    >
                      <div className="flex items-start gap-3">
                        <div className={`
                          h-4 w-4 mt-1 rounded border-2 flex items-center justify-center cursor-pointer
                          ${isSelected
                            ? "bg-primary border-primary text-primary-foreground"
                            : "border-input bg-background hover:border-primary/50"
                          }
                        `}>
                          {isSelected && <Check className="h-3 w-3" />}
                        </div>
                        <div className="flex-1 space-y-2">
                          <div className="flex items-center gap-2">
                            <Icon className={`h-5 w-5 ${isSelected ? "text-primary" : "text-muted-foreground"}`} />
                            <h3 className="font-semibold">{tool.name}</h3>
                          </div>
                          <p className="text-sm text-muted-foreground">{tool.description}</p>
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge variant="outline" className="text-xs">
                              {tool.category}
                            </Badge>
                            <Badge variant="outline" className={`text-xs ${getSeverityColor(tool.severity)}`}>
                              {tool.severity}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-1 text-xs text-muted-foreground">
                            <Clock className="h-3 w-3" />
                            {tool.estimatedTime}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Scan Summary */}
          <Card className="border-border bg-muted/30">
            <CardHeader>
              <CardTitle className="text-lg">Scan Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-lg bg-background border border-border">
                  <p className="text-sm text-muted-foreground mb-1">Target</p>
                  <p className="font-semibold truncate">{targetUrl || "No target specified"}</p>
                </div>
                <div className="p-4 rounded-lg bg-background border border-border">
                  <p className="text-sm text-muted-foreground mb-1">Selected Tools</p>
                  <p className="font-semibold">{selectedCount} / {scanTools.length}</p>
                </div>
                <div className="p-4 rounded-lg bg-background border border-border">
                  <p className="text-sm text-muted-foreground mb-1">Scan Mode</p>
                  <p className="font-semibold">Passive</p>
                </div>
                <div className="p-4 rounded-lg bg-background border border-border">
                  <p className="text-sm text-muted-foreground mb-1">Est. Duration</p>
                  <p className="font-semibold">{Math.round(totalTime)} min</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Action Buttons */}
          <div className="flex gap-4">
            <Button
              className="flex-1 bg-primary hover:bg-primary/90 h-12 text-lg gap-2"
              onClick={startScan}
              disabled={selectedTools.length === 0 || isScanning}
            >
              <Play className="h-5 w-5" />
              {isScanning ? "Scanning..." : "Start Scan"}
            </Button>
            <Button
              variant="outline"
              className="h-12"
            >
              Cancel
            </Button>
          </div>
        </div>

        {/* Scanning Progress Dialog */}
        <Dialog open={isScanning} onOpenChange={() => { }}>
          <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-primary animate-pulse" />
                Vulnerability Scan in Progress
              </DialogTitle>
            </DialogHeader>

            <div className="space-y-4 mt-4">
              <div className="text-center p-4 bg-muted/50 rounded-lg">
                <p className="text-sm text-muted-foreground mb-2">Scanning Target</p>
                <p className="font-semibold text-lg">{targetUrl || "No target specified"}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  {scanProgress.filter(p => p.status === 'completed').length} of {selectedTools.length} tools completed
                </p>
              </div>

              <div className="space-y-3">
                {scanProgress.map((progress) => {
                  const tool = scanTools.find(t => t.id === progress.toolId);
                  if (!tool) return null;

                  const Icon = tool.icon;
                  const isActive = currentScanningTool === progress.toolId;

                  return (
                    <div
                      key={progress.toolId}
                      className={`p-4 rounded-lg border transition-all ${isActive
                        ? 'border-primary bg-primary/5 shadow-md'
                        : progress.status === 'completed'
                          ? 'border-green-500/50 bg-green-500/5'
                          : 'border-border bg-muted/30'
                        }`}
                    >
                      <div className="flex items-center gap-3 mb-3">
                        <div className="relative">
                          <Icon className={`h-5 w-5 ${progress.status === 'completed'
                            ? 'text-green-500'
                            : isActive
                              ? 'text-primary'
                              : 'text-muted-foreground'
                            }`} />
                          {progress.status === 'completed' && (
                            <CheckCircle className="absolute -top-1 -right-1 h-3 w-3 text-green-500 bg-background rounded-full" />
                          )}
                          {isActive && (
                            <Loader2 className="absolute -top-1 -right-1 h-3 w-3 text-primary animate-spin bg-background rounded-full" />
                          )}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <h3 className="font-semibold">{tool.name}</h3>
                            <Badge variant={
                              progress.status === 'completed' ? 'default' :
                                progress.status === 'running' ? 'secondary' : 'outline'
                            } className="text-xs">
                              {progress.status === 'completed' ? 'Completed' :
                                progress.status === 'running' ? 'Running' : 'Pending'}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">
                            {progress.currentStep}
                          </p>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <div className="flex justify-between text-xs text-muted-foreground">
                          <span>Progress</span>
                          <span>{Math.round(progress.progress)}%</span>
                        </div>
                        <Progress
                          value={progress.progress}
                          className={`h-2 ${progress.status === 'completed' ? '[&>div]:bg-green-500' : ''
                            }`}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>

              {scanProgress.every(p => p.status === 'completed') && (
                <div className="text-center p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
                  <CheckCircle className="h-8 w-8 text-green-500 mx-auto mb-2" />
                  <p className="font-semibold text-green-700">All Scans Completed Successfully!</p>
                  <p className="text-sm text-green-600 mt-1">
                    Vulnerability assessment finished. Check the Reports section for detailed results.
                  </p>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>

        {/* Scan Results Dialog */}
        <Dialog open={showResults} onOpenChange={setShowResults}>
          <DialogContent className="max-w-7xl max-h-[95vh] overflow-y-auto">
            <DialogHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-primary/10 rounded-lg">
                    <FileText className="h-6 w-6 text-primary" />
                  </div>
                  <div>
                    <DialogTitle className="text-xl font-bold">Vulnerability Assessment Report</DialogTitle>
                    <p className="text-sm text-muted-foreground mt-1">
                      Comprehensive security analysis for {targetUrl || "target"}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => exportReport('json')}
                    className="gap-2"
                  >
                    <Download className="h-4 w-4" />
                    Export
                  </Button>
                  <Badge variant="outline" className="text-xs">
                    {new Date().toLocaleDateString()}
                  </Badge>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowResults(false)}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </DialogHeader>

            {scanResults && (
              <div className="space-y-6 mt-4">
                {/* Executive Summary */}
                <div className="bg-gradient-to-r from-primary/5 to-primary/10 p-6 rounded-lg border border-primary/20">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold flex items-center gap-2">
                      <TrendingUp className="h-5 w-5 text-primary" />
                      Executive Summary
                    </h3>
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="text-xs">
                        Security Score: 6.2/10
                      </Badge>
                      <Badge variant="destructive" className="text-xs">
                        MODERATE-HIGH RISK
                      </Badge>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="text-center p-4 bg-background/50 rounded-lg border">
                      <div className="text-2xl font-bold text-red-600 mb-1">{scanResults.criticalCount}</div>
                      <div className="text-xs text-red-700 font-medium">CRITICAL</div>
                      <div className="text-xs text-muted-foreground">Immediate Action</div>
                    </div>
                    <div className="text-center p-4 bg-background/50 rounded-lg border">
                      <div className="text-2xl font-bold text-orange-600 mb-1">{scanResults.highCount}</div>
                      <div className="text-xs text-orange-700 font-medium">HIGH</div>
                      <div className="text-xs text-muted-foreground">48 Hours</div>
                    </div>
                    <div className="text-center p-4 bg-background/50 rounded-lg border">
                      <div className="text-2xl font-bold text-yellow-600 mb-1">{scanResults.mediumCount}</div>
                      <div className="text-xs text-yellow-700 font-medium">MEDIUM</div>
                      <div className="text-xs text-muted-foreground">1-2 Weeks</div>
                    </div>
                    <div className="text-center p-4 bg-background/50 rounded-lg border">
                      <div className="text-2xl font-bold text-blue-600 mb-1">{scanResults.lowCount}</div>
                      <div className="text-xs text-blue-700 font-medium">LOW</div>
                      <div className="text-xs text-muted-foreground">1-3 Months</div>
                    </div>
                  </div>
                </div>

                {/* Scan Overview */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-4 bg-muted/50 rounded-lg border">
                    <h4 className="font-medium mb-3 flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      Scan Details
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Target:</span>
                        <span className="font-medium">{scanResults.target}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Tools Used:</span>
                        <span className="font-medium">{selectedTools.length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Total Issues:</span>
                        <span className="font-medium">{scanResults.totalVulnerabilities}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Scan Date:</span>
                        <span className="font-medium">{new Date().toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 bg-muted/50 rounded-lg border">
                    <h4 className="font-medium mb-3 flex items-center gap-2">
                      <Shield className="h-4 w-4" />
                      Compliance Status
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">PCI DSS:</span>
                        <Badge variant="secondary" className="text-xs">85%</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">NIST:</span>
                        <Badge variant="secondary" className="text-xs">85%</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">ISO 27001:</span>
                        <Badge variant="secondary" className="text-xs">86%</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">GDPR:</span>
                        <Badge variant="outline" className="text-xs">78%</Badge>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 bg-muted/50 rounded-lg border">
                    <h4 className="font-medium mb-3 flex items-center gap-2">
                      <Activity className="h-4 w-4" />
                      Risk Assessment
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Overall Risk:</span>
                        <Badge variant="destructive" className="text-xs">MODERATE-HIGH</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Attack Surface:</span>
                        <Badge variant="secondary" className="text-xs">LARGE</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Exploitability:</span>
                        <Badge variant="destructive" className="text-xs">HIGH</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Business Impact:</span>
                        <Badge variant="destructive" className="text-xs">CRITICAL</Badge>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Target Info */}
                <div className="p-4 bg-muted/50 rounded-lg">
                  <h3 className="font-semibold mb-2">Scan Details</h3>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Target:</span>
                      <span className="ml-2 font-medium">{scanResults.target}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Total Issues:</span>
                      <span className="ml-2 font-medium">{scanResults.totalVulnerabilities}</span>
                    </div>
                  </div>
                </div>

                {/* Tabbed Tool Results */}
                <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                  <TabsList className="grid w-full grid-cols-4 lg:grid-cols-7">
                    <TabsTrigger value="overview">Overview</TabsTrigger>
                    {Object.keys(scanResults.toolResults).map((toolId) => {
                      const tool = scanTools.find(t => t.id === toolId);
                      return tool ? (
                        <TabsTrigger key={toolId} value={toolId} className="text-xs">
                          {tool.name}
                        </TabsTrigger>
                      ) : null;
                    })}
                  </TabsList>

                  <TabsContent value="overview" className="space-y-4 mt-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {Object.entries(scanResults.toolResults).map(([toolId, results]: [string, any]) => {
                        const tool = scanTools.find(t => t.id === toolId);
                        if (!tool) return null;
                        const Icon = tool.icon;

                        let vulnCount = 0;
                        if (toolId === 'nessus') vulnCount = results.vulnerabilities?.length || 0;
                        else if (toolId === 'owasp-zap') vulnCount = results.alerts?.length || 0;
                        else if (toolId === 'nuclei') vulnCount = results.matched?.length || 0;
                        else if (toolId === 'nikto') vulnCount = results.findings?.length || 0;
                        else if (toolId === 'openvas') vulnCount = results.vulnerabilities?.length || 0;
                        else if (toolId === 'nmap') vulnCount = results.openPorts?.length || 0;

                        return (
                          <Card 
                            key={toolId} 
                            className="border-border hover:border-primary/50 transition-all cursor-pointer"
                            onClick={() => setActiveTab(toolId)}
                          >
                            <CardHeader className="pb-3">
                              <CardTitle className="flex items-center justify-between text-base">
                                <div className="flex items-center gap-2">
                                  <Icon className="h-5 w-5 text-primary" />
                                  {tool.name}
                                </div>
                                <ExternalLink className="h-4 w-4 text-muted-foreground" />
                              </CardTitle>
                            </CardHeader>
                            <CardContent>
                              <div className="flex items-center justify-between">
                                <span className="text-sm text-muted-foreground">
                                  {toolId === 'nmap' ? 'Open Ports' : 'Issues Found'}
                                </span>
                                <Badge variant="secondary" className="text-lg font-bold">
                                  {vulnCount}
                                </Badge>
                              </div>
                            </CardContent>
                          </Card>
                        );
                      })}
                    </div>
                  </TabsContent>

                  {Object.entries(scanResults.toolResults).map(([toolId, results]: [string, any]) => {
                    const tool = scanTools.find(t => t.id === toolId);
                    if (!tool) return null;

                    const Icon = tool.icon;

                    return (
                      <TabsContent key={toolId} value={toolId} className="space-y-4 mt-4">
                        <Card className="border-border">
                          <CardHeader className="pb-3">
                            <CardTitle className="flex items-center gap-2 text-base">
                              <Icon className="h-5 w-5" />
                              {tool.name} Results
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-3">
                          {toolId === 'nmap' && (
                            <div className="space-y-4">
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                                <div className="text-center p-3 bg-green-500/10 rounded-lg border border-green-500/20">
                                  <div className="text-lg font-bold text-green-600">{results.scanStats.hostsUp}</div>
                                  <div className="text-xs text-green-700">Hosts Up</div>
                                </div>
                                <div className="text-center p-3 bg-blue-500/10 rounded-lg border border-blue-500/20">
                                  <div className="text-lg font-bold text-blue-600">{results.scanStats.openPorts}</div>
                                  <div className="text-xs text-blue-700">Open Ports</div>
                                </div>
                                <div className="text-center p-3 bg-orange-500/10 rounded-lg border border-orange-500/20">
                                  <div className="text-lg font-bold text-orange-600">{results.scanStats.portsScanned}</div>
                                  <div className="text-xs text-orange-700">Ports Scanned</div>
                                </div>
                                <div className="text-center p-3 bg-purple-500/10 rounded-lg border border-purple-500/20">
                                  <div className="text-lg font-bold text-purple-600">{results.scanStats.scanDuration}</div>
                                  <div className="text-xs text-purple-700">Duration</div>
                                </div>
                              </div>

                              <div>
                                <h4 className="font-medium mb-3 flex items-center gap-2">
                                  <Network className="h-4 w-4" />
                                  Open Ports & Services
                                </h4>
                                <div className="space-y-2">
                                  {results.openPorts.map((port: any, idx: number) => {
                                    const portId = `nmap-${idx}`;
                                    const isExpanded = expandedVulns.has(portId);
                                    
                                    return (
                                      <div 
                                        key={idx} 
                                        className="p-3 bg-muted/30 rounded-lg border hover:bg-muted/50 transition-all cursor-pointer"
                                        onClick={() => toggleVulnExpand(portId)}
                                      >
                                        <div className="flex justify-between items-start mb-2">
                                          <div className="flex items-center gap-2">
                                            <Badge variant="outline" className="text-xs">
                                              {port.port}/{port.protocol}
                                            </Badge>
                                            <span className="font-medium text-sm">{port.service}</span>
                                          </div>
                                          <div className="flex gap-1 items-center">
                                            <Badge variant={port.state === 'open' ? 'default' : 'secondary'} className="text-xs">
                                              {port.state}
                                            </Badge>
                                            <Button
                                              variant="ghost"
                                              size="sm"
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                viewVulnDetail(port, 'Nmap');
                                              }}
                                              className="h-6 w-6 p-0"
                                            >
                                              <Eye className="h-3 w-3" />
                                            </Button>
                                            {isExpanded ? (
                                              <ChevronUp className="h-4 w-4 text-muted-foreground" />
                                            ) : (
                                              <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                            )}
                                          </div>
                                        </div>
                                        <div className="text-xs text-muted-foreground mb-1">
                                          <strong>Version:</strong> {port.version}
                                        </div>
                                        
                                        {isExpanded && (
                                          <div className="mt-2 pt-2 border-t space-y-1">
                                            <div className="text-xs text-muted-foreground">
                                              <strong>Banner:</strong> 
                                              <code className="ml-2 bg-muted px-2 py-1 rounded block mt-1">{port.banner}</code>
                                              <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={(e) => {
                                                  e.stopPropagation();
                                                  copyToClipboard(port.banner);
                                                }}
                                                className="h-5 w-5 p-0 mt-1"
                                              >
                                                <Copy className="h-3 w-3" />
                                              </Button>
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>

                              <div>
                                <h4 className="font-medium mb-3">OS Detection</h4>
                                <div className="p-3 bg-muted/30 rounded-lg border">
                                  <div className="grid grid-cols-2 gap-4 text-sm">
                                    <div>
                                      <span className="text-muted-foreground">OS:</span>
                                      <span className="ml-2 font-medium">{results.osDetection.os}</span>
                                    </div>
                                    <div>
                                      <span className="text-muted-foreground">Distribution:</span>
                                      <span className="ml-2 font-medium">{results.osDetection.distribution}</span>
                                    </div>
                                    <div>
                                      <span className="text-muted-foreground">Architecture:</span>
                                      <span className="ml-2 font-medium">{results.osDetection.architecture}</span>
                                    </div>
                                    <div>
                                      <span className="text-muted-foreground">Confidence:</span>
                                      <span className="ml-2 font-medium">{results.osDetection.confidence}%</span>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </div>
                          )}

                          {toolId === 'nessus' && (
                            <div className="space-y-4">
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                                <div className="text-center p-3 bg-blue-500/10 rounded-lg border border-blue-500/20">
                                  <div className="text-lg font-bold text-blue-600">{results.scanInfo.pluginsUsed.toLocaleString()}</div>
                                  <div className="text-xs text-blue-700">Plugins Used</div>
                                </div>
                                <div className="text-center p-3 bg-green-500/10 rounded-lg border border-green-500/20">
                                  <div className="text-lg font-bold text-green-600">{results.scanInfo.vulnerabilitiesFound}</div>
                                  <div className="text-xs text-green-700">Vulnerabilities</div>
                                </div>
                                <div className="text-center p-3 bg-purple-500/10 rounded-lg border border-purple-500/20">
                                  <div className="text-lg font-bold text-purple-600">{results.scanInfo.scanDuration}</div>
                                  <div className="text-xs text-purple-700">Duration</div>
                                </div>
                                <div className="text-center p-3 bg-orange-500/10 rounded-lg border border-orange-500/20">
                                  <div className="text-lg font-bold text-orange-600">{results.scanInfo.credentialedChecks ? 'Yes' : 'No'}</div>
                                  <div className="text-xs text-orange-700">Credentialed</div>
                                </div>
                              </div>

                              <div>
                                <h4 className="font-medium mb-3 flex items-center gap-2">
                                  <AlertTriangle className="h-4 w-4" />
                                  Critical Vulnerabilities
                                </h4>
                                <div className="space-y-3">
                                  {results.vulnerabilities.map((vuln: any, idx: number) => {
                                    const vulnId = `nessus-${idx}`;
                                    const isExpanded = expandedVulns.has(vulnId);
                                    
                                    return (
                                      <div 
                                        key={idx} 
                                        className="p-4 border rounded-lg bg-muted/20 hover:bg-muted/40 transition-all cursor-pointer"
                                        onClick={() => toggleVulnExpand(vulnId)}
                                      >
                                        <div className="flex justify-between items-start mb-3">
                                          <div className="flex items-center gap-2 flex-wrap">
                                            <Badge variant={
                                              vuln.severity === 'critical' ? 'destructive' :
                                                vuln.severity === 'high' ? 'destructive' :
                                                  vuln.severity === 'medium' ? 'secondary' : 'outline'
                                            } className="text-xs">
                                              {vuln.severity.toUpperCase()}
                                            </Badge>
                                            <span className="font-medium text-sm">{vuln.id}</span>
                                            <Badge variant="outline" className="text-xs">
                                              CVSS {vuln.cvss}
                                            </Badge>
                                          </div>
                                          <div className="flex gap-1 items-center">
                                            {vuln.exploitAvailable && (
                                              <Badge variant="destructive" className="text-xs">EXPLOIT</Badge>
                                            )}
                                            {vuln.patchAvailable && (
                                              <Badge variant="secondary" className="text-xs">PATCH</Badge>
                                            )}
                                            <Button
                                              variant="ghost"
                                              size="sm"
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                viewVulnDetail(vuln, 'Nessus');
                                              }}
                                              className="h-6 w-6 p-0"
                                            >
                                              <Eye className="h-3 w-3" />
                                            </Button>
                                            {isExpanded ? (
                                              <ChevronUp className="h-4 w-4 text-muted-foreground" />
                                            ) : (
                                              <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                            )}
                                          </div>
                                        </div>
                                        <p className="text-sm text-muted-foreground mb-2">{vuln.description}</p>
                                        
                                        {isExpanded && (
                                          <div className="mt-3 pt-3 border-t space-y-2">
                                            <div className="text-xs text-muted-foreground">
                                              <strong>CVSS Vector:</strong> 
                                              <code className="ml-2 bg-muted px-2 py-1 rounded">{vuln.vector}</code>
                                              <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={(e) => {
                                                  e.stopPropagation();
                                                  copyToClipboard(vuln.vector);
                                                }}
                                                className="h-5 w-5 p-0 ml-2"
                                              >
                                                <Copy className="h-3 w-3" />
                                              </Button>
                                            </div>
                                            <div className="text-xs">
                                              <strong className="text-green-600">Solution:</strong> {vuln.solution}
                                            </div>
                                            {vuln.references && vuln.references.length > 0 && (
                                              <div className="text-xs">
                                                <strong>References:</strong>
                                                <div className="mt-1 space-y-1">
                                                  {vuln.references.map((ref: string, refIdx: number) => (
                                                    <a
                                                      key={refIdx}
                                                      href={ref}
                                                      target="_blank"
                                                      rel="noopener noreferrer"
                                                      className="flex items-center gap-1 text-primary hover:underline"
                                                      onClick={(e) => e.stopPropagation()}
                                                    >
                                                      <ExternalLink className="h-3 w-3" />
                                                      {ref}
                                                    </a>
                                                  ))}
                                                </div>
                                              </div>
                                            )}
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>

                              <div>
                                <h4 className="font-medium mb-3">Compliance Summary</h4>
                                <div className="grid grid-cols-2 gap-4">
                                  <div className="p-3 bg-muted/30 rounded-lg border">
                                    <div className="text-center">
                                      <div className="text-2xl font-bold text-green-600">{results.compliance.passed}</div>
                                      <div className="text-xs text-green-700">Passed</div>
                                    </div>
                                  </div>
                                  <div className="p-3 bg-muted/30 rounded-lg border">
                                    <div className="text-center">
                                      <div className="text-2xl font-bold text-red-600">{results.compliance.failed}</div>
                                      <div className="text-xs text-red-700">Failed</div>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </div>
                          )}

                          {toolId === 'owasp-zap' && (
                            <div className="space-y-4">
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                                <div className="text-center p-3 bg-blue-500/10 rounded-lg border border-blue-500/20">
                                  <div className="text-lg font-bold text-blue-600">{results.scanInfo.urlsFound}</div>
                                  <div className="text-xs text-blue-700">URLs Found</div>
                                </div>
                                <div className="text-center p-3 bg-green-500/10 rounded-lg border border-green-500/20">
                                  <div className="text-lg font-bold text-green-600">{results.scanInfo.formsFound}</div>
                                  <div className="text-xs text-green-700">Forms Found</div>
                                </div>
                                <div className="text-center p-3 bg-orange-500/10 rounded-lg border border-orange-500/20">
                                  <div className="text-lg font-bold text-orange-600">{results.scanInfo.alertsRaised}</div>
                                  <div className="text-xs text-orange-700">Alerts Raised</div>
                                </div>
                                <div className="text-center p-3 bg-purple-500/10 rounded-lg border border-purple-500/20">
                                  <div className="text-lg font-bold text-purple-600">{results.spider.coverage}</div>
                                  <div className="text-xs text-purple-700">Coverage</div>
                                </div>
                              </div>

                              <div>
                                <h4 className="font-medium mb-3 flex items-center gap-2">
                                  <AlertTriangle className="h-4 w-4" />
                                  Security Alerts
                                </h4>
                                <div className="space-y-3">
                                  {results.alerts.map((alert: any, idx: number) => {
                                    const alertId = `zap-${idx}`;
                                    const isExpanded = expandedVulns.has(alertId);
                                    
                                    return (
                                      <div 
                                        key={idx} 
                                        className="p-4 border rounded-lg bg-muted/20 hover:bg-muted/40 transition-all cursor-pointer"
                                        onClick={() => toggleVulnExpand(alertId)}
                                      >
                                        <div className="flex justify-between items-start mb-3">
                                          <div className="flex items-center gap-2 flex-wrap">
                                            <Badge variant={
                                              alert.risk === 'High' ? 'destructive' :
                                                alert.risk === 'Medium' ? 'secondary' : 'outline'
                                            } className="text-xs">
                                              {alert.risk} RISK
                                            </Badge>
                                            <Badge variant="outline" className="text-xs">
                                              {alert.confidence} CONFIDENCE
                                            </Badge>
                                          </div>
                                          <div className="flex gap-1 items-center">
                                            <Button
                                              variant="ghost"
                                              size="sm"
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                viewVulnDetail(alert, 'OWASP ZAP');
                                              }}
                                              className="h-6 w-6 p-0"
                                            >
                                              <Eye className="h-3 w-3" />
                                            </Button>
                                            {isExpanded ? (
                                              <ChevronUp className="h-4 w-4 text-muted-foreground" />
                                            ) : (
                                              <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                            )}
                                          </div>
                                        </div>
                                        <h5 className="font-medium text-sm mb-2">{alert.name}</h5>
                                        <p className="text-sm text-muted-foreground mb-2">{alert.description}</p>
                                        
                                        {isExpanded && (
                                          <div className="mt-3 pt-3 border-t space-y-2">
                                            <div className="grid grid-cols-2 gap-4 text-xs">
                                              <div>
                                                <strong>URL:</strong> 
                                                <a 
                                                  href={alert.url} 
                                                  target="_blank" 
                                                  rel="noopener noreferrer"
                                                  className="ml-1 text-primary hover:underline inline-flex items-center gap-1"
                                                  onClick={(e) => e.stopPropagation()}
                                                >
                                                  {alert.url}
                                                  <ExternalLink className="h-3 w-3" />
                                                </a>
                                              </div>
                                              <div>
                                                <strong>Parameter:</strong> 
                                                <code className="ml-1 bg-muted px-1 rounded">{alert.parameter}</code>
                                              </div>
                                            </div>
                                            <div className="text-xs">
                                              <strong>Attack:</strong> 
                                              <code className="ml-2 bg-muted px-2 py-1 rounded">{alert.attack}</code>
                                              <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={(e) => {
                                                  e.stopPropagation();
                                                  copyToClipboard(alert.attack);
                                                }}
                                                className="h-5 w-5 p-0 ml-2"
                                              >
                                                <Copy className="h-3 w-3" />
                                              </Button>
                                            </div>
                                            <div className="text-xs">
                                              <strong>Evidence:</strong> {alert.evidence}
                                            </div>
                                            <div className="text-xs">
                                              <strong className="text-green-600">Solution:</strong> {alert.solution}
                                            </div>
                                            {alert.reference && (
                                              <div className="text-xs">
                                                <strong>Reference:</strong>
                                                <a
                                                  href={alert.reference}
                                                  target="_blank"
                                                  rel="noopener noreferrer"
                                                  className="ml-1 text-primary hover:underline inline-flex items-center gap-1"
                                                  onClick={(e) => e.stopPropagation()}
                                                >
                                                  {alert.reference}
                                                  <ExternalLink className="h-3 w-3" />
                                                </a>
                                              </div>
                                            )}
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>

                              <div>
                                <h4 className="font-medium mb-3">OWASP Top 10 Analysis</h4>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                  {Object.entries(results.owaspTop10).map(([category, count]: [string, any]) => (
                                    <div key={category} className="flex justify-between items-center p-2 bg-muted/30 rounded border">
                                      <span className="text-xs font-medium">{category}</span>
                                      <Badge variant={count > 0 ? 'destructive' : 'secondary'} className="text-xs">
                                        {count} issues
                                      </Badge>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    </TabsContent>
                  );
                })}
              </Tabs>

                {/* AI Analysis Section */}
                <div className="border-t pt-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold flex items-center gap-2">
                      <Brain className="h-5 w-5 text-primary" />
                      AI Security Analysis
                    </h3>
                    <Button
                      onClick={performAiAnalysis}
                      disabled={isAnalyzing}
                      className="gap-2 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700"
                    >
                      {isAnalyzing ? (
                        <>
                          <Loader2 className="h-4 w-4 animate-spin" />
                          Analyzing...
                        </>
                      ) : (
                        <>
                          <Brain className="h-4 w-4" />
                          AI Analyze
                        </>
                      )}
                    </Button>
                  </div>

                  {isAnalyzing && (
                    <div className="p-6 bg-gradient-to-br from-purple-600/5 to-blue-600/5 rounded-lg border border-purple-500/20">
                      <div className="flex items-center gap-3">
                        <Loader2 className="h-5 w-5 animate-spin text-purple-600" />
                        <div>
                          <p className="font-medium">AI is analyzing your scan results...</p>
                          <p className="text-sm text-muted-foreground">Generating comprehensive security insights and actionable recommendations...</p>
                        </div>
                      </div>
                    </div>
                  )}

                  {!isAnalyzing && !aiAnalysis && (
                    <Card className="bg-gradient-to-br from-purple-600/5 to-blue-600/5 border-purple-500/20">
                      <CardContent className="pt-6">
                        <div className="text-center space-y-3">
                          <div className="flex justify-center">
                            <div className="h-12 w-12 rounded-full bg-gradient-to-r from-purple-600 to-blue-600 flex items-center justify-center">
                              <Brain className="h-6 w-6 text-white" />
                            </div>
                          </div>
                          <h4 className="font-semibold">Get AI-Powered Security Insights</h4>
                          <p className="text-sm text-muted-foreground max-w-md mx-auto">
                            Our advanced AI will analyze your scan results and provide:
                          </p>
                          <div className="grid grid-cols-2 gap-3 max-w-lg mx-auto text-left">
                            <div className="flex items-start gap-2 text-sm">
                              <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                              <span>Risk prioritization</span>
                            </div>
                            <div className="flex items-start gap-2 text-sm">
                              <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                              <span>Remediation steps</span>
                            </div>
                            <div className="flex items-start gap-2 text-sm">
                              <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                              <span>Attack scenarios</span>
                            </div>
                            <div className="flex items-start gap-2 text-sm">
                              <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                              <span>Cost estimates</span>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* Vulnerability Detail Dialog */}
        <Dialog open={showVulnDetail} onOpenChange={setShowVulnDetail}>
          <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-primary/10 rounded-lg">
                    <Shield className="h-6 w-6 text-primary" />
                  </div>
                  <div>
                    <DialogTitle className="text-xl font-bold">
                      {selectedVuln?.name || selectedVuln?.id || selectedVuln?.service || 'Vulnerability Details'}
                    </DialogTitle>
                    <p className="text-sm text-muted-foreground mt-1">
                      Detected by {selectedVuln?.toolName}
                    </p>
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowVulnDetail(false)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </DialogHeader>

            {selectedVuln && (
              <div className="space-y-6 mt-4">
                {/* Severity & Status */}
                <div className="flex items-center gap-2 flex-wrap">
                  {selectedVuln.severity && (
                    <Badge variant={
                      selectedVuln.severity === 'critical' ? 'destructive' :
                        selectedVuln.severity === 'high' ? 'destructive' :
                          selectedVuln.severity === 'medium' ? 'secondary' : 'outline'
                    }>
                      {selectedVuln.severity.toUpperCase()}
                    </Badge>
                  )}
                  {selectedVuln.risk && (
                    <Badge variant={
                      selectedVuln.risk === 'High' ? 'destructive' :
                        selectedVuln.risk === 'Medium' ? 'secondary' : 'outline'
                    }>
                      {selectedVuln.risk} RISK
                    </Badge>
                  )}
                  {selectedVuln.cvss && (
                    <Badge variant="outline">CVSS {selectedVuln.cvss}</Badge>
                  )}
                  {selectedVuln.confidence && (
                    <Badge variant="outline">{selectedVuln.confidence} CONFIDENCE</Badge>
                  )}
                  {selectedVuln.exploitAvailable && (
                    <Badge variant="destructive">EXPLOIT AVAILABLE</Badge>
                  )}
                  {selectedVuln.patchAvailable && (
                    <Badge variant="secondary">PATCH AVAILABLE</Badge>
                  )}
                  {selectedVuln.state && (
                    <Badge variant={selectedVuln.state === 'open' ? 'default' : 'secondary'}>
                      {selectedVuln.state.toUpperCase()}
                    </Badge>
                  )}
                </div>

                {/* Description */}
                {selectedVuln.description && (
                  <div className="p-4 bg-muted/50 rounded-lg border">
                    <h3 className="font-semibold mb-2 flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      Description
                    </h3>
                    <p className="text-sm text-muted-foreground">{selectedVuln.description}</p>
                  </div>
                )}

                {/* Technical Details */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {selectedVuln.port && (
                    <div className="p-3 bg-muted/30 rounded-lg border">
                      <p className="text-xs text-muted-foreground mb-1">Port</p>
                      <p className="font-medium">{selectedVuln.port}/{selectedVuln.protocol}</p>
                    </div>
                  )}
                  {selectedVuln.service && (
                    <div className="p-3 bg-muted/30 rounded-lg border">
                      <p className="text-xs text-muted-foreground mb-1">Service</p>
                      <p className="font-medium">{selectedVuln.service}</p>
                    </div>
                  )}
                  {selectedVuln.version && (
                    <div className="p-3 bg-muted/30 rounded-lg border">
                      <p className="text-xs text-muted-foreground mb-1">Version</p>
                      <p className="font-medium">{selectedVuln.version}</p>
                    </div>
                  )}
                  {selectedVuln.url && (
                    <div className="p-3 bg-muted/30 rounded-lg border">
                      <p className="text-xs text-muted-foreground mb-1">URL</p>
                      <a 
                        href={selectedVuln.url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="font-medium text-primary hover:underline inline-flex items-center gap-1 text-sm break-all"
                      >
                        {selectedVuln.url}
                        <ExternalLink className="h-3 w-3 flex-shrink-0" />
                      </a>
                    </div>
                  )}
                  {selectedVuln.parameter && (
                    <div className="p-3 bg-muted/30 rounded-lg border">
                      <p className="text-xs text-muted-foreground mb-1">Parameter</p>
                      <code className="font-medium bg-muted px-2 py-1 rounded">{selectedVuln.parameter}</code>
                    </div>
                  )}
                </div>

                {/* CVSS Vector */}
                {selectedVuln.vector && (
                  <div className="p-4 bg-muted/50 rounded-lg border">
                    <h3 className="font-semibold mb-2">CVSS Vector</h3>
                    <div className="flex items-center gap-2">
                      <code className="text-sm bg-muted px-3 py-2 rounded flex-1">{selectedVuln.vector}</code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(selectedVuln.vector)}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                )}

                {/* Attack Details */}
                {selectedVuln.attack && (
                  <div className="p-4 bg-muted/50 rounded-lg border">
                    <h3 className="font-semibold mb-2">Attack Vector</h3>
                    <div className="flex items-center gap-2">
                      <code className="text-sm bg-muted px-3 py-2 rounded flex-1">{selectedVuln.attack}</code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(selectedVuln.attack)}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                )}

                {/* Evidence */}
                {selectedVuln.evidence && (
                  <div className="p-4 bg-muted/50 rounded-lg border">
                    <h3 className="font-semibold mb-2">Evidence</h3>
                    <p className="text-sm text-muted-foreground">{selectedVuln.evidence}</p>
                  </div>
                )}

                {/* Banner */}
                {selectedVuln.banner && (
                  <div className="p-4 bg-muted/50 rounded-lg border">
                    <h3 className="font-semibold mb-2">Service Banner</h3>
                    <div className="flex items-start gap-2">
                      <code className="text-sm bg-muted px-3 py-2 rounded flex-1 whitespace-pre-wrap">{selectedVuln.banner}</code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(selectedVuln.banner)}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                )}

                {/* Solution */}
                {selectedVuln.solution && (
                  <div className="p-4 bg-green-500/10 rounded-lg border border-green-500/20">
                    <h3 className="font-semibold mb-2 text-green-700 flex items-center gap-2">
                      <CheckCircle className="h-4 w-4" />
                      Recommended Solution
                    </h3>
                    <p className="text-sm text-green-700">{selectedVuln.solution}</p>
                  </div>
                )}

                {/* References */}
                {selectedVuln.references && selectedVuln.references.length > 0 && (
                  <div className="p-4 bg-muted/50 rounded-lg border">
                    <h3 className="font-semibold mb-3">References</h3>
                    <div className="space-y-2">
                      {selectedVuln.references.map((ref: string, idx: number) => (
                        <a
                          key={idx}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-2 text-sm text-primary hover:underline"
                        >
                          <ExternalLink className="h-4 w-4" />
                          {ref}
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {selectedVuln.reference && (
                  <div className="p-4 bg-muted/50 rounded-lg border">
                    <h3 className="font-semibold mb-3">Reference</h3>
                    <a
                      href={selectedVuln.reference}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-sm text-primary hover:underline"
                    >
                      <ExternalLink className="h-4 w-4" />
                      {selectedVuln.reference}
                    </a>
                  </div>
                )}

                {/* Action Buttons */}
                <div className="flex gap-2 pt-4 border-t">
                  <Button
                    variant="outline"
                    className="flex-1"
                    onClick={() => {
                      const text = JSON.stringify(selectedVuln, null, 2);
                      copyToClipboard(text);
                    }}
                  >
                    <Copy className="h-4 w-4 mr-2" />
                    Copy Details
                  </Button>
                  <Button
                    variant="outline"
                    className="flex-1"
                    onClick={() => {
                      const data = JSON.stringify(selectedVuln, null, 2);
                      const blob = new Blob([data], { type: 'application/json' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `vulnerability-${selectedVuln.id || 'detail'}.json`;
                      document.body.appendChild(a);
                      a.click();
                      document.body.removeChild(a);
                      URL.revokeObjectURL(url);
                    }}
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Export
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* AI Chat Component */}
        {showAIChat && aiAnalysis && (
          <AIChat 
            initialAnalysis={aiAnalysis} 
            onClose={() => setShowAIChat(false)}
          />
        )}
      </div>
    </DashboardLayout>
  );
};

export default ScanConfig;