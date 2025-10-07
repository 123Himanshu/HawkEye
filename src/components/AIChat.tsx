import { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Send, X, Sparkles, AlertTriangle, Zap, Copy, Download, RefreshCw, Shield } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";

interface Message {
  role: "user" | "assistant" | "system";
  content: string;
  type?: "analysis" | "chat" | "action" | "system";
  timestamp?: Date;
}

interface SuggestedAction {
  id: string;
  label: string;
  icon: any;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
}

interface AIChatProps {
  initialAnalysis?: string;
  onClose?: () => void;
}

const AIChat = ({ initialAnalysis, onClose }: AIChatProps) => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [suggestedActions, setSuggestedActions] = useState<SuggestedAction[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (initialAnalysis) {
      setIsOpen(true);
      setMessages([
        {
          role: "system",
          content: "AI Security Analysis Complete",
          type: "system",
          timestamp: new Date()
        }
      ]);

      // Simulate typing effect for analysis
      setTimeout(() => {
        setIsTyping(true);
        setTimeout(() => {
          setIsTyping(false);
          setMessages(prev => [...prev, {
            role: "assistant",
            content: initialAnalysis,
            type: "analysis",
            timestamp: new Date()
          }]);

          // Generate suggested actions
          generateSuggestedActions(initialAnalysis);
        }, 1500);
      }, 500);
    } else {
      setMessages([
        {
          role: "assistant",
          content: "👋 Hello! I'm your AI Security Assistant powered by advanced threat intelligence.\n\nI can help you:\n• Analyze vulnerability scan results\n• Explain CVEs and attack vectors\n• Suggest remediation strategies\n• Prioritize security fixes\n\nHow can I assist you today?",
          type: "chat",
          timestamp: new Date()
        }
      ]);
    }
  }, [initialAnalysis]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  const generateSuggestedActions = (analysis: string) => {
    const actions: SuggestedAction[] = [];

    if (analysis.includes("SQL Injection") || analysis.includes("SQL injection")) {
      actions.push({
        id: "fix-sql",
        label: "Fix SQL Injection",
        icon: Shield,
        severity: "critical",
        description: "Implement parameterized queries"
      });
    }

    if (analysis.includes("XSS") || analysis.includes("Cross Site Scripting")) {
      actions.push({
        id: "fix-xss",
        label: "Fix XSS Vulnerability",
        icon: AlertTriangle,
        severity: "high",
        description: "Add output encoding and CSP headers"
      });
    }

    if (analysis.includes("glibc") || analysis.includes("Buffer overflow")) {
      actions.push({
        id: "update-glibc",
        label: "Update glibc",
        icon: RefreshCw,
        severity: "critical",
        description: "Apply critical security patch"
      });
    }

    if (analysis.includes("security headers") || analysis.includes("Security Headers")) {
      actions.push({
        id: "add-headers",
        label: "Add Security Headers",
        icon: Shield,
        severity: "medium",
        description: "Implement HSTS, CSP, X-Frame-Options"
      });
    }

    actions.push({
      id: "generate-report",
      label: "Generate Full Report",
      icon: Download,
      severity: "low",
      description: "Export detailed PDF report"
    });

    setSuggestedActions(actions);
  };

  const handleSend = () => {
    if (!input.trim()) return;

    const userMessage: Message = {
      role: "user",
      content: input,
      type: "chat",
      timestamp: new Date()
    };
    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsTyping(true);

    // Simulate AI response
    setTimeout(() => {
      setIsTyping(false);
      let response = generateAIResponse(input);

      setMessages((prev) => [...prev, {
        role: "assistant",
        content: response,
        type: "chat",
        timestamp: new Date()
      }]);
    }, 1000 + Math.random() * 1000);
  };

  const generateAIResponse = (query: string): string => {
    const lowerQuery = query.toLowerCase();

    if (lowerQuery.includes("sql") && lowerQuery.includes("fix")) {
      return "🛡️ **SQL Injection Remediation Steps:**\n\n1. **Immediate Action:**\n   • Replace string concatenation with parameterized queries\n   • Example: `cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))`\n\n2. **Additional Security:**\n   • Implement input validation\n   • Use ORM frameworks (SQLAlchemy, Django ORM)\n   • Enable WAF rules for SQL injection patterns\n   • Conduct code review of all database queries\n\n3. **Testing:**\n   • Run automated SQL injection tests\n   • Verify all user inputs are sanitized\n\n**Estimated Time:** 2-4 hours\n**Priority:** CRITICAL";
    }

    if (lowerQuery.includes("xss")) {
      return "🔒 **XSS Vulnerability Mitigation:**\n\n1. **Output Encoding:**\n   • HTML encode all user-generated content\n   • Use template engines with auto-escaping\n\n2. **Content Security Policy:**\n   ```\n   Content-Security-Policy: default-src 'self'; script-src 'self'\n   ```\n\n3. **Input Validation:**\n   • Whitelist allowed characters\n   • Reject suspicious patterns\n\n4. **HTTPOnly Cookies:**\n   • Set HttpOnly flag on session cookies\n   • Prevents JavaScript access\n\n**Priority:** HIGH";
    }

    if (lowerQuery.includes("priority") || lowerQuery.includes("order")) {
      return "📊 **Recommended Remediation Priority:**\n\n**🔴 CRITICAL (0-24 hours):**\n1. CVE-2023-4911 - glibc buffer overflow\n2. SQL Injection in authentication\n\n**🟠 HIGH (24-72 hours):**\n3. Reflected XSS in search\n4. nginx HTTP/2 vulnerability\n5. Exposed database ports\n\n**🟡 MEDIUM (1-2 weeks):**\n6. Missing security headers\n7. Weak SSL ciphers\n8. CSRF token issues\n\n**🟢 LOW (2-4 weeks):**\n9. Directory indexing\n10. Cookie security flags\n\nFocus on critical items first for maximum risk reduction.";
    }

    if (lowerQuery.includes("cost") || lowerQuery.includes("budget")) {
      return "💰 **Estimated Remediation Costs:**\n\n**Phase 1 - Emergency (0-72h):**\n• Developer time: $15,000 - $25,000\n• Security consultant: $5,000\n• Total: ~$20,000 - $30,000\n\n**Phase 2 - Hardening (1-4 weeks):**\n• Infrastructure updates: $10,000\n• Development work: $25,000\n• Testing: $10,000\n• Total: ~$45,000\n\n**Phase 3 - Long-term (3 months):**\n• Security tools: $15,000/year\n• Training: $10,000\n• Ongoing monitoring: $20,000/year\n\n**Total First Year:** $110,000 - $130,000\n\nNote: Cost of a breach averages $4.35M - prevention is significantly cheaper!";
    }

    if (lowerQuery.includes("cve")) {
      return "🔍 **CVE Analysis:**\n\nI can provide detailed information about specific CVEs found in your scan:\n\n• **CVE-2023-4911** (CVSS 9.8) - Critical glibc vulnerability\n• **CVE-2023-1234** (CVSS 8.1) - nginx HTTP/2 RCE\n• **CVE-2023-5678** (CVSS 7.5) - SQL injection\n\nWhich CVE would you like me to explain in detail?";
    }

    return "I understand you're asking about: \"" + query + "\"\n\nI can provide more specific guidance on:\n• Vulnerability details and impact\n• Step-by-step remediation guides\n• Cost and time estimates\n• Compliance requirements\n• Attack scenarios\n\nCould you be more specific about what you'd like to know?";
  };

  const handleActionClick = (action: SuggestedAction) => {
    setMessages(prev => [...prev, {
      role: "user",
      content: `Execute action: ${action.label}`,
      type: "action",
      timestamp: new Date()
    }]);

    setIsTyping(true);
    setTimeout(() => {
      setIsTyping(false);
      let response = "";

      switch (action.id) {
        case "fix-sql":
          response = "✅ **SQL Injection Fix Guide Generated**\n\n```python\n# Before (Vulnerable)\nquery = f\"SELECT * FROM users WHERE username = '{username}'\"\ncursor.execute(query)\n\n# After (Secure)\nquery = \"SELECT * FROM users WHERE username = %s\"\ncursor.execute(query, (username,))\n```\n\n**Additional Steps:**\n1. Review all database queries in codebase\n2. Implement input validation\n3. Enable prepared statements\n4. Add WAF rules\n\n**Testing Command:**\n```bash\nsqlmap -u \"http://target.com/login\" --batch\n```";
          break;
        case "fix-xss":
          response = "✅ **XSS Remediation Package Ready**\n\n**1. Output Encoding:**\n```javascript\n// Use DOMPurify or similar\nimport DOMPurify from 'dompurify';\nconst clean = DOMPurify.sanitize(userInput);\n```\n\n**2. CSP Header:**\n```nginx\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline';\";\n```\n\n**3. Input Validation:**\n```javascript\nconst sanitize = (input) => {\n  return input.replace(/[<>\"']/g, '');\n};\n```";
          break;
        case "update-glibc":
          response = "✅ **glibc Update Procedure**\n\n**Ubuntu/Debian:**\n```bash\nsudo apt update\nsudo apt install --only-upgrade libc6\nsudo reboot\n```\n\n**RHEL/CentOS:**\n```bash\nsudo yum update glibc\nsudo reboot\n```\n\n**Verification:**\n```bash\nldd --version\n```\n\n⚠️ **Important:** Schedule maintenance window - requires system reboot!";
          break;
        case "add-headers":
          response = "✅ **Security Headers Configuration**\n\n```nginx\n# Add to nginx config\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-XSS-Protection \"1; mode=block\" always;\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\nadd_header Content-Security-Policy \"default-src 'self'\" always;\n```\n\n**Test Headers:**\n```bash\ncurl -I https://your-domain.com\n```";
          break;
        case "generate-report":
          response = "📄 **Report Generation Started**\n\n✅ Compiling vulnerability data...\n✅ Generating executive summary...\n✅ Creating remediation roadmap...\n✅ Adding compliance mappings...\n✅ Formatting PDF document...\n\n**Report Includes:**\n• Executive Summary\n• Detailed Findings (47 vulnerabilities)\n• Risk Assessment Matrix\n• Remediation Roadmap\n• Cost Analysis\n• Compliance Mapping\n\n📥 **Download Ready:** security-report-" + new Date().toISOString().split('T')[0] + ".pdf\n\n*Note: This is a UI demo - actual report generation would be implemented on backend*";
          break;
      }

      setMessages(prev => [...prev, {
        role: "assistant",
        content: response,
        type: "action",
        timestamp: new Date()
      }]);
    }, 1500);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-500/10 text-red-500 border-red-500/20";
      case "high": return "bg-orange-500/10 text-orange-500 border-orange-500/20";
      case "medium": return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
      case "low": return "bg-blue-500/10 text-blue-500 border-blue-500/20";
      default: return "bg-gray-500/10 text-gray-500 border-gray-500/20";
    }
  };

  const formatMessageContent = (content: string) => {
    // Split by code blocks
    const parts = content.split(/(```[\s\S]*?```)/g);

    return parts.map((part, index) => {
      if (part.startsWith('```')) {
        const code = part.replace(/```(\w+)?\n?/g, '').replace(/```$/g, '');
        const language = part.match(/```(\w+)/)?.[1] || 'text';

        return (
          <div key={index} className="my-3 relative group">
            <div className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity">
              <Button
                size="sm"
                variant="ghost"
                className="h-6 w-6 p-0"
                onClick={() => copyToClipboard(code)}
              >
                <Copy className="h-3 w-3" />
              </Button>
            </div>
            <pre className="bg-black/40 border border-border rounded-lg p-3 overflow-x-auto">
              <code className="text-xs text-green-400 font-mono">{code}</code>
            </pre>
            <div className="text-[10px] text-muted-foreground mt-1">{language}</div>
          </div>
        );
      }

      // Format regular text with markdown-like styling
      return (
        <div key={index} className="space-y-2">
          {part.split('\n').map((line, lineIndex) => {
            // Headers
            if (line.startsWith('# ')) {
              return <h3 key={lineIndex} className="text-lg font-bold mt-4 mb-2 text-primary">{line.substring(2)}</h3>;
            }
            if (line.startsWith('## ')) {
              return <h4 key={lineIndex} className="text-base font-semibold mt-3 mb-2">{line.substring(3)}</h4>;
            }
            if (line.startsWith('### ')) {
              return <h5 key={lineIndex} className="text-sm font-semibold mt-2 mb-1">{line.substring(4)}</h5>;
            }

            // Bold text
            if (line.includes('**')) {
              const formatted = line.split(/(\*\*.*?\*\*)/g).map((segment, i) => {
                if (segment.startsWith('**') && segment.endsWith('**')) {
                  return <strong key={i} className="font-semibold text-foreground">{segment.slice(2, -2)}</strong>;
                }
                return segment;
              });
              return <p key={lineIndex} className="text-sm leading-relaxed">{formatted}</p>;
            }

            // Bullet points
            if (line.trim().startsWith('•') || line.trim().startsWith('-')) {
              return (
                <div key={lineIndex} className="flex gap-2 text-sm ml-2">
                  <span className="text-primary">•</span>
                  <span>{line.trim().substring(1).trim()}</span>
                </div>
              );
            }

            // Numbered lists
            if (/^\d+\./.test(line.trim())) {
              return <p key={lineIndex} className="text-sm ml-2">{line}</p>;
            }

            // Empty lines
            if (line.trim() === '') {
              return <div key={lineIndex} className="h-2" />;
            }

            // Regular text
            return <p key={lineIndex} className="text-sm leading-relaxed">{line}</p>;
          })}
        </div>
      );
    });
  };

  const handleClose = () => {
    setIsOpen(false);
    if (onClose) onClose();
  };

  return (
    <>
      {/* Floating Button */}
      {!isOpen && !initialAnalysis && (
        <Button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 h-14 w-14 rounded-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 shadow-lg shadow-purple-500/50 animate-glow-pulse z-50"
        >
          <Sparkles className="h-6 w-6" />
        </Button>
      )}

      {/* Chat Window */}
      {isOpen && (
        <Card className="fixed bottom-6 right-6 w-[600px] h-[700px] border-border shadow-2xl shadow-purple-500/20 z-50 flex flex-col bg-background/95 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between border-b border-border bg-gradient-to-r from-purple-600/10 to-blue-600/10">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-full bg-gradient-to-r from-purple-600 to-blue-600 flex items-center justify-center">
                <Sparkles className="h-5 w-5 text-white" />
              </div>
              <div>
                <CardTitle className="text-lg">AI Security Assistant</CardTitle>
                <p className="text-xs text-muted-foreground">Powered by Advanced Threat Intelligence</p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="icon"
              onClick={handleClose}
              className="h-8 w-8 hover:bg-destructive/10"
            >
              <X className="h-4 w-4" />
            </Button>
          </CardHeader>

          <CardContent className="flex-1 flex flex-col p-0 overflow-hidden">
            <ScrollArea className="flex-1 p-4" ref={scrollRef}>
              <div className="space-y-4">
                {messages.map((message, i) => (
                  <div key={i}>
                    {message.type === "system" && (
                      <div className="flex justify-center my-4">
                        <Badge className="bg-gradient-to-r from-purple-600 to-blue-600 text-white border-0">
                          <Sparkles className="h-3 w-3 mr-1" />
                          {message.content}
                        </Badge>
                      </div>
                    )}

                    {message.type !== "system" && (
                      <div className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}>
                        <div className={`max-w-[85%] ${message.role === "user" ? "" : "w-full"}`}>
                          {message.role === "assistant" && (
                            <div className="flex items-center gap-2 mb-2">
                              <div className="h-6 w-6 rounded-full bg-gradient-to-r from-purple-600 to-blue-600 flex items-center justify-center">
                                <Sparkles className="h-3 w-3 text-white" />
                              </div>
                              <span className="text-xs font-medium">AI Assistant</span>
                              <span className="text-xs text-muted-foreground">
                                {message.timestamp?.toLocaleTimeString()}
                              </span>
                            </div>
                          )}

                          <div
                            className={`p-4 rounded-lg ${message.role === "user"
                              ? "bg-gradient-to-r from-purple-600 to-blue-600 text-white ml-auto"
                              : message.type === "analysis"
                                ? "bg-card border border-border"
                                : "bg-muted/50 border border-border/50"
                              }`}
                          >
                            {message.role === "user" ? (
                              <p className="text-sm">{message.content}</p>
                            ) : (
                              <div className="prose prose-sm max-w-none dark:prose-invert">
                                {formatMessageContent(message.content)}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ))}

                {isTyping && (
                  <div className="flex justify-start">
                    <div className="flex items-center gap-2">
                      <div className="h-6 w-6 rounded-full bg-gradient-to-r from-purple-600 to-blue-600 flex items-center justify-center">
                        <Sparkles className="h-3 w-3 text-white animate-pulse" />
                      </div>
                      <div className="bg-muted/50 border border-border/50 p-3 rounded-lg">
                        <div className="flex gap-1">
                          <div className="h-2 w-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                          <div className="h-2 w-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                          <div className="h-2 w-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </ScrollArea>

            {/* Suggested Actions */}
            {suggestedActions.length > 0 && (
              <div className="border-t border-border p-4 bg-muted/30">
                <div className="flex items-center gap-2 mb-3">
                  <Zap className="h-4 w-4 text-yellow-500" />
                  <span className="text-sm font-semibold">Suggested Actions</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {suggestedActions.map((action) => {
                    const Icon = action.icon;
                    return (
                      <Button
                        key={action.id}
                        size="sm"
                        variant="outline"
                        className={`${getSeverityColor(action.severity)} hover:scale-105 transition-transform`}
                        onClick={() => handleActionClick(action)}
                      >
                        <Icon className="h-3 w-3 mr-1" />
                        {action.label}
                      </Button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Input Area */}
            <div className="p-4 border-t border-border bg-background">
              <div className="flex gap-2">
                <Input
                  placeholder="Ask about vulnerabilities, fixes, or security best practices..."
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSend()}
                  className="bg-input border-border"
                />
                <Button
                  onClick={handleSend}
                  className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700"
                  disabled={isTyping}
                >
                  <Send className="h-4 w-4" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                💡 Try: "How do I fix SQL injection?" or "What should I prioritize?"
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </>
  );
};

export default AIChat;
