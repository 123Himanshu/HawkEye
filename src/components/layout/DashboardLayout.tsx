import { ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { Shield, LayoutDashboard, Target, FileText, Activity, Settings, LogOut, User } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface DashboardLayoutProps {
  children: ReactNode;
}

const DashboardLayout = ({ children }: DashboardLayoutProps) => {
  const location = useLocation();
  const { user, signOut } = useAuth();

  const navItems = [
    { name: "Dashboard", path: "/dashboard", icon: LayoutDashboard },
    { name: "Scan Config", path: "/scan-config", icon: Activity },
    { name: "Targets & Scans", path: "/targets", icon: Target },
    { name: "Reports", path: "/reports", icon: FileText },
    { name: "Settings", path: "/settings", icon: Settings },
  ];

  return (
    <div className="flex min-h-screen w-full bg-background">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-card flex flex-col relative">
        <div className="flex items-center gap-2 p-6 border-b border-border">
          <Shield className="h-8 w-8 text-primary" />
          <span className="text-xl font-bold">HawkEye</span>
        </div>
        <nav className="p-4 space-y-2 flex-1 overflow-y-auto pb-32">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${isActive
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted text-muted-foreground hover:text-foreground"
                  }`}
              >
                <Icon className="h-5 w-5" />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>

        {/* User Profile & Logout */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-border bg-card">
          <div className="flex items-center gap-3 mb-3 px-2">
            <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
              <User className="h-5 w-5 text-primary" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{user?.email}</p>
              <Badge variant="secondary" className="text-xs">
                Security Analyst
              </Badge>
            </div>
          </div>
          <Button
            onClick={signOut}
            variant="outline"
            className="w-full"
          >
            <LogOut className="h-4 w-4 mr-2" />
            Sign Out
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <div className="p-8">{children}</div>
      </main>
    </div>
  );
};

export default DashboardLayout;
