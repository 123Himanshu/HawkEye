import { LucideIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  variant?: "default" | "critical" | "warning" | "success";
}

export const StatCard = ({ title, value, icon: Icon, trend, variant = "default" }: StatCardProps) => {
  const variantClasses = {
    default: "border-border",
    critical: "border-critical/30 card-glow",
    warning: "border-medium/30",
    success: "border-low/30",
  };

  return (
    <Card className={`${variantClasses[variant]} transition-all hover:scale-105`}>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-muted-foreground">{title}</p>
            <p className="text-3xl font-bold mt-2">{value}</p>
            {trend && (
              <p className="text-xs text-muted-foreground mt-1">{trend}</p>
            )}
          </div>
          <Icon className="h-12 w-12 text-primary/50" />
        </div>
      </CardContent>
    </Card>
  );
};
