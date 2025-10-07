import { Badge } from "@/components/ui/badge";

interface SeverityBadgeProps {
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
}

export const SeverityBadge = ({ severity }: SeverityBadgeProps) => {
  const variants = {
    Critical: "bg-critical text-white",
    High: "bg-high text-white",
    Medium: "bg-medium text-white",
    Low: "bg-low text-white",
    Info: "bg-info text-white",
  };

  return (
    <Badge className={`${variants[severity]} font-semibold`}>
      {severity}
    </Badge>
  );
};
