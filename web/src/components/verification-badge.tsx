"use client";

import { CheckCircle2Icon, CircleDashedIcon, CircleSlashIcon, Loader2Icon, PauseCircleIcon, TrendingUpIcon, TriangleAlertIcon, XCircleIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { FindingVerification } from "@/lib/types";
import { cn } from "@/lib/utils";

// VerificationBadge shows whether the finding validator agent has confirmed a
// finding (latest validation round). Hover shows the validator's reasoning.
const STATES: Record<string, { label: string; icon: typeof CheckCircle2Icon; cls: string }> = {
  verified: { label: "Đã xác minh", icon: CheckCircle2Icon, cls: "border-emerald-500/40 text-emerald-600 dark:text-emerald-400" },
  rejected: { label: "Bị bác", icon: XCircleIcon, cls: "border-red-500/40 text-red-600 dark:text-red-400" },
  running: { label: "Đang xác minh", icon: Loader2Icon, cls: "border-sky-500/40 text-sky-600 dark:text-sky-400" },
  queued: { label: "Chờ xác minh", icon: CircleDashedIcon, cls: "border-sky-500/30 text-sky-600/80 dark:text-sky-400/80" },
  escalating: { label: "Đang nâng impact", icon: TrendingUpIcon, cls: "border-amber-500/40 text-amber-600 dark:text-amber-400" },
  failed: { label: "Lỗi xác minh", icon: TriangleAlertIcon, cls: "border-amber-500/40 text-amber-600 dark:text-amber-400" },
  paused: { label: "Tạm dừng", icon: PauseCircleIcon, cls: "border-muted-foreground/30 text-muted-foreground" },
  none: { label: "Chưa xác minh", icon: CircleSlashIcon, cls: "border-muted-foreground/20 text-muted-foreground" },
};

export function VerificationBadge({ v, className }: { v?: FindingVerification | null; className?: string }) {
  const s = STATES[v?.state ?? "none"] ?? STATES.none;
  const Icon = s.icon;
  const tip = v
    ? [
        `${s.label} (${v.stage === "escalator" ? "escalator" : "validator"}, ${v.at})`,
        v.severity_confirmed ? `Mức độ đã chứng minh: ${v.severity_confirmed}` : "",
        v.tier ? `Xếp loại: ${v.tier}` : "",
        v.summary || v.error || "",
      ]
        .filter(Boolean)
        .join("\n")
    : "Agent validator chưa xác minh lỗi này";
  return (
    <Badge variant="outline" title={tip} className={cn("gap-1 whitespace-nowrap font-normal", s.cls, className)}>
      <Icon className={cn("size-3", v?.state === "running" && "animate-spin")} />
      {s.label}
      {v?.state === "verified" && v.severity_confirmed ? ` · ${v.severity_confirmed}` : ""}
    </Badge>
  );
}
