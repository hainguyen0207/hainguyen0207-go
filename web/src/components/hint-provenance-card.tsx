"use client";

import * as React from "react";

import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { HintStats } from "@/lib/types";

const SOURCE_LABEL: Record<string, string> = { kb_hunter: "KB Hunter", operator: "Người vận hành", other: "Khác" };

// Hint -> intent -> finding provenance for one task: how many hints each source
// (KB Hunter, operator) wrote, how many the planner acted on, and what came out.
export function HintProvenanceCard({ taskId }: { taskId: string }) {
  const [data, setData] = React.useState<HintStats | null>(null);
  const [error, setError] = React.useState("");
  const [open, setOpen] = React.useState(false);

  React.useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .taskHintStats(taskId)
        .then((d) => alive && (setData(d), setError("")))
        .catch((e) => alive && setError((e as Error).message));
    load();
    const t = setInterval(load, 60000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [taskId]);

  const sources = Object.entries(data?.summary || {});
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Gợi ý → intent → finding</CardTitle>
        <CardDescription>
          Theo dõi gợi ý (lead của KB Hunter, gợi ý của bạn) đã sinh ra intent nào và ra finding gì. KB chỉ để ưu tiên — agent vẫn phải tự
          test đầy đủ.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {error && <p className="text-destructive text-sm">{error}</p>}
        {!data && !error && <p className="text-muted-foreground text-sm">Đang tải…</p>}
        {data && sources.length === 0 && <p className="text-muted-foreground text-sm">Task này chưa có gợi ý nào.</p>}
        {sources.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-muted-foreground text-xs">
                <tr>
                  <th className="py-1 pr-3 text-left font-medium">Nguồn</th>
                  <th className="py-1 pr-3 text-right font-medium">Gợi ý</th>
                  <th className="py-1 pr-3 text-right font-medium">Đã dùng</th>
                  <th className="py-1 pr-3 text-right font-medium">Intent</th>
                  <th className="py-1 pr-3 text-right font-medium">Finding</th>
                  <th className="py-1 text-right font-medium">Đã xác nhận</th>
                </tr>
              </thead>
              <tbody>
                {sources.map(([src, a]) => (
                  <tr key={src} className="border-t">
                    <td className="py-1 pr-3">{SOURCE_LABEL[src] || src}</td>
                    <td className="py-1 pr-3 text-right tabular-nums">{a.Hints}</td>
                    <td className="py-1 pr-3 text-right tabular-nums">{a.Used}</td>
                    <td className="py-1 pr-3 text-right tabular-nums">{a.Intents}</td>
                    <td className="py-1 pr-3 text-right tabular-nums">{a.Findings}</td>
                    <td className="py-1 text-right tabular-nums">{a.Confirmed}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.hints.length > 0 && (
          <button type="button" className="text-primary self-start text-xs underline" onClick={() => setOpen((o) => !o)}>
            {open ? "Ẩn chi tiết" : `Xem chi tiết ${data.hints.length} gợi ý`}
          </button>
        )}
        {open &&
          data?.hints.map((h) => (
            <div key={h.id} className="flex flex-col gap-1 rounded-md border p-2 text-xs">
              <div className="flex flex-wrap items-center gap-1.5">
                <Badge variant="secondary">#{h.id}</Badge>
                <Badge variant="outline">{SOURCE_LABEL[h.source] || h.source}</Badge>
                <span className="text-muted-foreground">{h.created_at}</span>
                <span className="text-muted-foreground ml-auto">
                  {h.intents.length} intent · {h.findings.length} finding
                </span>
              </div>
              <p className="whitespace-pre-wrap break-words">{h.text.length > 400 ? h.text.slice(0, 400) + "…" : h.text}</p>
              {h.intents.map((it) => (
                <p key={it.id} className="text-muted-foreground pl-2">
                  ↳ intent #{it.id} <Badge variant="outline">{it.state}</Badge> {it.summary}
                </p>
              ))}
              {h.findings.map((f) => (
                <p key={f.id} className="pl-4">
                  ⇒{" "}
                  <Link href={`/function/findings/detail?id=${f.id}`} className="text-primary underline">
                    finding #{f.id}
                  </Link>{" "}
                  [{f.severity}] {f.name} — {f.status}
                  {f.verdict ? ` · validator: ${f.verdict}${f.severity_confirmed ? ` (${f.severity_confirmed})` : ""}` : ""}
                </p>
              ))}
            </div>
          ))}
      </CardContent>
    </Card>
  );
}
