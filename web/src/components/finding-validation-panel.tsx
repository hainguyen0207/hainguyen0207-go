"use client";

import * as React from "react";

import Link from "next/link";

import { BilingualView } from "@/components/bilingual-view";
import { CopyButton } from "@/components/copy-button";
import { Markdown, extractHttpRequests } from "@/components/markdown";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { VerificationBadge } from "@/components/verification-badge";
import { api } from "@/lib/api";
import type { FindingValidation, FindingVerification } from "@/lib/types";

// Full output of the finding validator / escalator for one finding: verdict,
// tier, demonstrated severity, the reasoning summary and the Markdown evidence
// (reproduction steps, observed requests/responses), newest round first.
function toVerification(v: FindingValidation): FindingVerification {
  let state: FindingVerification["state"] = "failed";
  if (v.status === "pending") state = "queued";
  else if (v.status === "running") state = "running";
  else if (v.status === "stopped") state = "paused";
  else if (v.status === "completed" && v.verdict === "passed") state = "verified";
  else if (v.status === "completed" && v.verdict === "rejected") state = "rejected";
  else if (v.status === "completed" && v.verdict === "escalate") state = "escalating";
  return {
    state,
    stage: v.stage,
    verdict: v.verdict,
    tier: v.tier,
    severity_confirmed: v.severity_confirmed,
    summary: v.summary,
    error: v.error,
    at: (v.finished_at || v.started_at || v.created_at || "").replace("T", " ").slice(0, 16),
  };
}

export function FindingValidationPanel({ findingId }: { findingId: string }) {
  const [items, setItems] = React.useState<FindingValidation[] | null>(null);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    if (!findingId) return;
    let alive = true;
    const load = () =>
      api
        .findingValidations(findingId)
        .then((r) => alive && (setItems(r), setError("")))
        .catch((e) => alive && setError((e as Error).message));
    load();
    const t = setInterval(load, 15000); // a running round updates by itself
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [findingId]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Kết quả xác minh (validator)</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {error && <p className="text-destructive text-sm">{error}</p>}
        {items === null && !error && <p className="text-muted-foreground text-sm">Đang tải…</p>}
        {items && items.length === 0 && (
          <p className="text-muted-foreground text-sm">
            Chưa có lượt xác minh nào. Validator chỉ chạy cho lỗi từ medium trở lên của task bật “Verify finding”, sau khi
            reporter viết xong report.
          </p>
        )}
        {items?.map((v, i) => {
          const ver = toVerification(v);
          return (
            <div key={v.id} className="flex flex-col gap-2 rounded-lg border p-3">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="secondary">{v.stage === "escalator" ? "Escalator" : "Validator"} · lượt #{v.id}</Badge>
                <VerificationBadge v={ver} />
                {v.tier && <Badge variant="outline">Xếp loại: {v.tier}</Badge>}
                {v.severity_confirmed && <Badge variant="outline">Mức đã chứng minh: {v.severity_confirmed}</Badge>}
                <span className="text-muted-foreground text-xs">{ver.at}</span>
                {extractHttpRequests(v.evidence).length > 0 && (
                  <CopyButton
                    text={extractHttpRequests(v.evidence).join("\n\n")}
                    label={`Copy ${extractHttpRequests(v.evidence).length} HTTP request`}
                    successMessage="Đã copy các HTTP request"
                    className="ml-auto"
                  />
                )}
                {v.conversation_id ? (
                  <Link href={`/chat?c=${v.conversation_id}`} className="ml-auto text-primary text-xs underline">
                    Mở phiên của validator
                  </Link>
                ) : null}
              </div>
              {v.error && <p className="text-amber-600 text-sm dark:text-amber-400">Lỗi: {v.error}</p>}
              {v.notes && v.stage === "escalator" && (
                <p className="text-muted-foreground text-xs whitespace-pre-wrap">Bàn giao từ validator: {v.notes}</p>
              )}
              {(v.summary || v.evidence) && (
                <BilingualView kind="validation" refId={v.id}>
                  {v.summary && <p className="text-sm whitespace-pre-wrap break-words">{v.summary}</p>}
                  {v.evidence && (
                    <details open={i === 0} className="rounded-md bg-muted/30 p-2">
                      <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
                        Evidence / các bước tái hiện
                      </summary>
                      <div className="mt-2">
                        <Markdown text={v.evidence} />
                      </div>
                    </details>
                  )}
                </BilingualView>
              )}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
