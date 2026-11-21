"use client";

import * as React from "react";

import { Languages, Loader2, RefreshCw } from "lucide-react";

import { Markdown } from "@/components/markdown";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";

// Shows the English original (children) with an on-demand Vietnamese translation
// beside it (stacked on narrow screens). The translation is made by the backend
// with a cheap model the first time the button is clicked, then cached; an
// already cached one shows up automatically.
export function BilingualView({
  kind,
  refId,
  children,
}: {
  kind: "finding_report" | "validation";
  refId: number | string;
  children: React.ReactNode;
}) {
  const [vi, setVi] = React.useState("");
  const [stale, setStale] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [show, setShow] = React.useState(true);

  React.useEffect(() => {
    let alive = true;
    setVi("");
    setStale(false);
    api
      .getTranslation(kind, refId)
      .then((r) => {
        if (!alive) return;
        setVi(r.content || "");
        setStale(!!r.stale);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [kind, refId]);

  const translate = async () => {
    setBusy(true);
    setError("");
    try {
      const r = await api.createTranslation(kind, refId);
      setVi(r.content || "");
      setStale(false);
      setShow(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const hasVi = vi !== "" && show;
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center justify-end gap-2">
        {error && <span className="text-destructive text-xs">{error}</span>}
        {vi && stale && <span className="text-amber-600 text-xs dark:text-amber-400">Bản gốc đã đổi, bản dịch có thể cũ</span>}
        {vi ? (
          <>
            <Button size="sm" variant="ghost" onClick={() => setShow((s) => !s)}>
              <Languages className="size-4" />
              {show ? "Ẩn tiếng Việt" : "Hiện tiếng Việt"}
            </Button>
            {stale && (
              <Button size="sm" variant="outline" onClick={translate} disabled={busy}>
                {busy ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
                Dịch lại
              </Button>
            )}
          </>
        ) : (
          <Button size="sm" variant="outline" onClick={translate} disabled={busy}>
            {busy ? <Loader2 className="size-4 animate-spin" /> : <Languages className="size-4" />}
            {busy ? "Đang dịch…" : "Dịch tiếng Việt"}
          </Button>
        )}
      </div>
      <div className={hasVi ? "grid gap-4 lg:grid-cols-2" : ""}>
        <div className="min-w-0">
          {hasVi && <p className="text-muted-foreground mb-2 text-xs font-medium uppercase">English (bản gốc)</p>}
          {children}
        </div>
        {hasVi && (
          <div className="min-w-0 border-t pt-4 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-4">
            <p className="text-muted-foreground mb-2 text-xs font-medium uppercase">Tiếng Việt</p>
            <Markdown text={vi} />
          </div>
        )}
      </div>
    </div>
  );
}
