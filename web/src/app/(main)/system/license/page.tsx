"use client";

import * as React from "react";

import { CheckCircle2Icon, CopyIcon, KeyRoundIcon, LockIcon, ShieldCheckIcon, XCircleIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { LicenseStatus } from "@/lib/types";

function fmtDate(unix?: number): string {
  if (!unix) return "—";
  try {
    return new Date(unix * 1000).toISOString().slice(0, 10);
  } catch {
    return "—";
  }
}

export default function SystemLicensePage() {
  "use no memo";
  const [status, setStatus] = React.useState<LicenseStatus | null>(null);
  const [code, setCode] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      setStatus(await api.license());
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to load license");
    } finally {
      setLoaded(true);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const copy = React.useCallback((text: string) => {
    navigator.clipboard?.writeText(text).then(
      () => toast.success("Copied"),
      () => toast.error("Copy failed"),
    );
  }, []);

  const activate = React.useCallback(async () => {
    const c = code.trim();
    if (!c) {
      toast.error("Paste a license code first");
      return;
    }
    setBusy(true);
    try {
      const next = await api.activateLicense(c);
      setStatus(next);
      setCode("");
      if (next.licensed) toast.success("License activated — all features unlocked");
      else toast.error(next.reason || "License not accepted");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Activation failed");
    } finally {
      setBusy(false);
    }
  }, [code]);

  const deactivate = React.useCallback(async () => {
    if (!confirm("Deactivate the current license? The platform will revert to the locked (read-only) state.")) return;
    setBusy(true);
    try {
      setStatus(await api.activateLicense(""));
      toast.success("License deactivated");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Deactivation failed");
    } finally {
      setBusy(false);
    }
  }, []);

  const licensed = status?.licensed ?? false;
  const expiringSoon = typeof status?.days_left === "number" && status.days_left >= 0 && status.days_left <= 14;

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-4 p-4">
      <div className="flex items-center gap-2">
        <KeyRoundIcon className="size-5" />
        <h1 className="text-xl font-semibold">License</h1>
      </div>

      {/* Status banner */}
      <Card className={licensed ? "border-emerald-500/40" : "border-amber-500/40"}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {licensed ? (
              <>
                <CheckCircle2Icon className="size-5 text-emerald-500" />
                Licensed — all features unlocked
              </>
            ) : (
              <>
                <LockIcon className="size-5 text-amber-500" />
                Locked — a license key is required
              </>
            )}
          </CardTitle>
          <CardDescription>
            {licensed
              ? "This installation is activated. Enter a new code to replace it."
              : "Reads are available, but running tasks, workflows and agents is disabled until a valid key is activated."}
          </CardDescription>
        </CardHeader>
        {loaded && status && (
          <CardContent className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
            <Field label="Tier" value={(status.tier || "community").toUpperCase()} />
            <Field label="Customer" value={status.customer || "—"} />
            <Field
              label="Expires"
              value={
                status.activated
                  ? status.expires_at
                    ? `${fmtDate(status.expires_at)}${
                        typeof status.days_left === "number"
                          ? ` (${status.days_left >= 0 ? `${status.days_left}d left` : "expired"})`
                          : ""
                      }`
                    : "never"
                  : "—"
              }
              tone={status.expired ? "bad" : expiringSoon ? "warn" : undefined}
            />
            <Field label="Machine binding" value={status.machine_bound ? "bound to this machine" : "any machine"} />
            <Field
              label="Limits"
              value={
                status.limits
                  ? `targets ${status.limits.targets || "∞"} · tasks ${status.limits.tasks || "∞"} · tokens ${
                      status.limits.tokens || "∞"
                    }`
                  : "—"
              }
            />
            <Field
              label="Features"
              value={status.features && status.features.length > 0 ? status.features.join(", ") : "all"}
            />
            {!licensed && status.reason && (
              <div className="sm:col-span-2 flex items-center gap-2 text-amber-600 dark:text-amber-400">
                <XCircleIcon className="size-4" />
                <span>{status.reason}</span>
              </div>
            )}
          </CardContent>
        )}
      </Card>

      {/* Machine ID — the operator sends this to the vendor for a machine-bound code */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheckIcon className="size-4" />
            Machine ID
          </CardTitle>
          <CardDescription>
            Send this to your vendor to receive a code bound to this machine (or request an any-machine code).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-2">
          <code className="flex-1 overflow-x-auto rounded bg-muted px-3 py-2 font-mono text-xs">
            {status?.machine_id || "…"}
          </code>
          <Button
            type="button"
            variant="outline"
            size="icon"
            onClick={() => status?.machine_id && copy(status.machine_id)}
            disabled={!status?.machine_id}
            title="Copy machine ID"
          >
            <CopyIcon className="size-4" />
          </Button>
        </CardContent>
      </Card>

      {/* Activate */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Activate a license code</CardTitle>
          <CardDescription>Paste the code your vendor sent. It is verified offline — no internet required.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste license code here…"
            className="min-h-24 font-mono text-xs"
            spellCheck={false}
          />
          <div className="flex gap-2">
            <Button type="button" onClick={activate} disabled={busy || !code.trim()}>
              {busy ? "Activating…" : "Activate"}
            </Button>
            {status?.activated && (
              <Button type="button" variant="outline" onClick={deactivate} disabled={busy}>
                Deactivate
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function Field({ label, value, tone }: { label: string; value: string; tone?: "bad" | "warn" }) {
  const color = tone === "bad" ? "text-red-600 dark:text-red-400" : tone === "warn" ? "text-amber-600 dark:text-amber-400" : "";
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={`font-medium ${color}`}>{value}</span>
    </div>
  );
}
