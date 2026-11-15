package server

// Recon-first task launch: when a task opts in (recon_first), run a recon
// WORKFLOW first, compile the run's recon-brief, seed it as the task's first
// intent, and only THEN start the pentest engine — so the worker begins with the
// mapped surface in hand instead of guessing to re-scan. Deterministic and cheap
// on LLM (the mechanical recon is done server-side). Every failure branch falls
// back to the normal launchTask path so a task is never stranded.
//
// Reuses integration C (POST /api/v1/runs, scope-guarded by targetExists) and
// integration A (GET /api/v1/runs/{id}/recon-brief) over the mounted k1z API.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// pendingPushBack maps a recon run id -> task id for runs an agent launched via
// run_workflow but may NOT consume inline (wait=false, or a run slower than the
// blocking cap). When such a run finishes, OnReconRunFinished seeds its brief back
// into the originating task, so a slow run is never silently skipped.
var pendingPushBack sync.Map // runID string -> taskID string

func registerPushBack(runID, taskID string) {
	if runID != "" && taskID != "" && taskID != "0" {
		pendingPushBack.Store(runID, taskID)
	}
}

// OnReconRunFinished is wired to the k1z runner's RunFinishedHook, which fires on
// every terminal outcome (completed, failed, cancelled). If the finished run was
// registered for push-back, fetch its recon brief and seed it back into the task
// that launched it (reviving a terminal task), so results that landed after the
// agent moved on — even partial results from a failed run — are acted on instead
// of lost. No-ops when the run wasn't registered or produced no brief.
func (s *Server) OnReconRunFinished(runID string) {
	defer func() { _ = recover() }()
	// Auto-aggregate this run's target assets into the rich inventory FIRST, for
	// EVERY finished run (not just push-back ones), so no workflow asset is ever
	// missed even when no agent runs the sync. Best-effort, idempotent.
	s.autoPromoteRunAssets(runID)
	v, ok := pendingPushBack.LoadAndDelete(runID)
	if !ok {
		return
	}
	taskID, _ := v.(string)
	t, ok := s.m.Task(taskID)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	data, code, err := s.reconJSON(ctx, "GET", "/api/v1/runs/"+url.PathEscape(runID)+"/recon-brief", nil)
	if err != nil || code >= 300 {
		return
	}
	brief := reconBriefMarkdown(data)
	if strings.TrimSpace(brief) == "" {
		return
	}
	s.seedIntentText(t, "Recon run "+runID+" completed — its results arrived AFTER the earlier recon call:\n\n"+brief+
		"\n\nReview and act on any uncovered surface from this run; do not skip it.")
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: "📥 Recon run " + runID + " completed — results pushed back into the task."})
	s.reviveTask(t)
}

// autoPromoteRunAssets resolves a finished run's target and promotes all of that
// target's workflow-discovered assets into the rich inventory via the shared sync.
// Wired into OnReconRunFinished so aggregation is automatic and complete, never
// dependent on an agent being run. Best-effort: logs the counts, swallows errors.
func (s *Server) autoPromoteRunAssets(runID string) {
	ctx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
	defer cancel()
	data, code, err := s.reconJSON(ctx, "GET", "/api/v1/runs/"+url.PathEscape(runID), nil)
	if err != nil || code >= 300 {
		return
	}
	var r struct {
		Target string `json:"target"`
	}
	_ = json.Unmarshal(data, &r)
	target := strings.TrimSpace(strings.ToLower(r.Target))
	if target == "" {
		return
	}
	counts, errs := s.runReconAssetSync(ctx, target, 0)
	// #1 deterministic JS → assets: download the target's JS and extract endpoints in
	// code (no LLM), so JS endpoints land in the inventory on every run regardless.
	jsAdded, jsSecrets, jsErrs := s.syncJSEndpoints(ctx, s.assetStore(), target)
	wafTagged := s.detectWAFCDN(ctx, s.assetStore(), target) // #6 tag WAF/CDN per host
	log.Printf("[asset-sync] run %s (%s) promoted: %v + js_endpoints=%d js_secrets=%d waf_cdn_tagged=%d (errs=%d/%d)",
		runID, target, counts, jsAdded, jsSecrets, wafTagged, len(errs), jsErrs)
	// Then kick the intelligent layer: auto-run the endpoint_recon agent on
	// this domain (deep JS extraction + request reconstruction + replay + appraisal),
	// in the background, so it runs per task/per domain without anyone opening a chat.
	s.maybeLaunchEndpointAgent(target)
}

// endpointReconLaunched throttles the per-target auto-launch of the endpoint agent so
// repeated run-finished events for the same domain don't spawn duplicate background
// reconstructions. target -> last launch time.
var endpointReconLaunched sync.Map

// maybeLaunchEndpointAgent fires a background endpoint_recon agent run against
// target, gated by the endpoint_reconstructor setting and throttled per target. The
// agent's own tools are gated by the same setting, so when it runs they are live.
func (s *Server) maybeLaunchEndpointAgent(target string) {
	if target == "" || !s.m.pg.GetBool(settingEndpointReconstructor, false) {
		return
	}
	now := time.Now()
	if v, ok := endpointReconLaunched.Load(target); ok {
		if last, _ := v.(time.Time); now.Sub(last) < 15*time.Minute {
			return // recently launched for this target — skip duplicate
		}
	}
	endpointReconLaunched.Store(target, now)
	s.StartTriggeredRun(
		"endpoint_recon",
		"endpoint reconstruction - "+target,
		"A recon run just finished for "+target+". Automatically reconstruct & appraise all endpoints for this target, ESPECIALLY those in JavaScript, and write them into the asset inventory. "+
			"Start with sync_recon_assets("+target+"). Then enumerate EVERY live host via recon_assets — all subdomains AND vhost-bound hosts, not just the apex. For EACH host be PORT-AWARE: read its open ports (recon_findings kind=port / recon_graph) and probe it on every open web port (80/443/8080/8443/8000/…), since a vhost only adds a Host header to its IP and may serve only on a non-standard port. On each (host, open port) find .js files and extract_js_endpoints each, reconstruct full requests, replay to observe real status, and upsert_endpoint_asset with full params/status/source/appraisal. Be thorough and professional; work only in scope.",
		0, false, "", "",
	)
	log.Printf("[endpoint-recon] auto-launched endpoint_recon agent for %s", target)
}

const (
	defaultReconWorkflow = "02-full-recon-artex.yaml" // discovery-only: hands names to the agent, which resolves+probes (matches recon-first model); has all direct-API sources (fofa/leakix/subdomain.center/...) that 01 lacks
	reconFirstMaxWait    = 90 * time.Minute           // total cap across all recon workflows; then fall back
	reconPollEvery       = 15 * time.Second
)

// domainRe extracts the first plausible host/domain from free text (good enough
// for pulling a target out of a goal/description).
var domainRe = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b`)

func extractTargetDomain(ss ...string) string {
	for _, s := range ss {
		if m := domainRe.FindString(strings.TrimSpace(s)); m != "" {
			return strings.ToLower(m)
		}
	}
	return ""
}

// launchTaskReconFirst runs a recon workflow first, seeds the brief, then starts
// the engine. Asynchronous — the HTTP handler returns immediately. Any failure
// (no target, out-of-scope, workflow error, timeout, empty brief, panic) emits a
// visible notice and falls back to the standard launchTask path.
func (s *Server) launchTaskReconFirst(t *Task, req createTaskReq) {
	seedText := req.Description + " " + req.Goal

	target := strings.ToLower(strings.TrimSpace(req.ReconTarget))
	if target == "" {
		target = extractTargetDomain(req.Goal, req.Description)
	}
	workflowSpec := strings.TrimSpace(req.ReconWorkflow) // "" (default), a name, "a,b", or "all"

	if target == "" {
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: "Recon-first: could not determine a target from the goal/description — running the standard flow."})
		s.launchTask(t, seedText, false)
		return
	}

	// Scope guard (same rule as the run_workflow tool): only recon a REGISTERED
	// target so the scan stays inside a defined deny-wins scope.
	ctx0, cancel0 := context.WithTimeout(s.ctx, 10*time.Second)
	registered := targetExists(ctx0, target)
	cancel0()
	if !registered {
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("Recon-first: target %q is not registered (Targets) — skipping auto-recon, running the standard flow. Register a scope and try again.", target)})
		s.launchTask(t, seedText, false)
		return
	}

	// Hold a task operation slot but DON'T start the engine yet; seed the root
	// asset so the task has context while recon runs.
	if !s.engine.beginTaskOperation(t.ID) {
		return
	}
	s.seed(t, seedText)
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("⏳ Recon-first: preparing recon on %s…", target)})

	go func() {
		defer s.engine.decInflight(t.ID)
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[recon-first] task %s panic: %v — fallback", t.ID, rec)
				s.reconFallbackAdmit(t)
			}
		}()

		ctx, cancel := context.WithTimeout(s.ctx, reconFirstMaxWait)
		defer cancel()

		workflows := s.resolveReconWorkflows(ctx, workflowSpec)
		var briefs []string
		for _, wf := range workflows {
			runID, err := s.reconStartRun(ctx, target, wf, maxWorkflowVars(ctx, wf)) // full options (minus opted-out pivots)
			if err != nil {
				s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
					Summary: fmt.Sprintf("⚠️ Recon-first: workflow %s could not start (%s) — skipping.", wf, err.Error())})
				continue
			}
			s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
				Summary: fmt.Sprintf("⏳ Recon-first: %s (run %s) is running…", wf, runID)})
			if err := s.reconWaitDone(ctx, runID); err != nil {
				s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
					Summary: fmt.Sprintf("⚠️ Recon-first: %s — %s", wf, err.Error())})
				if ctx.Err() != nil {
					break
				}
				continue
			}
			if b, err := s.reconFetchBrief(ctx, runID); err == nil && strings.TrimSpace(b) != "" {
				briefs = append(briefs, fmt.Sprintf("## Recon workflow: %s (run %s)\n\n%s", wf, runID, strings.TrimSpace(b)))
			}
			if ctx.Err() != nil {
				break
			}
		}

		if len(briefs) == 0 {
			s.reconAbort(t, "no recon workflow completed")
			return
		}

		intent := strings.Join(briefs, "\n\n---\n\n") + "\n\n---\nOBJECTIVE: Base your work ENTIRELY on the recon surface above. " +
			"Prioritize broken access control/IDOR, SSRF, auth/JWT/OAuth, injection (SQLi/SSTI/command) and file upload on the live hosts. " +
			"Validate with a minimal non-destructive PoC; no DoS. Stay STRICT in-scope (deny-wins). " +
			"For details call recon_findings/recon_assets; when you find new surface, call list_workflows to pick a fitting workflow, or the recon-first-pentest skill."
		s.seedIntentText(t, intent)
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("✅ Recon done (%d/%d workflows) — brief loaded, starting pentest.", len(briefs), len(workflows))})

		if _, err := s.admitTask(t, "bootstrap"); err != nil {
			log.Printf("[recon-first] task %s admit error: %v", t.ID, err)
		}
	}()
}

// launchTaskReconParallel starts the agent IMMEDIATELY (its own recon-engine loop
// drives subdomain discovery + exploitation right away) and, in parallel, kicks
// off the recon workflow(s) in the background for the task's target. Each run is
// registered for push-back, so when a workflow finishes OnReconRunFinished
// promotes its assets and seeds the fuller surface back into the running task —
// the agent absorbs it without ever waiting. Scope-guarded: the background
// workflow only runs for a REGISTERED target; otherwise the agent still runs.
// This is the default for UI-created tasks.
func (s *Server) launchTaskReconParallel(t *Task, req createTaskReq) {
	seedText := req.Description + " " + req.Goal
	// 1) agent now — do not wait for any workflow.
	s.launchTask(t, seedText, req.SeedFirstIntent != nil && *req.SeedFirstIntent)

	// 2) recon workflow(s) in the background, feeding results back as they land.
	target := strings.ToLower(strings.TrimSpace(req.ReconTarget))
	if target == "" {
		target = extractTargetDomain(req.Goal, req.Description)
	}
	if target == "" {
		return
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[recon-parallel] task %s panic: %v", t.ID, rec)
			}
		}()
		ctx0, cancel0 := context.WithTimeout(s.ctx, 10*time.Second)
		registered := targetExists(ctx0, target)
		cancel0()
		if !registered {
			s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
				Summary: fmt.Sprintf("Recon (song song): target %q chua dang ky trong Targets - bo qua workflow nen; agent van tu recon.", target)})
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, reconFirstMaxWait)
		defer cancel()
		for _, wf := range s.resolveReconWorkflows(ctx, strings.TrimSpace(req.ReconWorkflow)) {
			runID, err := s.reconStartRun(ctx, target, wf, maxWorkflowVars(ctx, wf))
			if err != nil {
				s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
					Summary: fmt.Sprintf("Recon (song song): workflow %s khong khoi dong duoc (%s).", wf, err.Error())})
				continue
			}
			registerPushBack(runID, t.ID)
			s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
				Summary: fmt.Sprintf("Recon (song song): %s (run %s) dang chay nen - ket qua se tu day vao task.", wf, runID)})
		}
	}()
}

// resolveReconWorkflows turns the recon_workflow spec into a concrete list:
// "all" → every available workflow; a comma-separated list → those names; empty →
// the default single pipeline.
func (s *Server) resolveReconWorkflows(ctx context.Context, spec string) []string {
	spec = strings.TrimSpace(spec)
	if strings.EqualFold(spec, "all") {
		if all := s.reconListWorkflows(ctx); len(all) > 0 {
			return all
		}
		return []string{defaultReconWorkflow}
	}
	if spec == "" {
		return []string{defaultReconWorkflow}
	}
	var out []string
	for _, p := range strings.Split(spec, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{defaultReconWorkflow}
	}
	return out
}

// reconListWorkflows returns the available workflow file names from the Runner.
func (s *Server) reconListWorkflows(ctx context.Context) []string {
	data, code, err := s.reconJSON(ctx, "GET", "/api/v1/workflows", nil)
	if err != nil || code >= 300 {
		return nil
	}
	var names []string
	_ = json.Unmarshal(data, &names)
	return names
}

// reconFallbackAdmit starts the engine for a task whose recon-first pre-step bailed
// out after the operation slot was already taken (so launchTask's own
// beginTaskOperation is not reused). Mirrors launchTask's tail.
func (s *Server) reconFallbackAdmit(t *Task) {
	if _, err := s.admitTask(t, "bootstrap"); err != nil {
		log.Printf("[recon-first] task %s fallback admit error: %v", t.ID, err)
	}
}

func (s *Server) reconAbort(t *Task, why string) {
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: "⚠️ Recon-first skipped (" + why + ") — running the standard flow."})
	s.reconFallbackAdmit(t)
}

// ── HTTP helpers against the local k1z API (ReconAPIBase set from main) ───────

func (s *Server) reconJSON(ctx context.Context, method, path string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, ReconAPIBase+path, body)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return data, resp.StatusCode, nil
}

func (s *Server) reconStartRun(ctx context.Context, target, workflow string, vars []string) (string, error) {
	payload := map[string]any{"workflow": workflow, "target": target}
	if len(vars) > 0 {
		payload["vars"] = vars
	}
	body, _ := json.Marshal(payload)
	data, code, err := s.reconJSON(ctx, "POST", "/api/v1/runs", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(data)))
	}
	var r struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.ID == "" {
		return "", fmt.Errorf("no run id in the response")
	}
	return r.ID, nil
}

func (s *Server) reconWaitDone(ctx context.Context, runID string) error {
	tick := time.NewTicker(reconPollEvery)
	defer tick.Stop()
	for {
		data, code, err := s.reconJSON(ctx, "GET", "/api/v1/runs/"+runID, nil)
		if err == nil && code < 300 {
			var r struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(data, &r)
			switch strings.ToLower(r.Status) {
			case "completed", "done", "finished", "success":
				return nil
			case "failed", "error", "paused", "cancelled", "canceled", "timeout":
				return fmt.Errorf("run ended with status=%s", r.Status)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("recon wait timed out (%s)", reconFirstMaxWait)
		case <-tick.C:
		}
	}
}

// reconFetchBrief reads GET /runs/{id}/recon-brief. The k1z handler returns JSON
// with a "markdown" field (handleReconBrief); accept a raw-markdown body too.
func (s *Server) reconFetchBrief(ctx context.Context, runID string) (string, error) {
	data, code, err := s.reconJSON(ctx, "GET", "/api/v1/runs/"+runID+"/recon-brief", nil)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("HTTP %d", code)
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		var r struct {
			Markdown string `json:"markdown"`
		}
		if json.Unmarshal(data, &r) == nil && strings.TrimSpace(r.Markdown) != "" {
			return r.Markdown, nil
		}
	}
	return string(data), nil
}
