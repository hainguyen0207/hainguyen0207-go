package server

// Ported from ScopeWeaver/bcpen (AGPL-3.0, an ARTEX derivative): the pre-report
// finding gate. Extended here with an AUTOMATIC flow (validate every finding once
// its report is saved) and with Telegram delivery gated on the verdict.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/notify"
	actool "github.com/Autumn-27/norma/tool"
)

// The pre-report finding gate. Two separate conversation agents run against a
// finding with opposing default stances (see agent.ValidatorDefaultPrompt /
// agent.EscalatorDefaultPrompt): the validator (disbelief) decides passed /
// rejected / escalate; an escalate is handed off automatically to the escalator
// (belief), which resolves it to passed or rejected. Only a passed verdict admits
// the finding to a deliverable report (report.Input.Verdicts).

func (s *Server) listActiveFindingValidations(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	items, err := pg.ListActiveFindingValidations(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"validations": items})
}

func (s *Server) listFindingValidations(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	items, err := pg.ListFindingValidations(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"validations": items})
}

// startFindingValidation launches the validator stage for a finding. The
// escalator stage is never launched directly from here — it is spawned only as
// the automatic handoff of a validator that returned 'escalate'.
func (s *Server) startFindingValidation(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var req struct {
		Notes string `json:"notes"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	req.Notes = strings.TrimSpace(req.Notes)
	if utf8.RuneCountInString(req.Notes) > 4000 {
		writeErr(w, 400, "validation notes are limited to 4000 characters")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	if !s.validationAgentReady(w, db.FindingValidatorAgentKey, "validator") {
		return
	}
	if s.ctx.Err() != nil {
		writeErr(w, 503, "server is shutting down")
		return
	}
	v, conv, created, err := pg.CreateFindingValidation(r.Context(), id, "validator", req.Notes)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "finding not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if created {
		s.dispatchValidation(conv, v.InitialMessage())
	}
	code := http.StatusOK
	if created {
		code = http.StatusAccepted
	}
	writeJSON(w, code, map[string]any{"validation": v, "created": created})
}

// validationAgentReady checks the given stage's agent exists, is enabled, and has
// both gate tools bound; it writes the error response itself and returns false on
// any gap. label is the human stage name for the message.
func (s *Server) validationAgentReady(w http.ResponseWriter, agentKey, label string) bool {
	a, err := s.m.pg.GetAgentByKey(agentKey)
	if err != nil {
		writeErr(w, 500, err.Error())
		return false
	}
	if a == nil || !a.Enabled {
		writeErr(w, 409, "the "+label+" agent does not exist or is not enabled; configure it under Agent management")
		return false
	}
	for _, key := range []string{"get_finding_validation_context", "record_finding_validation_result"} {
		t, err := s.m.pg.GetTool(key)
		if err != nil {
			writeErr(w, 500, err.Error())
			return false
		}
		if t == nil || !t.Enabled || !slices.Contains(t.Agents, a.Key) {
			writeErr(w, 409, "enable and bind the tool for the "+label+" agent: "+key)
			return false
		}
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: a.Key}) == nil {
		writeErr(w, 503, s.chatUnavailableReason())
		return false
	}
	return true
}

// dispatchValidation marks the conversation busy and runs its first turn, the
// same handoff startFindingRetest uses.
func (s *Server) dispatchValidation(conv *db.Conversation, msg string) {
	busyKey := s.convBusyKey(conv.ID)
	s.chatMu.Lock()
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()
	s.runConversation(conv, msg, busyKey)
}

// Both tools derive the finding from server-owned conversation context; tool
// arguments cannot redirect a result into a different finding or conversation.
func (s *Server) findingValidationTools() []actool.CoreTool {
	return []actool.CoreTool{
		roTool("get_finding_validation_context", "Read the finding's filed evidence/PoC snapshot, the validation stage (validator or escalator), any escalate handoff note from the validator, and the current task constraints bound to this validation session. No parameters; only the current session can be read.",
			objSchema(map[string]any{}), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
				v, err := s.m.pg.FindingValidationForConversation(ctx, intercept.ConvIDFromContext(ctx))
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if v == nil {
					return actool.Errorf("the current session is not associated with a validation record; start a validation from the finding details"), nil
				}
				var constraints []db.Constraint
				f, err := s.m.pg.GetFinding(v.FindingID)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if f != nil && f.TaskID != nil {
					if task, ok := s.m.Task(strconv.FormatInt(*f.TaskID, 10)); ok {
						constraints, err = task.Store.ListConstraints()
						if err != nil {
							return actool.Errorf(err.Error()), nil
						}
					}
				}
				out := map[string]any{"validation": v, "current_constraints": constraints}
				// The traffic bound to this finding (request/response bodies via
				// get_finding_traffic) and the task's test accounts: an access-control
				// claim must be re-tested with two genuinely separate identities.
				if list, err := s.m.pg.GetFindingTraffic(ctx, v.FindingID); err == nil && list != nil {
					out["traffic"] = trafficSummary(list)
				}
				if f != nil && f.TaskID != nil {
					if creds, err := s.m.pg.TaskCredentials(*f.TaskID); err == nil && len(creds) > 0 {
						out["task_credentials"] = creds
					}
				}
				return jsonResult(out)
			}),
		wrTool("record_finding_validation_result", "Save the single gate verdict for the current validation session. Run the TIER gate first: tier = finding (confirmed vuln with standalone, demonstrable, independently-rewardable impact) / gadget (a real reproduced primitive with no standalone rewardable impact) / lead (a direction, not yet proven) / note (an observation). passed = tier is finding AND impact independently reproduced AND demonstrated (set severity_confirmed to what you actually proved: critical/high/medium/low — info is not rewardable and cannot pass); rejected = false positive / unreplayable PoC / no impact / out of scope / a gadget-or-below; escalate = a reproduced primitive with a named, unexercised path to higher impact that could not be finished here (validator stage only). A passed verdict marks the finding Confirmed; a rejected verdict marks it a false positive; an escalate hands off to the escalator. A gadget cannot be passed — reject it (salvage as a lead) or escalate. Evidence citing the actual requests/responses/controls is required. Calibration teeth: a default-gadget class — existence/differential oracle (account/email enumeration, 200-vs-404/timing/error diffs), open redirect with no further impact, or version/stack/verbose-error disclosure — has no standalone impact and CANNOT pass as a finding unless you set chained=true, asserting a demonstrated chain to real impact or a cited exception (returns sensitive PII / program policy rewards it / mass-bulk exposure).",
			objSchema(map[string]any{
				"verdict":            map[string]any{"type": "string", "enum": []string{"passed", "rejected", "escalate"}},
				"tier":               map[string]any{"type": "string", "enum": []string{"note", "lead", "gadget", "finding"}},
				"severity_confirmed": strParam("the severity actually demonstrated (required for passed, must be rewardable): critical / high / medium / low"),
				"summary":            strParam("one-line summary of the verdict basis"),
				"evidence":           strParam("Markdown: reproduction steps, actual observations, the impact demonstrated or the reason for rejection; for escalate, the named higher-impact paths, what was tried, and the blocker"),
				"chained":            map[string]any{"type": "boolean", "description": "only for a default-gadget class (oracle/enumeration/open-redirect/version-disclosure): true asserts you demonstrated a chain to real impact or a cited exception (PII/policy/bulk). Without it such a class cannot pass. Ignored for classes that carry standalone impact."},
			}, "verdict", "tier", "summary", "evidence"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				var a struct {
					Verdict           string `json:"verdict"`
					Tier              string `json:"tier"`
					SeverityConfirmed string `json:"severity_confirmed"`
					Summary           string `json:"summary"`
					Evidence          string `json:"evidence"`
					Chained           bool   `json:"chained"`
				}
				if err := json.Unmarshal(in, &a); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if err := s.m.pg.RecordFindingValidationResult(ctx, intercept.ConvIDFromContext(ctx), a.Verdict, a.Tier, a.SeverityConfirmed, a.Summary, a.Evidence, a.Chained); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"saved": true, "verdict": a.Verdict, "tier": a.Tier})
			}),
	}
}

// seedFindingValidators atomically seeds the two editable gate agents and binds
// both gate tools to each. Once seeded, user edits/deletion survive restarts.
func (s *Server) seedFindingValidators() error {
	bindings, _ := json.Marshal([]string{db.FindingValidatorAgentKey, db.FindingEscalatorAgentKey})
	for _, t := range s.findingValidationTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			return err
		}
	}
	const flag = "finding_validator_seed_v1"
	tx, err := s.m.pg.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(7337741011)`); err != nil {
		return err
	}
	var done string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, flag).Scan(&done)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if done == "true" {
		return nil
	}
	agents := []struct {
		key, name, desc, prompt string
	}{
		{db.FindingValidatorAgentKey, "Finding Validator", "The pre-report gate: independently reproduces a candidate finding cold from its written PoC and confirms true impact, defaulting to disbelief.", agent.ValidatorDefaultPrompt},
		{db.FindingEscalatorAgentKey, "Finding Escalator", "Runs on a validator's escalate: pushes a reproduced primitive to its true, higher impact within authorization, defaulting to belief.", agent.EscalatorDefaultPrompt},
	}
	for _, ag := range agents {
		var id int64
		err = tx.QueryRow(`INSERT INTO agents(key,name,description,role,builtin,enabled)
		VALUES ($1,$2,$3,'assistant',false,true)
		ON CONFLICT (key) DO NOTHING RETURNING id`, ag.key, ag.name, ag.desc).Scan(&id)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if id > 0 {
			var pid int64
			if err = tx.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)
			VALUES ($1,1,$2,'built-in default','system') RETURNING id`, id, ag.prompt).Scan(&pid); err != nil {
				return err
			}
			if _, err = tx.Exec(`UPDATE agents SET current_prompt_id=$1 WHERE id=$2`, pid, id); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec(`INSERT INTO settings(key,value) VALUES ($1,'true') ON CONFLICT(key) DO UPDATE SET value='true'`, flag); err != nil {
		return err
	}
	return tx.Commit()
}

// finishValidation seals the round and, when a validator concluded 'escalate',
// hands the finding off to the escalator automatically.
func (s *Server) finishValidation(id int64, status, reason string) {
	if err := s.m.pg.FinishFindingValidation(id, status, reason); err != nil {
		log.Printf("[validation %d] finish: %v", id, err)
		return
	}
	s.maybeSpawnEscalator(id)
	s.afterValidation(id)
	s.pumpValidations()
}

// maybeSpawnEscalator starts the escalator stage when the just-sealed round was a
// completed validator with an 'escalate' verdict. Best-effort: a missing or
// disabled escalator agent is logged, never fatal — the validator's verdict is
// already saved and the finding stays out of the report until a pass.
func (s *Server) maybeSpawnEscalator(validationID int64) {
	v, err := s.m.pg.GetFindingValidation(context.Background(), validationID)
	if err != nil || v == nil {
		if err != nil {
			log.Printf("[validation %d] reload for handoff: %v", validationID, err)
		}
		return
	}
	if v.Stage != "validator" || v.Status != "completed" || v.Verdict != "escalate" {
		return
	}
	a, err := s.m.pg.GetAgentByKey(db.FindingEscalatorAgentKey)
	if err != nil || a == nil || !a.Enabled {
		log.Printf("[validation %d] escalate verdict but escalator unavailable; finding %d awaits manual escalation", validationID, v.FindingID)
		return
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: a.Key}) == nil {
		log.Printf("[validation %d] escalator agent has no usable LLM profile; skipping auto-handoff", validationID)
		return
	}
	ev, conv, created, err := s.m.pg.CreateFindingValidation(context.Background(), v.FindingID, "escalator", v.Summary)
	if err != nil {
		log.Printf("[validation %d] spawn escalator: %v", validationID, err)
		return
	}
	if created {
		s.dispatchValidation(conv, ev.InitialMessage())
	}
}

// ── Automatic flow ───────────────────────────────────────────────────────────
//
//	report saved -> validator (disbelief) -> passed   -> push report (confirmed severity)
//	                                      -> rejected -> no push (finding = false_positive)
//	                                      -> escalate -> escalator -> passed / rejected
//	validator unavailable / failed twice / interrupted escalator -> push marked UNVERIFIED,
//	so a real finding is never silently lost.

const maxAutoValidatorRounds = 2

// validationStageReady is validationAgentReady without an HTTP response: agent
// enabled, both gate tools bound, and a usable LLM.
func (s *Server) validationStageReady(agentKey string) bool {
	a, err := s.m.pg.GetAgentByKey(agentKey)
	if err != nil || a == nil || !a.Enabled {
		return false
	}
	for _, key := range []string{"get_finding_validation_context", "record_finding_validation_result"} {
		t, err := s.m.pg.GetTool(key)
		if err != nil || t == nil || !t.Enabled || !slices.Contains(t.Agents, a.Key) {
			return false
		}
	}
	return s.resolveChatAgent(&db.Conversation{AgentKey: a.Key}) != nil
}

// startAutoValidation launches the validator for a finding whose report was just
// saved. It returns true when the gate owns delivery from here (a round started,
// one is already running, or the finding was already judged) and false when the
// caller must deliver the report itself (validator unavailable).
func (s *Server) startAutoValidation(findingID int64) bool {
	if s.ctx.Err() != nil {
		return true // shutting down: boot recovery re-validates
	}
	ctx := context.Background()
	if done, err := s.m.pg.HasCompletedFindingValidation(ctx, findingID); err == nil && done {
		return true // already judged once; a report rewrite does not re-open the gate
	}
	if !s.validationStageReady(db.FindingValidatorAgentKey) {
		log.Printf("[validation] finding %d: validator unavailable, delivering report unverified", findingID)
		return false
	}
	v, conv, created, err := s.m.pg.CreateFindingValidation(ctx, findingID, "validator", "")
	if err != nil {
		log.Printf("[validation] finding %d: start failed: %v", findingID, err)
		return false
	}
	if created {
		_ = conv
		log.Printf("[validation] finding %d: validator round %d queued", findingID, v.ID)
		s.pumpValidations()
	}
	return true
}

// afterValidation decides report delivery once a round is sealed.
func (s *Server) afterValidation(validationID int64) {
	ctx := context.Background()
	v, err := s.m.pg.GetFindingValidation(ctx, validationID)
	if err != nil || v == nil {
		return
	}
	fid := v.FindingID
	switch {
	case v.Status == "completed" && v.Verdict == "passed":
		label := "✅ Verified by validator"
		if v.Stage == "escalator" {
			label = "✅ Verified (escalated to higher impact)"
		}
		s.queueReportReady(fid, v.SeverityConfirmed, label)
	case v.Status == "completed" && v.Verdict == "rejected":
		log.Printf("[validation %d] finding %d rejected (%s); report not pushed", v.ID, fid, v.Tier)
	case v.Status == "completed" && v.Verdict == "escalate":
		// maybeSpawnEscalator ran just before us; if no escalator round is active,
		// the hand-off could not happen -> deliver rather than drop a real primitive.
		active, _ := s.m.pg.ListActiveFindingValidations(ctx)
		for _, a := range active {
			if a.FindingID == fid && a.Stage == "escalator" {
				return
			}
		}
		s.queueReportReady(fid, "", "⚠️ Unverified: validator escalated but the escalator could not run")
	case v.Status == "stopped":
		// Stopped by the operator (pause) or by a shutdown: never push. A restart
		// interruption is resumed after boot (resumeInterruptedValidations); an
		// operator pause stays paused until someone re-queues it.
		log.Printf("[validation %d] finding %d stopped (%s); not delivered", v.ID, fid, v.Error)
	default: // failed
		if v.Stage == "validator" && v.Status == "failed" && s.ctx.Err() == nil {
			if n, err := s.m.pg.FindingValidationRounds(ctx, fid, "validator"); err == nil && n < maxAutoValidatorRounds {
				if nv, _, created, err := s.m.pg.CreateFindingValidation(ctx, fid, "validator", ""); err == nil && created {
					log.Printf("[validation] finding %d: round %d failed (%s), retrying as round %d", fid, v.ID, v.Error, nv.ID)
					s.pumpValidations()
					return
				}
			}
		}
		reason := v.Error
		if reason == "" {
			reason = v.Status
		}
		s.queueReportReady(fid, "", "⚠️ Unverified: "+oneLineText(reason, 120))
	}
}

// resumeInterruptedValidations re-runs validations a server restart cut off
// (RecoverFindingValidations marked them stopped) so a reboot never strands a
// finding between "report written" and "pushed".
func (s *Server) resumeInterruptedValidations() {
	ctx := context.Background()
	rows, err := s.m.pg.InterruptedValidationFindings(ctx)
	if err != nil {
		log.Printf("[validation] resume scan: %v", err)
		return
	}
	for _, r := range rows {
		fid, stage := r[0].(int64), r[1].(string)
		if stage == "escalator" && s.validationStageReady(db.FindingEscalatorAgentKey) {
			if ev, _, created, err := s.m.pg.CreateFindingValidation(ctx, fid, "escalator", "Re-run after a server restart interrupted the previous escalation."); err == nil && created {
				log.Printf("[validation] finding %d: escalator resumed after restart (round %d)", fid, ev.ID)
			}
			continue
		}
		if s.validationStageReady(db.FindingValidatorAgentKey) {
			if nv, _, created, err := s.m.pg.CreateFindingValidation(ctx, fid, "validator", ""); err == nil && created {
				log.Printf("[validation] finding %d: validator resumed after restart (round %d)", fid, nv.ID)
			}
			continue
		}
		s.queueReportReady(fid, "", "⚠️ Unverified: validation interrupted by a restart")
	}
	s.pumpValidations()
}

func oneLineText(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}

// seedValidatorSkills lets the validator/escalator load the per-class testing
// skills (their prompt says to confirm with the class's Skill). Insert-if-absent,
// so an operator's later toggle-off survives restarts.
func (s *Server) seedValidatorSkills() {
	skills := []string{"sql-injection-testing", "xss-testing", "ssrf-testing", "xxe-testing", "command-injection-testing",
		"deserialization-testing", "file-upload-testing", "idor-testing", "csrf-testing", "business-logic-testing",
		"ldap-injection-testing", "xpath-injection-testing", "ssti-testing", "lfi-testing", "open-redirect-testing",
		"auth-bypass-testing", "api-security", "finding-discipline", "web-pentest", "cloud-security", "crypto-analysis"}
	if _, err := s.m.pg.Exec(`INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled)
		SELECT a.id, sk, true FROM agents a CROSS JOIN unnest($1::text[]) AS sk
		WHERE a.key IN ($2,$3) ON CONFLICT (agent_id, skill_name) DO NOTHING`,
		pqStringArray(skills), db.FindingValidatorAgentKey, db.FindingEscalatorAgentKey); err != nil {
		log.Printf("[validator] skill visibility seed: %v", err)
	}
}

// pqStringArray renders a Postgres text[] literal for a $n::text[] parameter.
func pqStringArray(items []string) string {
	q := make([]string, len(items))
	for i, it := range items {
		q[i] = `"` + strings.ReplaceAll(strings.ReplaceAll(it, `\`, `\\`), `"`, `\"`) + `"`
	}
	return "{" + strings.Join(q, ",") + "}"
}

// ── Bounded queue ─────────────────────────────────────────────────────────────
// Each validation is a full agent session that sends live requests to the target
// and spends model quota, so a burst of findings must not fan out unbounded. Auto
// rounds are created 'pending' and dispatched here, at most
// maxConcurrentValidations at a time (FIFO). Escalator hand-offs and operator
// launches dispatch directly and count against the same limit.
const maxConcurrentValidations = 3

var validationPumpMu sync.Mutex

func (s *Server) pumpValidations() {
	if s.ctx.Err() != nil {
		return
	}
	validationPumpMu.Lock()
	defer validationPumpMu.Unlock()
	rows, err := s.m.pg.Query(`SELECT id, conversation_id, status FROM finding_validations
		WHERE status IN ('pending','running') AND conversation_id IS NOT NULL ORDER BY id`)
	if err != nil {
		log.Printf("[validation] pump: %v", err)
		return
	}
	type row struct {
		id, conv int64
		status   string
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.conv, &r.status); err == nil {
			all = append(all, r)
		}
	}
	rows.Close()
	busy := func(conv int64) bool {
		s.chatMu.Lock()
		defer s.chatMu.Unlock()
		return s.chatBusy[s.convBusyKey(conv)]
	}
	active := 0
	var waiting []row
	for _, r := range all {
		if r.status == "running" || busy(r.conv) {
			active++
		} else {
			waiting = append(waiting, r)
		}
	}
	for _, r := range waiting {
		if active >= maxConcurrentValidations {
			return
		}
		v, err := s.m.pg.GetFindingValidation(context.Background(), r.id)
		if err != nil || v == nil || v.Status != "pending" {
			continue
		}
		conv, err := s.m.pg.GetConversation(r.conv)
		if err != nil || conv == nil {
			continue
		}
		log.Printf("[validation] dispatch round %d (%s) for finding %d", v.ID, v.Stage, v.FindingID)
		s.dispatchValidation(conv, v.InitialMessage())
		active++
	}
}

// backfillFindingValidations (POST /api/exploration/findings/validations/backfill,
// body {"finding_ids":[...]}) queues a validator round for each finding that has
// no active or completed validation yet. Rounds go through the bounded queue
// (pumpValidations), never all at once.
func (s *Server) backfillFindingValidations(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		FindingIDs []int64 `json:"finding_ids"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	if !s.validationStageReady(db.FindingValidatorAgentKey) {
		writeErr(w, 409, "the validator agent is not ready (agent, tool bindings or LLM profile)")
		return
	}
	var queued, skipped []int64
	for _, id := range req.FindingIDs {
		if done, err := pg.HasCompletedFindingValidation(r.Context(), id); err != nil || done {
			skipped = append(skipped, id)
			continue
		}
		_, _, created, err := pg.CreateFindingValidation(r.Context(), id, "validator", "")
		if err != nil || !created {
			skipped = append(skipped, id)
			continue
		}
		queued = append(queued, id)
	}
	s.pumpValidations()
	writeJSON(w, 200, map[string]any{"queued": queued, "skipped": skipped})
}

// setTaskVerifyFindings (POST /api/tasks/{id}/verify-findings, {"enabled":bool})
// toggles a task's finding-validation gate. It applies to reports saved from now
// on; it does not re-judge findings already pushed or validated.
func (s *Server) setTaskVerifyFindings(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad task id")
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil || req.Enabled == nil {
		writeErr(w, 400, `body must be {"enabled": true|false}`)
		return
	}
	if err := s.m.pg.SetTaskVerifyFindings(id, *req.Enabled); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.m.mu.Lock()
	t.VerifyFindings = *req.Enabled
	s.m.mu.Unlock()
	log.Printf("[task] #%s verify_findings=%v", t.ID, *req.Enabled)
	writeJSON(w, 200, map[string]any{"ok": true, "verify_findings": *req.Enabled})
}

// FindingVerificationDTO is the validation status shown next to a finding.
// State: queued | running | verified | rejected | escalating | failed | paused.
type FindingVerificationDTO struct {
	State             string `json:"state"`
	Stage             string `json:"stage"`
	Verdict           string `json:"verdict,omitempty"`
	Tier              string `json:"tier,omitempty"`
	SeverityConfirmed string `json:"severity_confirmed,omitempty"`
	Summary           string `json:"summary,omitempty"`
	Error             string `json:"error,omitempty"`
	At                string `json:"at"`
}

// attachVerification fills each DTO's Verification from its latest validation
// round, in one query. Best-effort: on error the list is returned unannotated.
func (s *Server) attachVerification(items []FindingDTO) {
	if len(items) == 0 || s.m == nil || s.m.pg == nil {
		return
	}
	var ids []string
	for _, it := range items {
		if _, err := strconv.ParseInt(it.FindingID, 10, 64); err == nil {
			ids = append(ids, it.FindingID)
		}
	}
	if len(ids) == 0 {
		return
	}
	rows, err := s.m.pg.Query(`SELECT DISTINCT ON (finding_id) finding_id, stage, status, verdict, tier, severity_confirmed,
		left(summary, 400), left(error, 200), to_char(COALESCE(finished_at, started_at, created_at), 'YYYY-MM-DD HH24:MI')
		FROM finding_validations WHERE finding_id = ANY($1::bigint[]) ORDER BY finding_id, id DESC`, "{"+strings.Join(ids, ",")+"}")
	if err != nil {
		log.Printf("[validation] attach status: %v", err)
		return
	}
	defer rows.Close()
	byID := map[string]*FindingVerificationDTO{}
	for rows.Next() {
		var fid int64
		var stage, status string
		v := &FindingVerificationDTO{}
		if err := rows.Scan(&fid, &stage, &status, &v.Verdict, &v.Tier, &v.SeverityConfirmed, &v.Summary, &v.Error, &v.At); err != nil {
			continue
		}
		v.Stage = stage
		switch {
		case status == "pending":
			v.State = "queued"
		case status == "running":
			v.State = "running"
		case status == "completed" && v.Verdict == "passed":
			v.State = "verified"
		case status == "completed" && v.Verdict == "rejected":
			v.State = "rejected"
		case status == "completed" && v.Verdict == "escalate":
			v.State = "escalating"
		case status == "stopped":
			v.State = "paused"
		default:
			v.State = "failed"
		}
		byID[strconv.FormatInt(fid, 10)] = v
	}
	for i := range items {
		if v, ok := byID[items[i].FindingID]; ok {
			items[i].Verification = v
		}
	}
}

// ── Report sweeper ────────────────────────────────────────────────────────────
// Delivery and validation start when the reporter saves a report. If the
// reporter run failed (LLM/network outage) the finding would stay silent forever,
// so every 10 minutes this re-runs the reporter for findings still without a
// report after 30 minutes (at most reportRetryMax times, 30 min apart), then
// falls back to judging/pushing the finding on its evidence alone (summary
// message instead of report.md). Forward-looking only: findings older than the
// first sweep (setting report_sweeper_since) are left alone; a backfill of old
// findings is an explicit operator decision.
const reportRetryMax = 2

func (s *Server) sweepMissingReports() {
	if s.ctx.Err() != nil || s.m == nil || s.m.pg == nil {
		return
	}
	pg := s.m.pg
	since, ok, _ := pg.GetSetting("report_sweeper_since")
	if !ok || since == "" {
		since = time.Now().UTC().Format(time.RFC3339)
		_ = pg.SetSetting("report_sweeper_since", since)
		log.Printf("[report-sweep] armed: findings created after %s are watched", since)
		return
	}
	rows, err := pg.Query(`SELECT f.id, f.node_id, COALESCE(f.task_id,0), COALESCE(f.severity,''),
		COALESCE(t.verify_findings,false), COALESCE(r.attempts,0), r.last_at IS NULL OR r.last_at < now()-interval '30 minutes'
		FROM findings f
		LEFT JOIN tasks t ON t.id=f.task_id
		LEFT JOIN finding_report_retries r ON r.finding_id=f.id
		WHERE COALESCE(f.report,'')='' AND f.node_id IS NOT NULL
		  AND f.created_at > $1::timestamptz AND f.created_at < now()-interval '30 minutes'
		  AND COALESCE(f.status,'pending') NOT IN ('false_positive','duplicate')
		  AND NOT EXISTS (SELECT 1 FROM notification_events e WHERE e.kind='finding_report_ready' AND e.finding_id=f.id)
		  AND NOT EXISTS (SELECT 1 FROM finding_validations v WHERE v.finding_id=f.id AND v.status IN ('pending','running','completed'))
		ORDER BY f.id LIMIT 20`, since)
	if err != nil {
		log.Printf("[report-sweep] query: %v", err)
		return
	}
	type cand struct {
		id, node, task int64
		sev            string
		verify, due    bool
		attempts       int
	}
	var cs []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.node, &c.task, &c.sev, &c.verify, &c.attempts, &c.due); err == nil {
			cs = append(cs, c)
		}
	}
	rows.Close()
	for _, c := range cs {
		if !c.due {
			continue
		}
		if c.attempts < reportRetryMax {
			var desc, goal string
			_ = pg.QueryRow(`SELECT COALESCE(description,''), COALESCE(goal,'') FROM tasks WHERE id=$1`, c.task).Scan(&desc, &goal)
			msg := reporterToolCallMessage + fmt.Sprintf("\n\n[Re-triggered by the report sweeper: no report was saved for this finding]\nTool: report_finding\nResult: {\"finding_id\": %d, \"finding_node_id\": %d}", c.id, c.node)
			s.StartTriggeredRun("reporter", fmt.Sprintf("report retry - finding#%d - task#%d", c.id, c.task), msg, c.task, false, desc, goal)
			_, _ = pg.Exec(`INSERT INTO finding_report_retries(finding_id, attempts, last_at) VALUES ($1,1,now())
				ON CONFLICT (finding_id) DO UPDATE SET attempts=finding_report_retries.attempts+1, last_at=now()`, c.id)
			log.Printf("[report-sweep] finding %d: no report after 30m, reporter re-run %d/%d", c.id, c.attempts+1, reportRetryMax)
			continue
		}
		// Reporter gave up: judge/push on evidence alone.
		log.Printf("[report-sweep] finding %d: still no report after %d reporter runs, falling back to evidence", c.id, c.attempts)
		switch {
		case !c.verify:
			s.queueReportReady(c.id, "", "⚪ Not verified (verification off) - no report: reporter failed")
		case notify.SeverityRank(strings.ToLower(c.sev)) < notify.SeverityRank("medium"):
			s.queueReportReady(c.id, "", "⚪ Not verified (below medium) - no report: reporter failed")
		case s.startAutoValidation(c.id):
		default:
			s.queueReportReady(c.id, "", "⚠️ Unverified - no report: reporter failed and validator unavailable")
		}
	}
}

// seedValidatorTrafficBinding lets the gate agents read the finding's bound
// traffic (get_finding_traffic is read-only). One-time, so an operator's later
// unbinding survives restarts.
func (s *Server) seedValidatorTrafficBinding() {
	const flag = "validator_traffic_binding_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, key := range []string{db.FindingValidatorAgentKey, db.FindingEscalatorAgentKey} {
		if err := s.m.pg.AddAgentToToolBinding(key, []string{"get_finding_traffic"}); err != nil {
			log.Printf("[validator] bind get_finding_traffic to %s: %v", key, err)
			return
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
