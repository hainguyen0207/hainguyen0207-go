package db

// Ported from ScopeWeaver/bcpen (AGPL-3.0, an ARTEX derivative): finding
// validation rounds (validator / escalator). The cross-task lessons lock was
// dropped (not ported); auto-run helpers are appended at the end.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/validation"
)

// The two opposing finding-gate agents. They are separate conversation agents
// (distinct keys, distinct editable prompts) on purpose: the gate's value is two
// independent stances on the same finding — the validator defaults to disbelief
// (the false-positive firewall), the escalator defaults to belief-and-ambition
// (push a reproduced primitive to its true impact). The escalator runs only on a
// finding the validator returned 'escalate' for. The agent key of a validation's
// conversation IS its stage.
const (
	FindingValidatorAgentKey = "validator"
	FindingEscalatorAgentKey = "escalator"
)

// StageAgentKey maps a validation stage to its conversation agent key (here they
// are identical, but callers should go through this rather than assume).
func StageAgentKey(stage string) string { return stage }

var ErrValidationNotRunning = errors.New("this validation has ended or has not started; start a new validation from the finding details")

// FindingValidation is one validation round for a finding. Immutable once its
// conversation turn ends. Snapshot is only loaded for the agent.
type FindingValidation struct {
	ID                int64           `json:"id"`
	FindingID         int64           `json:"finding_id"`
	Stage             string          `json:"stage"` // validator | escalator
	ConversationID    *int64          `json:"conversation_id"`
	Status            string          `json:"status"`
	Verdict           string          `json:"verdict"` // passed | rejected | escalate
	Tier              string          `json:"tier"`    // note | lead | gadget | finding
	SeverityConfirmed string          `json:"severity_confirmed"`
	Notes             string          `json:"notes"`
	Snapshot          json.RawMessage `json:"snapshot,omitempty"`
	Summary           string          `json:"summary"`
	Evidence          string          `json:"evidence"`
	Error             string          `json:"error"`
	CreatedAt         time.Time       `json:"created_at"`
	StartedAt         *time.Time      `json:"started_at"`
	FinishedAt        *time.Time      `json:"finished_at"`
}

const validationCols = `id, finding_id, stage, conversation_id, status, verdict, tier, severity_confirmed, notes, summary, evidence, error, created_at, started_at, finished_at`

func scanValidation(row interface{ Scan(...any) error }) (*FindingValidation, error) {
	v := &FindingValidation{}
	err := row.Scan(&v.ID, &v.FindingID, &v.Stage, &v.ConversationID, &v.Status, &v.Verdict, &v.Tier,
		&v.SeverityConfirmed, &v.Notes, &v.Summary, &v.Evidence, &v.Error, &v.CreatedAt, &v.StartedAt, &v.FinishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return v, err
}

// ActiveFindingValidation is the small status payload polled by the findings list.
type ActiveFindingValidation struct {
	ID             int64  `json:"id"`
	FindingID      int64  `json:"finding_id,string"`
	Stage          string `json:"stage"`
	ConversationID int64  `json:"conversation_id"`
	Status         string `json:"status"`
}

func (d *DB) ListActiveFindingValidations(ctx context.Context) ([]ActiveFindingValidation, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, finding_id, stage, conversation_id, status FROM finding_validations
	WHERE status IN ('pending','running') AND conversation_id IS NOT NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ActiveFindingValidation{}
	for rows.Next() {
		var item ActiveFindingValidation
		if err := rows.Scan(&item.ID, &item.FindingID, &item.Stage, &item.ConversationID, &item.Status); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// CreateFindingValidation atomically snapshots the finding, creates its conversation
// (agent_key = stage) and persists the first message. A finding row lock plus the
// active-run guard deduplicate simultaneous launches: only one validation round
// (either stage) may be in flight per finding at a time. handoff is the validator's
// escalate note, carried into the escalator's opening message (empty for the
// validator stage).
func (d *DB) CreateFindingValidation(ctx context.Context, findingID int64, stage, handoff string) (*FindingValidation, *Conversation, bool, error) {
	if stage != "validator" && stage != "escalator" {
		return nil, nil, false, errors.New("stage must be validator or escalator")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, false, err
	}
	defer tx.Rollback()
	var title string
	var snapshot []byte
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(NULLIF(f.name,''), NULLIF(f.vulnclass,''), 'Uncategorized'),
	jsonb_build_object('finding', to_jsonb(f),
	 'assets', COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM assets a WHERE f.asset_ids @> to_jsonb(ARRAY[a.id])), '[]'::jsonb),
	 'constraints', COALESCE((SELECT jsonb_agg(to_jsonb(c)) FROM task_constraints c JOIN tasks t ON t.exploration_id=c.exploration_id WHERE t.id=f.task_id), '[]'::jsonb))
	FROM findings f WHERE f.id=$1 FOR UPDATE OF f`, findingID).Scan(&title, &snapshot)
	if err != nil {
		return nil, nil, false, err
	}
	// Only one active validation round per finding, regardless of stage.
	v, err := scanValidation(tx.QueryRowContext(ctx, `SELECT `+validationCols+` FROM finding_validations WHERE finding_id=$1 AND status IN ('pending','running')`, findingID))
	if err != nil {
		return nil, nil, false, err
	}
	if v != nil {
		return v, nil, false, nil
	}
	if runes := []rune(title); len(runes) > 100 {
		title = string(runes[:100])
	}
	label := "Validate"
	if stage == "escalator" {
		label = "Escalate"
	}
	// Per-task model for the gate agents (task_role_llm role "validator"); NULL =
	// the validator/escalator agent's own binding.
	var pin *int64
	var pid int64
	if err := tx.QueryRowContext(ctx, `SELECT r.profile_id FROM task_role_llm r JOIN findings f ON f.task_id=r.task_id
		WHERE f.id=$1 AND r.role='validator'`, findingID).Scan(&pid); err == nil {
		pin = &pid
	}
	c, err := scanConv(tx.QueryRowContext(ctx, `INSERT INTO conversations(agent_key,title,llm_profile_id) VALUES ($1,$2,$3) RETURNING `+convCols,
		StageAgentKey(stage), fmt.Sprintf("%s #%d · %s", label, findingID, title), pin))
	if err != nil {
		return nil, nil, false, err
	}
	v, err = scanValidation(tx.QueryRowContext(ctx, `INSERT INTO finding_validations(finding_id,stage,conversation_id,notes,snapshot) VALUES ($1,$2,$3,$4,$5) RETURNING `+validationCols,
		findingID, stage, c.ID, strings.TrimSpace(handoff), snapshot))
	if err != nil {
		return nil, nil, false, err
	}
	msg := v.InitialMessage()
	_, err = tx.ExecContext(ctx, `INSERT INTO conversation_activities(conversation_id,worker,kind,summary,detail) VALUES ($1,$2,'user',$3,$4)`,
		c.ID, StageAgentKey(stage), fmt.Sprintf("Please %s finding #%d", strings.ToLower(label), findingID), msg)
	if err != nil {
		return nil, nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, false, err
	}
	return v, &c, true, nil
}

func (v *FindingValidation) InitialMessage() string {
	if v.Stage == "escalator" {
		msg := fmt.Sprintf("Escalate finding #%d. First call get_finding_validation_context to read the finding and the validator's escalate note, then pursue the named higher-impact paths within authorization, and finally call record_finding_validation_result with passed or rejected.", v.FindingID) + validationToolsNote(v.FindingID)
		if v.Notes != "" {
			msg += "\n\nValidator's escalate handoff:\n" + v.Notes
		}
		return msg
	}
	return fmt.Sprintf("Validate finding #%d. First call get_finding_validation_context to read the filed PoC and constraints bound to this conversation, reproduce it cold from the written PoC only, confirm the true impact, and finally call record_finding_validation_result with passed, rejected, or escalate.", v.FindingID) + validationToolsNote(v.FindingID)
}

func (d *DB) ListFindingValidations(findingID int64) ([]*FindingValidation, error) {
	rows, err := d.Query(`SELECT `+validationCols+` FROM finding_validations WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FindingValidation{}
	for rows.Next() {
		v, err := scanValidation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetFindingValidation reads one round by id (snapshot omitted).
func (d *DB) GetFindingValidation(ctx context.Context, id int64) (*FindingValidation, error) {
	return scanValidation(d.QueryRowContext(ctx, `SELECT `+validationCols+` FROM finding_validations WHERE id=$1`, id))
}

func (d *DB) FindingValidationForConversation(ctx context.Context, conversationID int64) (*FindingValidation, error) {
	v, err := scanValidation(d.QueryRowContext(ctx, `SELECT `+validationCols+` FROM finding_validations WHERE conversation_id=$1`, conversationID))
	if err != nil || v == nil {
		return v, err
	}
	err = d.QueryRowContext(ctx, `SELECT snapshot FROM finding_validations WHERE id=$1`, v.ID).Scan(&v.Snapshot)
	return v, err
}

func (d *DB) FailPendingValidationForConversation(conversationID int64, reason string) error {
	_, err := d.Exec(`UPDATE finding_validations SET status='failed', error=$2, finished_at=now()
		WHERE conversation_id=$1 AND status IN ('pending','running')`, conversationID, reason)
	return err
}

func (d *DB) StartFindingValidation(ctx context.Context, id int64) (bool, error) {
	res, err := d.ExecContext(ctx, `UPDATE finding_validations SET status='running', started_at=now() WHERE id=$1 AND status='pending'`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RecordFindingValidationResult stages the gate verdict. Ownership comes from the
// runtime conversation, never a caller-supplied finding id. Identical retries are
// safe; a second, different verdict is refused. Verdict must be one of the three
// gate verdicts (passed/rejected/escalate) — never pending. A passed verdict must
// carry the demonstrated severity.
func (d *DB) RecordFindingValidationResult(ctx context.Context, conversationID int64, verdict, tier, severityConfirmed, summary, evidence string, chained bool) error {
	ver, ok := validation.ParseVerdict(verdict)
	if !ok || ver == validation.VerdictPending {
		return errors.New("verdict must be passed / rejected / escalate")
	}
	summary, evidence = strings.TrimSpace(summary), strings.TrimSpace(evidence)
	severityConfirmed = strings.TrimSpace(strings.ToLower(severityConfirmed))
	tier = strings.TrimSpace(strings.ToLower(tier))
	if summary == "" || evidence == "" {
		return errors.New("summary and evidence must not be empty; cite the specific requests/responses/controls behind the verdict")
	}
	// Tier gate: a pass must be tier=finding with a rewardable severity. A
	// gadget/lead/note, or info-only impact, cannot be laundered into the report.
	if ver == validation.VerdictPassed {
		if err := validation.PassRequires(validation.Tier(tier), validation.Severity(severityConfirmed)); err != nil {
			return err
		}
		// Class-aware teeth (CAL-001/002): a default-gadget vulnclass (enumeration /
		// differential oracle / open redirect / version disclosure) cannot pass as a
		// standalone finding — only as a demonstrated chain (chained=true) — even if
		// the agent mislabeled its tier as finding.
		var vulnclass string
		_ = d.QueryRowContext(ctx, `SELECT COALESCE(f.vulnclass,'') FROM findings f
JOIN finding_validations fv ON fv.finding_id=f.id WHERE fv.conversation_id=$1`, conversationID).Scan(&vulnclass)
		if err := validation.PassRequiresClass(vulnclass, chained); err != nil {
			return err
		}
	} else if tier != "" {
		// For reject/escalate, tier is optional context; validate it when given.
		if _, ok := validation.ParseTier(tier); !ok {
			return errors.New("tier must be one of note / lead / gadget / finding")
		}
	}
	if len(summary) > 16000 || len(evidence) > 128000 {
		return errors.New("validation conclusion is too long (summary ≤ 16KB, evidence ≤ 128KB)")
	}
	res, err := d.ExecContext(ctx, `UPDATE finding_validations SET verdict=$2,tier=$3,severity_confirmed=$4,summary=$5,evidence=$6
	WHERE conversation_id=$1 AND status='running' AND (verdict='' OR (verdict=$2 AND summary=$5 AND evidence=$6))`,
		conversationID, string(ver), tier, severityConfirmed, summary, evidence)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrValidationNotRunning
	}
	return nil
}

// FinishFindingValidation seals the round. Cancellation/failure takes precedence
// over a staged verdict so an interrupted validation cannot appear passed. A newly
// completed terminal verdict drives the finding's handling status in the same
// transaction (passed → confirmed, rejected → false_positive); escalate changes no
// status — the server layer hands it to the escalator.
func (d *DB) FinishFindingValidation(id int64, status, reason string) error {
	if status != "completed" && status != "failed" && status != "stopped" {
		return errors.New("invalid terminal validation status")
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var findingID int64
	err = tx.QueryRow(`SELECT f.id FROM findings f WHERE f.id=(SELECT finding_id FROM finding_validations WHERE id=$1) FOR UPDATE OF f`, id).Scan(&findingID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // finding/validation already deleted
	}
	if err != nil {
		return err
	}
	var finalStatus, verdict string
	err = tx.QueryRow(`UPDATE finding_validations SET
	status=CASE WHEN $2='completed' AND verdict='' THEN 'failed' ELSE $2 END,
	error=CASE WHEN $2='completed' AND verdict='' THEN 'Agent did not save the validation verdict; review the conversation and validate again' ELSE $3 END,
	finished_at=now() WHERE id=$1 AND status IN ('pending','running') RETURNING status,verdict`, id, status, reason).Scan(&finalStatus, &verdict)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // replay must not overwrite a later manual triage decision
	}
	if err != nil {
		return err
	}
	if finalStatus == "completed" {
		if newStatus, change := validation.Verdict(verdict).StatusAfter(); change {
			// Only an untriaged finding (pending / in_progress) takes the gate's
			// status. A human or agent decision already made (confirmed, fixed,
			// duplicate, ...) is never overwritten; the verdict is still recorded
			// on the validation round and shown as the verification badge.
			var cur string
			if err := tx.QueryRow(`SELECT COALESCE(status,'pending') FROM findings WHERE id=$1`, findingID).Scan(&cur); err != nil {
				return err
			}
			if cur == FindingPending || cur == FindingInProgress {
				if _, _, _, _, err := SetFindingStatusTx(context.Background(), tx, findingID, newStatus); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}

func (d *DB) RecoverFindingValidations() error {
	_, err := d.Exec(`UPDATE finding_validations SET status='stopped', error='Server restarted; the validation was interrupted, please start it again', finished_at=now() WHERE status IN ('pending','running')`)
	return err
}

// LatestVerdicts returns each finding's most recent concluded gate verdict, for
// the report gate. Only findings with a completed validation appear; absence means
// "never validated" and the report builder must treat that as not-report-ready.
func (d *DB) LatestVerdicts(findingIDs []int64) (map[int64]validation.Verdict, error) {
	out := map[int64]validation.Verdict{}
	if len(findingIDs) == 0 {
		return out, nil
	}
	rows, err := d.Query(`SELECT DISTINCT ON (finding_id) finding_id, verdict
	FROM finding_validations WHERE status='completed' AND verdict<>'' AND finding_id = ANY($1)
	ORDER BY finding_id, id DESC`, findingIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var fid int64
		var vs string
		if err := rows.Scan(&fid, &vs); err != nil {
			return nil, err
		}
		if v, ok := validation.ParseVerdict(vs); ok {
			out[fid] = v
		}
	}
	return out, rows.Err()
}

// FindingValidationRounds counts the validation rounds of one stage for a finding
// (any status), used to cap automatic retries.
func (d *DB) FindingValidationRounds(ctx context.Context, findingID int64, stage string) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT count(*) FROM finding_validations WHERE finding_id=$1 AND stage=$2`, findingID, stage).Scan(&n)
	return n, err
}

// HasCompletedFindingValidation reports whether a finding already has a
// completed (verdict-bearing) validation round of any stage.
func (d *DB) HasCompletedFindingValidation(ctx context.Context, findingID int64) (bool, error) {
	var ok bool
	err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM finding_validations WHERE finding_id=$1 AND status='completed')`, findingID).Scan(&ok)
	return ok, err
}

// InterruptedValidationFindings lists findings whose LATEST validation round was
// stopped by a server restart (see RecoverFindingValidations) within the last 7
// days and whose report has not been pushed yet, so they can be re-validated
// automatically after boot. Returns (finding id, stage) pairs.
func (d *DB) InterruptedValidationFindings(ctx context.Context) ([][2]any, error) {
	rows, err := d.QueryContext(ctx, `SELECT v.finding_id, v.stage FROM finding_validations v
	WHERE v.id = (SELECT max(id) FROM finding_validations WHERE finding_id=v.finding_id)
	  AND v.status='stopped' AND v.error LIKE 'Server restarted%'
	  AND v.created_at > now() - interval '7 days'
	  AND NOT EXISTS (SELECT 1 FROM notification_events e WHERE e.kind='finding_report_ready' AND e.finding_id=v.finding_id)
	ORDER BY v.finding_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]any
	for rows.Next() {
		var fid int64
		var stage string
		if err := rows.Scan(&fid, &stage); err != nil {
			return nil, err
		}
		out = append(out, [2]any{fid, stage})
	}
	return out, rows.Err()
}

// validationToolsNote tells the gate agents what evidence they can use beyond
// the written PoC.
func validationToolsNote(findingID int64) string {
	return fmt.Sprintf("\n\nAvailable evidence: the context includes `traffic` (the requests/responses bound to this finding; "+
		"read a body with get_finding_traffic(finding_id=%d, binding_id, side=request|response)) and, when declared, "+
		"`task_credentials` (this task's test accounts). For an access-control / IDOR / privilege claim, re-test with two "+
		"genuinely separate identities from task_credentials; if only one account exists, say so in the evidence instead of guessing.", findingID)
}
