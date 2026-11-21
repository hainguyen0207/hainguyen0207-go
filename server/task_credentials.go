package server

// Ported from ScopeWeaver/bcpen (AGPL-3.0, an ARTEX derivative): per-task test credentials (#3).

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/db"
)

// seedTaskCredentialBindings binds the task-credential tools onto worker and
// pentest ONCE (guarded by a settings flag), so existing DBs seeded before the
// feature still get them — fresh DBs already have them via the pentest catalog.
// A user who deliberately unbinds them is not overridden.
func (s *Server) seedTaskCredentialBindings() {
	const flag = "task_credential_bindings_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	for _, agentKey := range []string{"worker", "pentest"} {
		if err := s.m.pg.AddAgentToToolBinding(agentKey, []string{"save_task_credential", "list_task_credentials"}); err != nil {
			log.Printf("[%s] task-credential default binding failed: %v", agentKey, err)
			return // flag not set; retried on next startup
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

// Task credential HTTP handlers (#3). The agent-side write path is the
// save_task_credential tool; these routes serve the UI (task detail tab) and the
// creation dialog.

// taskCredentialReq is the add/update payload from the task-detail tab. (In the
// ARTEX base this lived in server.go beside createTaskReq; kept here so the
// restored feature stays self-contained against ScopeWeaver's server.go.)
type taskCredentialReq struct {
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
	Note     string `json:"note"`
}

// taskCredentialDTO masks nothing — the admin is the credential owner — but the
// frontend renders passwords masked with an explicit reveal.
func taskCredentialDTO(c db.TaskCredential) map[string]any {
	return map[string]any{
		"id": c.ID, "task_id": c.TaskID, "domain": c.Domain, "username": c.Username,
		"password": c.Password, "source": c.Source, "note": c.Note,
		"created_at": c.CreatedAt, "updated_at": c.UpdatedAt,
	}
}

func (s *Server) taskCredentialTaskID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return 0, false
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 500, "task id is not numeric")
		return 0, false
	}
	return id, true
}

func (s *Server) listTaskCredentials(w http.ResponseWriter, r *http.Request) {
	id, ok := s.taskCredentialTaskID(w, r)
	if !ok {
		return
	}
	list, err := s.m.PG().TaskCredentials(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		out = append(out, taskCredentialDTO(c))
	}
	writeJSON(w, 200, out)
}

func (s *Server) addTaskCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := s.taskCredentialTaskID(w, r)
	if !ok {
		return
	}
	var req taskCredentialReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	// source=user: manual adds from the UI (e.g. relaying an OTP-verified account).
	// An empty password stays allowed here — the "agent generates" mode.
	c, err := s.m.PG().UpsertTaskCredential(id, db.TaskCredentialInput{
		Domain: req.Domain, Username: req.Username, Password: req.Password,
		Source: "user", Note: req.Note,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, taskCredentialDTO(c))
}

func (s *Server) deleteTaskCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := s.taskCredentialTaskID(w, r)
	if !ok {
		return
	}
	cid, err := strconv.ParseInt(r.PathValue("cid"), 10, 64)
	if err != nil || cid <= 0 {
		writeErr(w, 400, "invalid credential id")
		return
	}
	if err := s.m.PG().DeleteTaskCredential(id, cid); err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
