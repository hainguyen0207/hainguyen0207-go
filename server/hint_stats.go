package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Hint provenance: which hints (KB Hunter "KB-LEAD", operator, main agent)
// produced intents (add_intent from_hints) and which of those intents yielded
// findings, with the findings' verification. Lets the operator see whether the
// KB Hunter is worth its tokens.

type hintStatIntent struct {
	ID    int64  `json:"id"`
	State string `json:"state"`
	Text  string `json:"summary"`
}

type hintStatFinding struct {
	ID        int64  `json:"id"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	Name      string `json:"name"`
	Verdict   string `json:"verdict,omitempty"`
	IntentID  int64  `json:"intent_id"`
	Confirmed string `json:"severity_confirmed,omitempty"`
}

type hintStat struct {
	ID        int64             `json:"id"`
	Source    string            `json:"source"` // kb_hunter | operator | other
	State     string            `json:"state"`
	Text      string            `json:"text"`
	CreatedAt string            `json:"created_at"`
	Intents   []hintStatIntent  `json:"intents"`
	Findings  []hintStatFinding `json:"findings"`
}

func hintSource(text, origin string) string {
	if strings.HasPrefix(strings.TrimSpace(text), "KB-LEAD") {
		return "kb_hunter"
	}
	if origin == "human" {
		return "operator"
	}
	return "other"
}

// GET /api/tasks/{id}/hint-stats
func (s *Server) taskHintStats(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	ctx := r.Context()
	pg := s.m.pg
	rows, err := pg.QueryContext(ctx, `SELECT id, state, COALESCE(origin,''), COALESCE(payload->>'text',''), to_char(created_at,'YYYY-MM-DD HH24:MI')
		FROM exploration_nodes WHERE exploration_id=$1 AND kind='hint' ORDER BY id DESC LIMIT 500`, t.ExpID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var hints []*hintStat
	byID := map[int64]*hintStat{}
	for rows.Next() {
		h := &hintStat{Intents: []hintStatIntent{}, Findings: []hintStatFinding{}}
		var origin string
		if err := rows.Scan(&h.ID, &h.State, &origin, &h.Text, &h.CreatedAt); err != nil {
			rows.Close()
			writeErr(w, 500, err.Error())
			return
		}
		h.Source = hintSource(h.Text, origin)
		hints = append(hints, h)
		byID[h.ID] = h
	}
	rows.Close()

	// intents that name their source hints
	irows, err := pg.QueryContext(ctx, `SELECT id, state, COALESCE(payload->>'summary',''), payload->'from_hints'
		FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND payload ? 'from_hints'`, t.ExpID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	intentHints := map[int64][]int64{}
	for irows.Next() {
		var it hintStatIntent
		var raw []byte
		if irows.Scan(&it.ID, &it.State, &it.Text, &raw) != nil {
			continue
		}
		var hs []int64
		_ = json.Unmarshal(raw, &hs)
		if len(it.Text) > 200 {
			it.Text = it.Text[:200] + "…"
		}
		for _, hid := range hs {
			if h := byID[hid]; h != nil {
				h.Intents = append(h.Intents, it)
				intentHints[it.ID] = append(intentHints[it.ID], hid)
			}
		}
	}
	irows.Close()

	// findings yielded by those intents (intent --yields--> finding node)
	if len(intentHints) > 0 {
		ids := make([]int64, 0, len(intentHints))
		for id := range intentHints {
			ids = append(ids, id)
		}
		raw, _ := json.Marshal(ids)
		frows, err := pg.QueryContext(ctx, `SELECT e.src_id, f.id, COALESCE(f.severity,''), COALESCE(f.status,''), COALESCE(f.name,''),
			COALESCE(v.verdict,''), COALESCE(v.severity_confirmed,'')
			FROM exploration_edges e
			JOIN findings f ON f.node_id = e.dst_id
			LEFT JOIN LATERAL (SELECT verdict, severity_confirmed FROM finding_validations fv
			                   WHERE fv.finding_id=f.id AND fv.status='completed' ORDER BY fv.id DESC LIMIT 1) v ON true
			WHERE e.exploration_id=$1 AND e.rel='yields' AND e.src_id IN (SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb))`,
			t.ExpID, string(raw))
		if err == nil {
			for frows.Next() {
				var src int64
				var f hintStatFinding
				if frows.Scan(&src, &f.ID, &f.Severity, &f.Status, &f.Name, &f.Verdict, &f.Confirmed) != nil {
					continue
				}
				f.IntentID = src
				for _, hid := range intentHints[src] {
					byID[hid].Findings = append(byID[hid].Findings, f)
				}
			}
			frows.Close()
		}
	}

	// per-source summary
	type agg struct {
		Hints, Used, Intents, Findings, Confirmed int
	}
	sum := map[string]*agg{}
	for _, h := range hints {
		a := sum[h.Source]
		if a == nil {
			a = &agg{}
			sum[h.Source] = a
		}
		a.Hints++
		if len(h.Intents) > 0 {
			a.Used++
		}
		a.Intents += len(h.Intents)
		a.Findings += len(h.Findings)
		for _, f := range h.Findings {
			if f.Status == "confirmed" || f.Verdict == "passed" {
				a.Confirmed++
			}
		}
	}
	if hints == nil {
		hints = []*hintStat{}
	}
	writeJSON(w, 200, map[string]any{"summary": sum, "hints": hints})
}
