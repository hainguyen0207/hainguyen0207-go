package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// Grouped view over the vuln KB, built offline by tools/kbtax (no LLM): every
// report is tagged along several dimensions — class (bug class), bypass (what
// was bypassed), impact (ATO / RCE / admin / mass data / financial / DoS), tech
// (framework / product), source (internal pentest / bug bounty / exploit /
// scanner / KEV), scope, quality (A = rich reusable testcase), ref (has_cve /
// in_kev) — plus per-tech profiles of the characteristic classes (lift vs the
// whole KB). Read-only reference data.

var (
	vulnKBIdxOnce sync.Once
	vulnKBIdxConn *sql.DB
)

func vulnKBIndexPath() string {
	if p := strings.TrimSpace(os.Getenv("HAINGUYEN0207_VULN_KB_INDEX")); p != "" {
		return p
	}
	return strings.TrimSuffix(vulnKBPath(), "issues.sqlite3") + "tech_index.sqlite3"
}

func vulnKBIndex() *sql.DB {
	vulnKBIdxOnce.Do(func() {
		p := vulnKBIndexPath()
		if _, err := os.Stat(p); err != nil {
			return
		}
		db, err := sql.Open("sqlite", "file:"+p+"?mode=ro&_pragma=busy_timeout(5000)")
		if err != nil {
			return
		}
		db.SetMaxOpenConns(2)
		vulnKBIdxConn = db
	})
	return vulnKBIdxConn
}

const kbReferenceNote = "KB = static snapshot, REFERENCE ONLY — it helps you PRIORITISE, it never limits scope: still run the FULL methodology and the complete vuln-catalogue on every host/endpoint, including classes the KB does not list for this tech. Use it to decide what to test first, then confirm the exact product/version against current external sources (NVD, vendor advisory, GitHub advisory) and verify on the target yourself. Never search external sources with target hostnames — use product + version only."

// resolveKBTech maps a free-form tech name to an indexed tech tag.
func resolveKBTech(ctx context.Context, idx *sql.DB, q string) (string, []string, error) {
	q = strings.TrimSpace(q)
	var exact string
	err := idx.QueryRowContext(ctx, `SELECT tag FROM tag_def WHERE dim='tech' AND lower(tag)=lower(?)`, q).Scan(&exact)
	if err == nil {
		return exact, nil, nil
	}
	rows, err := idx.QueryContext(ctx, `SELECT tag FROM tag_def WHERE dim='tech' AND (lower(tag) LIKE '%'||lower(?)||'%' OR lower(?) LIKE '%'||lower(tag)||'%') ORDER BY n DESC LIMIT 8`, q, q)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	var cands []string
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			cands = append(cands, t)
		}
	}
	if len(cands) == 1 {
		return cands[0], nil, nil
	}
	return "", cands, nil
}

func kbTechList(ctx context.Context, idx *sql.DB) string {
	rows, err := idx.QueryContext(ctx, `SELECT tag||' ('||n||')' FROM tag_def WHERE dim='tech' ORDER BY n DESC`)
	if err != nil {
		return ""
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			out = append(out, t)
		}
	}
	return strings.Join(out, ", ")
}

// kbSnippet returns a short reproduce/description snippet for one report.
func kbSnippet(ctx context.Context, id int64, n int) string {
	db := vulnKB()
	if db == nil {
		return ""
	}
	var s string
	_ = db.QueryRowContext(ctx, `SELECT substr(COALESCE(NULLIF(reproduce,''), description, ''),1,?) FROM issues_fts WHERE rowid=?`, n*2, id).Scan(&s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func reconVulnKBProfile() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "vuln_kb_profile",
		Description: "Characteristic-vulnerability profile of a tech/framework/product from the vuln KB (~130k real reports grouped by bug class, bypass technique, impact, CVE). Call it RIGHT AFTER fingerprinting a host (e.g. tech='Spring', 'Keycloak', 'WordPress', 'GraphQL', 'Jenkins', 'Laravel', 'ASP.NET', 'Exchange') to get, ranked by how much more often they occur on that tech than on average: the bug classes to prioritise, the bypass techniques seen, the typical impacts (ATO/RCE/admin/data), known CVEs (KEV first) and the best reusable testcases — each with a report id. Then pull full reproduce steps with query_vuln_kb(tech=..., vclass=... / bypass=... / impact=...). " + kbReferenceNote,
		Schema: rtObj(map[string]any{
			"tech": rtStr("tech / framework / product name, e.g. 'Spring', 'Keycloak', 'WordPress', 'GraphQL'. Omit to list every indexed tech."),
		}),
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p struct {
				Tech string `json:"tech"`
			}
			_ = json.Unmarshal(in, &p)
			idx := vulnKBIndex()
			if idx == nil {
				return actool.Errorf("vuln KB index not available (knowledge/tech_index.sqlite3 missing — build it with tools/kbtax/build.py)"), nil
			}
			if strings.TrimSpace(p.Tech) == "" {
				return actool.Text("Indexed techs (report count): " + kbTechList(ctx, idx)), nil
			}
			tech, cands, err := resolveKBTech(ctx, idx, p.Tech)
			if err != nil {
				return actool.Errorf("vuln KB index query failed: " + err.Error()), nil
			}
			if tech == "" {
				if len(cands) > 0 {
					return actool.Text(fmt.Sprintf("Ambiguous tech %q — pick one: %s", p.Tech, strings.Join(cands, ", "))), nil
				}
				return actool.Text(fmt.Sprintf("No indexed tech matches %q. Use query_vuln_kb with keywords instead. Indexed techs: %s", p.Tech, kbTechList(ctx, idx))), nil
			}
			out, err := kbProfile(ctx, idx, tech)
			if err != nil {
				return actool.Errorf("vuln KB profile failed: " + err.Error()), nil
			}
			return actool.Text(out), nil
		},
	})
}

func kbProfile(ctx context.Context, idx *sql.DB, tech string) (string, error) {
	var total int
	_ = idx.QueryRowContext(ctx, `SELECT n FROM tag_def WHERE dim='tech' AND tag=?`, tech).Scan(&total)
	type row struct {
		dim, tag, label string
		n               int
		lift            float64
		ex              []int64
	}
	rows, err := idx.QueryContext(ctx, `SELECT p.dim, p.tag, COALESCE(d.label,p.tag), p.n, p.lift, p.examples
		FROM tech_profile p LEFT JOIN tag_def d ON d.dim=p.dim AND d.tag=p.tag
		WHERE p.tech=? AND p.dim IN ('class','bypass','impact') AND p.n>=5`, tech)
	if err != nil {
		return "", err
	}
	byDim := map[string][]row{}
	for rows.Next() {
		var r row
		var ex string
		if err := rows.Scan(&r.dim, &r.tag, &r.label, &r.n, &r.lift, &ex); err != nil {
			rows.Close()
			return "", err
		}
		_ = json.Unmarshal([]byte(ex), &r.ex)
		if r.tag == "other_bypass" || r.tag == "unclassified" {
			continue
		}
		byDim[r.dim] = append(byDim[r.dim], r)
	}
	rows.Close()
	score := func(r row) float64 { return r.lift * math.Log(float64(r.n)+1) }
	var b strings.Builder
	fmt.Fprintf(&b, "KB profile — %s (%d reports)\n", tech, total)
	sections := []struct {
		dim, title string
		max        int
		minLift    float64
	}{
		{"class", "Characteristic bug classes (×lift vs whole KB, report count)", 9, 1.2},
		{"bypass", "Bypass techniques seen on this tech", 5, 0},
		{"impact", "Typical impact", 5, 0},
	}
	for _, sec := range sections {
		list := byDim[sec.dim]
		sort.Slice(list, func(i, j int) bool { return score(list[i]) > score(list[j]) })
		shown := 0
		for _, r := range list {
			if r.lift < sec.minLift || shown >= sec.max {
				continue
			}
			if shown == 0 {
				fmt.Fprintf(&b, "\n%s:\n", sec.title)
			}
			shown++
			fmt.Fprintf(&b, "- %s [%s=%s] ×%.1f (%d)", r.label, sec.dim, r.tag, r.lift, r.n)
			if len(r.ex) > 0 {
				var title, sev string
				_ = idx.QueryRowContext(ctx, `SELECT title, severity FROM issue_meta WHERE issue_id=?`, r.ex[0]).Scan(&title, &sev)
				fmt.Fprintf(&b, " — e.g. #%d [%s] %s", r.ex[0], sev, strings.TrimSpace(title))
				if sec.dim == "class" && shown <= 5 {
					if sn := kbSnippet(ctx, r.ex[0], 220); sn != "" {
						fmt.Fprintf(&b, "\n    ↳ %s", sn)
					}
				}
			}
			b.WriteString("\n")
		}
	}
	// Known CVEs for this tech, KEV first.
	crow, err := idx.QueryContext(ctx, `SELECT m.cves, m.source, m.severity FROM issue_meta m JOIN issue_tag t ON t.issue_id=m.issue_id
		WHERE t.dim='tech' AND t.tag=? AND m.cves<>''`, tech)
	if err == nil {
		type cv struct {
			id       string
			n        int
			kev      bool
			critical bool
		}
		m := map[string]*cv{}
		for crow.Next() {
			var cves, src, sev string
			if crow.Scan(&cves, &src, &sev) != nil {
				continue
			}
			for _, c := range strings.Split(cves, ",") {
				if c == "" {
					continue
				}
				e := m[c]
				if e == nil {
					e = &cv{id: c}
					m[c] = e
				}
				e.n++
				e.kev = e.kev || src == "kev"
				e.critical = e.critical || sev == "CRITICAL"
			}
		}
		crow.Close()
		list := make([]*cv, 0, len(m))
		for _, e := range m {
			list = append(list, e)
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].kev != list[j].kev {
				return list[i].kev
			}
			if list[i].n != list[j].n {
				return list[i].n > list[j].n
			}
			return list[i].id > list[j].id
		})
		if len(list) > 0 {
			fmt.Fprintf(&b, "\nKnown CVEs in the KB (%d; KEV = exploited in the wild) — check which apply to the exact version:\n", len(list))
			for i, e := range list {
				if i >= 15 {
					break
				}
				tag := ""
				if e.kev {
					tag = " KEV"
				}
				fmt.Fprintf(&b, "%s%s(%d) ", e.id, tag, e.n)
			}
			b.WriteString("\n")
		}
	}
	// Best reusable testcases (quality A) for this tech.
	trow, err := idx.QueryContext(ctx, `SELECT m.issue_id, m.severity, m.source, m.title FROM issue_meta m JOIN issue_tag t ON t.issue_id=m.issue_id
		WHERE t.dim='tech' AND t.tag=? AND m.quality='A' AND m.source IN ('internal','bugbounty') ORDER BY m.score DESC, m.issue_id DESC LIMIT 8`, tech)
	if err == nil {
		first := true
		for trow.Next() {
			var id int64
			var sev, src, title string
			if trow.Scan(&id, &sev, &src, &title) != nil {
				continue
			}
			if first {
				b.WriteString("\nBest testcases (full steps, chained impact):\n")
				first = false
			}
			fmt.Fprintf(&b, "- #%d [%s/%s] %s\n", id, sev, src, strings.TrimSpace(title))
		}
		trow.Close()
	}
	fmt.Fprintf(&b, "\nNext: query_vuln_kb(tech=%q, vclass=<class> | bypass=<tag> | impact=<tag>, quality=\"A\") for full reproduce steps; ids above can be fetched with query_vuln_kb(id=<n>).\n%s", tech, kbReferenceNote)
	return b.String(), nil
}

// kbFilterIDs returns report ids matching the grouped-view filters ("" = no
// filter), best quality first; nil,false when no filter was given.
func kbFilterIDs(ctx context.Context, tech, vclass, bypass, impact, quality, source string, limit int) ([]int64, bool, error) {
	conds := []struct{ dim, tag string }{}
	for _, f := range []struct{ dim, v string }{{"tech", tech}, {"class", vclass}, {"bypass", bypass}, {"impact", impact}} {
		if v := strings.TrimSpace(f.v); v != "" {
			conds = append(conds, struct{ dim, tag string }{f.dim, v})
		}
	}
	quality, source = strings.ToUpper(strings.TrimSpace(quality)), strings.ToLower(strings.TrimSpace(source))
	if len(conds) == 0 && quality == "" && source == "" {
		return nil, false, nil
	}
	idx := vulnKBIndex()
	if idx == nil {
		return nil, true, fmt.Errorf("vuln KB index not available")
	}
	if tech != "" {
		if t, _, err := resolveKBTech(ctx, idx, tech); err == nil && t != "" {
			for i := range conds {
				if conds[i].dim == "tech" {
					conds[i].tag = t
				}
			}
		}
	}
	q := `SELECT m.issue_id FROM issue_meta m WHERE 1=1`
	args := []any{}
	for _, c := range conds {
		q += ` AND EXISTS (SELECT 1 FROM issue_tag t WHERE t.issue_id=m.issue_id AND t.dim=? AND lower(t.tag)=lower(?))`
		args = append(args, c.dim, c.tag)
	}
	if quality != "" {
		q += ` AND m.quality <= ?` // "A" -> A only, "B" -> A+B
		args = append(args, quality)
	}
	if source != "" {
		q += ` AND m.source=?`
		args = append(args, source)
	}
	q += ` ORDER BY m.score DESC, m.issue_id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := idx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, true, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids, true, rows.Err()
}
