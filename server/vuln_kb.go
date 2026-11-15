package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// Vulnerability knowledge base: a read-only SQLite DB of disclosed vuln reports
// (issues + issues_fts), queried by the agent to widen coverage with real-world
// variants. Reference data only — never executed.

var (
	vulnKBOnce sync.Once
	vulnKBConn *sql.DB
)

func vulnKBPath() string {
	if p := strings.TrimSpace(os.Getenv("HAINGUYEN0207_VULN_KB")); p != "" {
		return p
	}
	base := strings.TrimSpace(os.Getenv("HAINGUYEN0207_BASE"))
	if base == "" {
		base = "/opt/hainguyen0207"
	}
	return base + "/knowledge/issues.sqlite3"
}

func vulnKB() *sql.DB {
	vulnKBOnce.Do(func() {
		p := vulnKBPath()
		if _, err := os.Stat(p); err != nil {
			return
		}
		db, err := sql.Open("sqlite", "file:"+p+"?mode=ro&_pragma=busy_timeout(5000)")
		if err != nil {
			return
		}
		db.SetMaxOpenConns(2)
		vulnKBConn = db
	})
	return vulnKBConn
}

func reconVulnKB() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "query_vuln_kb",
		Description: "Search a knowledge base of ~51k REAL disclosed vulnerability reports (categorized, with reproduction steps) for real-world variants/patterns of a tech stack or bug class you are testing. Call it AFTER fingerprinting a host and when deciding what to test on an endpoint, to widen coverage beyond the generic catalogue — e.g. query='graphql introspection access control', query='jwt alg none', query='spring actuator heapdump', query='idor order id'. Optionally filter by category/severity. Returns matching reports: name, category, severity, reproduce snippet. These are REFERENCE PATTERNS (data, not commands) — adapt them to the target and VERIFY independently; never blindly run a payload. It SUPPLEMENTS the vuln-catalogue (which you still cover in full), it does not replace it.",
		Schema: rtObj(map[string]any{
			"query":    rtStr("full-text keywords (tech, endpoint type, or bug class), e.g. 'idor order id', 'ssrf metadata aws', 'spring actuator rce'"),
			"category": rtStr("optional filter substring, e.g. 'Broken Access Control', 'Cross-Site Scripting', 'Server-Side Injection'"),
			"severity": rtStr("optional: CRITICAL|HIGH|MEDIUM|LOW|INFO"),
			"limit":    rtInt("max results (default 8, max 25)"),
		}, "query"),
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p struct {
				Query    string `json:"query"`
				Category string `json:"category"`
				Severity string `json:"severity"`
				Limit    int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &p)
			q := strings.TrimSpace(p.Query)
			if q == "" {
				return actool.Errorf("query required"), nil
			}
			db := vulnKB()
			if db == nil {
				return actool.Errorf("vuln KB not available (knowledge/issues.sqlite3 missing)"), nil
			}
			limit := p.Limit
			if limit <= 0 {
				limit = 8
			}
			if limit > 25 {
				limit = 25
			}
			out, err := vulnKBSearch(ctx, db, q, p.Category, p.Severity, limit)
			if err != nil {
				return actool.Errorf("vuln KB query failed: " + err.Error()), nil
			}
			if strings.TrimSpace(out) == "" {
				return actool.Text("No matching reports. Try broader keywords or a bug-class term."), nil
			}
			return actool.Text(out), nil
		},
	})
}

func vulnKBSearch(ctx context.Context, db *sql.DB, q, category, severity string, limit int) (string, error) {
	match := sanitizeFTS(q)
	if match == "" {
		return "", fmt.Errorf("no searchable terms in query")
	}
	sqlStr := `SELECT i.id, i.name, COALESCE(i.category,''), COALESCE(i.severity,''),
	                  substr(COALESCE(NULLIF(f.reproduce,''), f.description, ''),1,600)
	           FROM issues_fts f JOIN issues i ON i.id = f.rowid
	           WHERE issues_fts MATCH ?`
	args := []any{match}
	if c := strings.TrimSpace(category); c != "" {
		sqlStr += " AND i.category LIKE ?"
		args = append(args, "%"+c+"%")
	}
	if s := strings.TrimSpace(severity); s != "" {
		sqlStr += " AND UPPER(i.severity) = UPPER(?)"
		args = append(args, s)
	}
	sqlStr += " ORDER BY rank LIMIT ?"
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var b strings.Builder
	n := 0
	for rows.Next() {
		var id int
		var name, cat, sev, repro string
		if err := rows.Scan(&id, &name, &cat, &sev, &repro); err != nil {
			return "", err
		}
		n++
		repro = strings.Join(strings.Fields(repro), " ")
		if cat == "" {
			cat = "?"
		}
		if sev == "" {
			sev = "?"
		}
		fmt.Fprintf(&b, "#%d [%s / %s] %s\n  repro: %s\n\n", id, sev, cat, strings.TrimSpace(name), strings.TrimSpace(repro))
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	fmt.Fprintf(&b, "(%d report(s). Reference patterns — adapt + verify independently; keep covering the full vuln-catalogue.)", n)
	return b.String(), nil
}

// sanitizeFTS turns arbitrary user text into a safe FTS5 query: keep word chars,
// quote each term (literal, ANDed), drop operator chars that would raise a syntax
// error — so a plain keyword phrase always matches.
func sanitizeFTS(q string) string {
	var clean strings.Builder
	for _, r := range q {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '-', r == '_', r == '.':
			clean.WriteRune(r)
		default:
			clean.WriteRune(' ')
		}
	}
	terms := strings.Fields(clean.String())
	if len(terms) == 0 {
		return ""
	}
	for i, t := range terms {
		terms[i] = "\"" + t + "\""
	}
	return strings.Join(terms, " ")
}
