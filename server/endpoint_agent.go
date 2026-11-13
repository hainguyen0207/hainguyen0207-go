package server

// Endpoint Reconstructor & Appraiser — a standalone chat-agent persona
// ("endpoint_recon") that turns the endpoints the recon workflows found
// (especially those extracted from JavaScript) into a rich, fully-processed asset
// inventory: it reconstructs a complete HTTP request (method + query/body/header
// params) per endpoint, optionally REPLAYS it safely to observe the real response,
// writes a rich endpoint asset (url + method + params + status + source), and
// appraises each endpoint's value as attack surface.
//
// Gating: the whole feature is off by default. The two server-side tools below
// refuse unless `endpoint_reconstructor` is on; write HTTP methods in
// replay_endpoint additionally require `endpoint_replay_write`. Reading the
// discovered surface reuses the always-present recon_* tools (recon_findings /
// recon_assets / recon_graph), so no new read tool is needed.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	settingEndpointReconstructor = "endpoint_reconstructor"
	settingEndpointReplayWrite   = "endpoint_replay_write"
)

// endpointReconTools are the two host tools exclusive to the endpoint_recon
// agent (seeded + bound to it only). Added to every agent's base via hostTools, then
// kept only for its bound agent by ToolResolve.
func (s *Server) endpointReconTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolSyncReconAssets(),
		s.toolExtractJSEndpoints(),
		s.toolReplayEndpoint(),
		s.toolUpsertEndpointAsset(),
	}
}

var endpointReconToolKeys = []string{"sync_recon_assets", "extract_js_endpoints", "replay_endpoint", "upsert_endpoint_asset"}

// ---- #3 endpoint URL normalization (dedup variants) ----

var (
	numSegRe  = regexp.MustCompile(`^\d+$`)
	uuidSegRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexSegRe  = regexp.MustCompile(`^[0-9a-f]{8,}$`)
)

// normalizeEndpointURL templatizes volatile path segments (numeric ids, uuids, long
// hashes → {id}/{uuid}/{hash}) and blanks query values (keeping keys), so /user/1?t=a
// and /user/2?t=b collapse to one inventory endpoint instead of flooding it.
func normalizeEndpointURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return raw
	}
	if u.Path != "" {
		segs := strings.Split(u.Path, "/")
		for i, s := range segs {
			ls := strings.ToLower(s)
			switch {
			case numSegRe.MatchString(s):
				segs[i] = "{id}"
			case uuidSegRe.MatchString(ls):
				segs[i] = "{uuid}"
			case hexSegRe.MatchString(ls):
				segs[i] = "{hash}"
			}
		}
		u.Path = strings.Join(segs, "/")
	}
	if u.RawQuery != "" {
		keys := make([]string, 0)
		for k := range u.Query() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		nq := url.Values{}
		for _, k := range keys {
			nq.Set(k, "")
		}
		u.RawQuery = nq.Encode()
	}
	return u.String()
}

// ---- #2 deterministic attack-surface appraisal ----

var appraiseSensitivePaths = map[string]int{
	"admin": 25, "wp-admin": 15, "internal": 20, "debug": 20, "graphql": 20, "actuator": 25,
	"swagger": 10, "openapi": 10, "api-docs": 10, "upload": 20, ".git": 30, ".env": 25, "backup": 20,
	"console": 15, "metrics": 10, "config": 15, "phpinfo": 20, "jenkins": 20, "kibana": 15, "grafana": 10,
	"phpmyadmin": 20, "server-status": 15, "trace": 10, "heapdump": 25,
}
var appraiseSuspParams = map[string]string{
	"id": "idor", "uid": "idor", "user": "idor", "account": "idor", "order": "idor", "doc": "idor",
	"file": "lfi", "path": "lfi", "dir": "lfi", "template": "ssti", "page": "lfi",
	"url": "ssrf", "uri": "ssrf", "dest": "ssrf", "callback": "ssrf", "feed": "ssrf", "target": "ssrf",
	"redirect": "openredirect", "return": "openredirect", "returnurl": "openredirect", "next": "openredirect",
	"cmd": "rce", "exec": "rce", "command": "rce", "ping": "rce",
	"q": "injection", "query": "injection", "search": "injection", "filter": "injection", "sort": "injection",
	"token": "secret", "key": "secret", "apikey": "secret", "password": "secret", "secret": "secret",
	"role": "privesc", "is_admin": "privesc", "admin": "privesc", "debug": "debug",
}

// appraiseEndpoint scores an endpoint's value as attack surface (0-100) with tags/hint,
// deterministically — so every endpoint is appraised even without the LLM agent.
func appraiseEndpoint(rawURL, method string, params []map[string]any) map[string]any {
	u, _ := url.Parse(rawURL)
	path := ""
	names := map[string]bool{}
	if u != nil {
		path = strings.ToLower(u.Path)
		for k := range u.Query() {
			names[strings.ToLower(k)] = true
		}
	}
	for _, p := range params {
		if n, ok := p["name"].(string); ok && n != "" {
			names[strings.ToLower(n)] = true
		}
	}
	score := 0
	tagSet := map[string]bool{}
	add := func(pts int, tag string) {
		score += pts
		tagSet[tag] = true
	}
	for k, v := range appraiseSensitivePaths {
		if strings.Contains(path, k) {
			add(v, "path:"+k)
		}
	}
	for n := range names {
		if cls, ok := appraiseSuspParams[n]; ok {
			add(12, cls+":"+n)
		}
	}
	if m := strings.ToUpper(method); m != "" && m != "GET" && m != "HEAD" && m != "OPTIONS" {
		add(8, "method:"+m)
	}
	if score > 100 {
		score = 100
	}
	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	hint := "low-value"
	switch {
	case score >= 60:
		hint = "high-value: probe auth/IDOR/injection first"
	case score >= 30:
		hint = "medium-value: worth testing"
	}
	out := map[string]any{"score": score, "hint": hint}
	if len(tags) > 0 {
		out["tags"] = tags
	}
	return out
}

// ---- #4 common port → service name (deterministic service labelling) ----

var commonPortService = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 110: "pop3", 111: "rpcbind",
	135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 445: "smb",
	465: "smtps", 587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
	1521: "oracle", 1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker",
	3306: "mysql", 3389: "rdp", 5432: "postgres", 5672: "amqp", 5900: "vnc", 5985: "winrm",
	5986: "winrm", 6379: "redis", 6443: "kubernetes-api", 7001: "weblogic", 8086: "influxdb",
	9042: "cassandra", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch",
	10250: "kubelet", 11211: "memcached", 15672: "rabbitmq", 27017: "mongodb",
}

func portServiceName(port int) string { return commonPortService[port] }

// ---- #1 deterministic JS endpoint extraction (no LLM) ----

// resolveJSEndpoint turns a raw token extracted from JS into an absolute http(s) URL,
// resolved against the JS file's own URL. Conservative: only accepts clearly
// path/URL-shaped tokens (leading /, //, ./, ../, or absolute) to avoid promoting
// mime-types / arbitrary strings the regex also matches.
func resolveJSEndpoint(base *url.URL, ep string) string {
	ep = strings.TrimSpace(ep)
	if len(ep) < 2 {
		return ""
	}
	switch {
	case strings.HasPrefix(ep, "http://"), strings.HasPrefix(ep, "https://"):
		return ep
	case strings.HasPrefix(ep, "//"):
		sc := "https"
		if base != nil && base.Scheme != "" {
			sc = base.Scheme
		}
		return sc + ":" + ep
	case strings.HasPrefix(ep, "/"), strings.HasPrefix(ep, "./"), strings.HasPrefix(ep, "../"):
		if base == nil {
			return ""
		}
		r, err := base.Parse(ep)
		if err != nil || (r.Scheme != "http" && r.Scheme != "https") {
			return ""
		}
		return r.String()
	default:
		return "" // bare token (mime type, word) — skip to keep the inventory clean
	}
}

// syncJSEndpoints deterministically downloads a target's JavaScript files (from the
// recon url findings) and promotes every endpoint hiding inside them into the asset
// inventory (source=js), with normalization + appraisal — no LLM involved. Bounded by
// file + endpoint caps so it stays efficient.
func (s *Server) syncJSEndpoints(ctx context.Context, as *db.AssetStore, target string) (int, int) {
	if as == nil {
		return 0, 0
	}
	data, err := reconGetJSON(ctx, fmt.Sprintf("/api/v1/findings?host=%s&kind=url&limit=8000", url.QueryEscape(target)))
	if err != nil {
		return 0, 1
	}
	var wrap struct {
		Items []struct {
			URL *string `json:"url"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &wrap)
	var jsURLs []string
	seen := map[string]bool{}
	for _, it := range wrap.Items {
		if it.URL == nil {
			continue
		}
		u := strings.TrimSpace(*it.URL)
		base := strings.ToLower(u)
		if i := strings.IndexAny(base, "?#"); i >= 0 {
			base = base[:i]
		}
		if strings.HasSuffix(base, ".js") && !seen[u] {
			seen[u] = true
			jsURLs = append(jsURLs, u)
			if len(jsURLs) >= 150 { // cap JS files per run
				break
			}
		}
	}
	if len(jsURLs) == 0 {
		return 0, 0
	}
	client := replayHTTPClient(10 * time.Second)
	added, errs := 0, 0
	for _, ju := range jsURLs {
		if added >= 4000 { // overall endpoint cap
			break
		}
		req, err := http.NewRequestWithContext(ctx, "GET", ju, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "k1nzr3c0n-endpoint-recon/1.0")
		resp, err := client.Do(req)
		if err != nil {
			errs++
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 3<<20))
		resp.Body.Close()
		base, _ := url.Parse(ju)
		eseen := map[string]bool{}
		for _, m := range jsEndpointRe.FindAllSubmatch(body, -1) {
			if len(m) < 2 {
				continue
			}
			abs := resolveJSEndpoint(base, strings.TrimSpace(string(m[1])))
			if abs == "" {
				continue
			}
			nurl := normalizeEndpointURL(abs)
			if nurl == "" || eseen[nurl] {
				continue
			}
			eseen[nurl] = true
			extra := map[string]any{
				"source": "js", "from_js": ju, "reconstructed": true,
				"appraisal": appraiseEndpoint(nurl, "GET", nil),
			}
			if _, err := as.UpsertEndpoint(db.UpsertEndpointReq{URL: nurl, Method: "GET", Extra: extra}); err == nil {
				added++
			}
		}
	}
	return added, errs
}

// ---- safe HTTP replay client ----

// isBlockedReplayIP blocks only the addresses that are never a legitimate replay
// target: loopback, link-local (incl. the 169.254.169.254 cloud-metadata IP),
// unspecified, and multicast. RFC1918 is deliberately ALLOWED — an authorized
// engagement's scope often includes internal hosts.
func isBlockedReplayIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast()
}

// replayHTTPClient builds an HTTP client that resolves the host, rejects blocked
// addresses at dial time (defeating DNS rebinding), caps redirects, and tolerates
// self-signed TLS (pentest targets routinely have bad certs).
func replayHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if isBlockedReplayIP(ip.IP) {
					return nil, fmt.Errorf("blocked address %s (loopback/link-local/metadata are not replayable)", ip.IP)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // pentest targets often use self-signed certs
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          10,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

var replayTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractReplayTitle(b []byte) string {
	m := replayTitleRe.FindSubmatch(b)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(string(m[1]))
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

func isWriteMethod(m string) bool {
	switch m {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// jsEndpointRe is a LinkFinder-style regex: it pulls quoted strings that look like
// URLs, absolute/relative paths, or file references out of JavaScript source.
var jsEndpointRe = regexp.MustCompile(`(?:"|')((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}|(?:/|\.\./|\./)[^"'><,;| *()%$^/\\\[\]][^"'><,;|()]{1,}|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,})?|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,})?|[a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,})?)(?:"|')`)

// toolExtractJSEndpoints downloads one JavaScript file and regex-extracts the
// endpoints/paths referenced inside it (so the agent itself pulls endpoints out of
// JS, not only what the recon workflow already extracted). Returns a deduped list;
// the agent then reconstructs + upserts each as an endpoint asset with source=js.
func (s *Server) toolExtractJSEndpoints() actool.CoreTool {
	return wrTool("extract_js_endpoints",
		"Download ONE JavaScript file and extract the endpoints/paths referenced inside it (LinkFinder-style). "+
			"Use it to list the real endpoints hiding in a site's JS: first find .js URLs (recon_findings kind=url, or recon_assets), then call this per JS file. "+
			"Returns {js_url, count, endpoints:[...]} (relative + absolute). Resolve relative ones against the site base, then reconstruct + upsert_endpoint_asset each with source=js and from_js=<this js_url>.",
		objSchema(map[string]any{
			"js_url": strParam("absolute URL of a .js file to fetch and parse"),
		}, "js_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if !s.m.pg.GetBool(settingEndpointReconstructor, false) {
				return actool.Errorf("feature disabled: endpoint_reconstructor (enable it in Settings → Endpoint reconstructor)"), nil
			}
			var a struct {
				JSURL string `json:"js_url"`
			}
			_ = json.Unmarshal(in, &a)
			u, err := url.Parse(strings.TrimSpace(a.JSURL))
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return actool.Errorf("invalid js_url (must be absolute http/https)"), nil
			}
			req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			req.Header.Set("User-Agent", "k1nzr3c0n-endpoint-recon/1.0")
			resp, err := replayHTTPClient(12 * time.Second).Do(req)
			if err != nil {
				return actool.Errorf("fetch failed: " + err.Error()), nil
			}
			defer resp.Body.Close()
			const maxJS = 3 << 20 // 3 MiB
			data, _ := io.ReadAll(io.LimitReader(resp.Body, maxJS))
			seen := map[string]bool{}
			var eps []string
			for _, m := range jsEndpointRe.FindAllSubmatch(data, -1) {
				if len(m) < 2 {
					continue
				}
				ep := strings.TrimSpace(string(m[1]))
				// drop obvious noise: bare file names with no path separator and very short tokens
				if ep == "" || len(ep) < 2 || seen[ep] {
					continue
				}
				seen[ep] = true
				eps = append(eps, ep)
				if len(eps) >= 1000 {
					break
				}
			}
			return jsonResult(map[string]any{
				"js_url":    u.String(),
				"status":    resp.StatusCode,
				"bytes":     len(data),
				"count":     len(eps),
				"endpoints": eps,
			})
		})
}

// toolReplayEndpoint sends a reconstructed request and returns the real response
// shape (status / content-type / length / title / auth-gate / redirect). Default
// GET/HEAD/OPTIONS; write methods are gated behind endpoint_replay_write.
func (s *Server) toolReplayEndpoint() actool.CoreTool {
	return wrTool("replay_endpoint",
		"Send a reconstructed HTTP request to observe its REAL response (status, content-type, length, title, whether it is auth-gated, redirect). "+
			"Default method GET; HEAD/OPTIONS also safe. POST/PUT/PATCH/DELETE are sent only when the endpoint_replay_write setting is on. "+
			"Use SAFE, non-destructive param values. Loopback/link-local/cloud-metadata addresses are refused. Returns a JSON response summary + a short body snippet.",
		objSchema(map[string]any{
			"url":        strParam("absolute URL to send (http/https, host+path+query)"),
			"method":     strParam("HTTP method (default GET). POST/PUT/PATCH/DELETE require endpoint_replay_write=on."),
			"headers":    map[string]any{"type": "object", "description": "optional request headers {Name: Value} (e.g. Content-Type, Authorization, a session cookie)"},
			"body":       strParam("optional request body (only used for POST/PUT/PATCH/DELETE)"),
			"timeout_ms": map[string]any{"type": "integer", "description": "request timeout in ms (default 8000, max 20000)"},
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if !s.m.pg.GetBool(settingEndpointReconstructor, false) {
				return actool.Errorf("feature disabled: endpoint_reconstructor (enable it in Settings → Endpoint reconstructor)"), nil
			}
			var a struct {
				URL       string            `json:"url"`
				Method    string            `json:"method"`
				Headers   map[string]string `json:"headers"`
				Body      string            `json:"body"`
				TimeoutMs int               `json:"timeout_ms"`
			}
			_ = json.Unmarshal(in, &a)
			method := strings.ToUpper(strings.TrimSpace(a.Method))
			if method == "" {
				method = "GET"
			}
			switch method {
			case "GET", "HEAD", "OPTIONS":
			case "POST", "PUT", "PATCH", "DELETE":
				if !s.m.pg.GetBool(settingEndpointReplayWrite, false) {
					return actool.Errorf("write method " + method + " is disabled: turn on endpoint_replay_write to allow non-idempotent replay"), nil
				}
			default:
				return actool.Errorf("unsupported method: " + method), nil
			}
			u, err := url.Parse(strings.TrimSpace(a.URL))
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return actool.Errorf("invalid url (must be absolute http/https)"), nil
			}
			timeout := time.Duration(a.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 8 * time.Second
			}
			if timeout > 20*time.Second {
				timeout = 20 * time.Second
			}
			var bodyReader io.Reader
			if a.Body != "" && isWriteMethod(method) {
				bodyReader = strings.NewReader(a.Body)
			}
			req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			req.Header.Set("User-Agent", "k1nzr3c0n-endpoint-recon/1.0")
			for k, v := range a.Headers {
				req.Header.Set(k, v)
			}
			resp, err := replayHTTPClient(timeout).Do(req)
			if err != nil {
				return jsonResult(map[string]any{"url": u.String(), "method": method, "error": err.Error()})
			}
			defer resp.Body.Close()
			const maxBody = 256 * 1024
			data, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
			out := map[string]any{
				"url":            u.String(),
				"final_url":      resp.Request.URL.String(),
				"method":         method,
				"status_code":    resp.StatusCode,
				"content_type":   resp.Header.Get("Content-Type"),
				"content_length": len(data),
				"title":          extractReplayTitle(data),
				"auth_gated":     resp.StatusCode == 401 || resp.StatusCode == 403,
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				out["redirect_location"] = loc
			}
			if len(data) > 0 {
				snippet := data
				if len(snippet) > 2000 {
					snippet = snippet[:2000]
				}
				out["body_snippet"] = string(snippet)
			}
			return jsonResult(out)
		})
}

// toolUpsertEndpointAsset writes a rich endpoint asset into the shared asset
// inventory (db.AssetStore), carrying the full processed data: method, params with
// their location, observed status/length/content-type, provenance (source/from_js)
// and the attack-surface appraisal. Idempotent by (url, method).
func (s *Server) toolUpsertEndpointAsset() actool.CoreTool {
	return wrTool("upsert_endpoint_asset",
		"Write a fully-processed endpoint into the shared asset inventory (idempotent by url+method). Store EVERYTHING you reconstructed/observed: "+
			"method, params (each with its location), the replayed status/length/content-type, where it came from (source, from_js), and the value appraisal. "+
			"This is how a domain's endpoints — including those found only in JavaScript — become queryable assets with method/param/status.",
		objSchema(map[string]any{
			"url":    strParam("absolute endpoint URL (host+path; keep path-template markers like /user/{id})"),
			"method": strParam("HTTP method (default GET)"),
			"params": map[string]any{"type": "array", "description": "reconstructed params", "items": objSchema(map[string]any{
				"location": strParam("query | body | path | header"),
				"name":     strParam("param name"),
				"value":    strParam("example/placeholder value (optional)"),
				"type":     strParam("value type hint, e.g. int/string/bool (optional)"),
			}, "name")},
			"status_code":    map[string]any{"type": "integer", "description": "observed HTTP status from replay (optional)"},
			"content_length": map[string]any{"type": "integer", "description": "observed response length in bytes (optional)"},
			"content_type":   strParam("observed Content-Type (optional)"),
			"source":         strParam("provenance: js | crawl | dir-brute | swagger | param-discovery"),
			"from_js":        strParam("the JS file the endpoint was extracted from, when known (optional)"),
			"reconstructed":  map[string]any{"type": "boolean", "description": "true when the request signature was reconstructed/synthesized"},
			"synthetic":      map[string]any{"type": "boolean", "description": "true when placeholder param values were used"},
			"appraisal":      map[string]any{"type": "object", "description": "attack-surface value appraisal {score: 0-100, tags: [..], hint: \"..\"}"},
			"ip":             strParam("resolved IP (optional)"),
		}, "url"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if !s.m.pg.GetBool(settingEndpointReconstructor, false) {
				return actool.Errorf("feature disabled: endpoint_reconstructor (enable it in Settings → Endpoint reconstructor)"), nil
			}
			as := s.assetStore()
			if as == nil {
				return actool.Errorf("asset store not initialized"), nil
			}
			var a struct {
				URL           string           `json:"url"`
				Method        string           `json:"method"`
				Params        []map[string]any `json:"params"`
				StatusCode    *int             `json:"status_code"`
				ContentLength *int64           `json:"content_length"`
				ContentType   string           `json:"content_type"`
				Source        string           `json:"source"`
				FromJS        string           `json:"from_js"`
				Reconstructed *bool            `json:"reconstructed"`
				Synthetic     *bool            `json:"synthetic"`
				Appraisal     map[string]any   `json:"appraisal"`
				IP            string           `json:"ip"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.URL) == "" {
				return actool.Errorf("url is required"), nil
			}
			method := strings.ToUpper(strings.TrimSpace(a.Method))
			if method == "" {
				method = "GET"
			}
			extra := map[string]any{}
			if a.ContentType != "" {
				extra["content_type"] = a.ContentType
			}
			if a.Source != "" {
				extra["source"] = a.Source
			}
			if a.FromJS != "" {
				extra["from_js"] = a.FromJS
			}
			if a.Reconstructed != nil {
				extra["reconstructed"] = *a.Reconstructed
			}
			if a.Synthetic != nil {
				extra["synthetic"] = *a.Synthetic
			}
			nurl := normalizeEndpointURL(a.URL) // #3 dedup variants
			if len(a.Appraisal) > 0 {
				extra["appraisal"] = a.Appraisal
			} else {
				extra["appraisal"] = appraiseEndpoint(nurl, method, a.Params) // #2 deterministic fallback
			}
			id, err := as.UpsertEndpoint(db.UpsertEndpointReq{
				URL:           nurl,
				Method:        method,
				Params:        a.Params,
				IP:            a.IP,
				StatusCode:    a.StatusCode,
				ContentLength: a.ContentLength,
				Extra:         extra,
			})
			if err != nil {
				return actool.Errorf("upsert failed: " + err.Error()), nil
			}
			return jsonResult(map[string]any{"ok": true, "id": id, "url": nurl, "method": method})
		})
}

// reconGetJSON does a localhost GET against the Workflow-Runner API and returns the
// raw body for unmarshaling (reconHTTP returns an actool.Result, not bytes).
func reconGetJSON(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", ReconAPIBase+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("recon API %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func rawToStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	_ = json.Unmarshal(raw, &out)
	return out
}

// endpointURLFrom builds an absolute endpoint URL: prefer the finding's url, else
// resolve a relative name/path against the (domain) host. Returns "" when unresolvable.
func endpointURLFrom(u, name *string, host string) string {
	if u != nil && strings.TrimSpace(*u) != "" {
		return strings.TrimSpace(*u)
	}
	if name == nil {
		return ""
	}
	p := strings.TrimSpace(*name)
	if p == "" || host == "" || net.ParseIP(host) != nil {
		return ""
	}
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return "https://" + host + p
}

// toolSyncReconAssets deterministically promotes EVERY asset the recon workflows
// produced for a target — subdomains, IPs, ports, live HTTP services, URLs/endpoints
// and params — into the shared rich asset inventory, so nothing is missed. It also
// guarantees every host/IP that appears on ANY finding (incl. cert/dns/secret/etc.)
// becomes an asset. One server-side pass; returns counts by type.
func (s *Server) toolSyncReconAssets() actool.CoreTool {
	return wrTool("sync_recon_assets",
		"Aggregate EVERYTHING the recon workflows found for a target into the shared asset inventory in one deterministic pass: every subdomain, IP, port, live HTTP service, URL/endpoint and param — plus the host/IP of every other finding (cert/dns/secret/…), so no asset is missed. "+
			"Run this FIRST, before deep-diving. Returns counts by type.",
		objSchema(map[string]any{
			"target": strParam("the target host/domain to aggregate, e.g. example.com"),
			"limit":  map[string]any{"type": "integer", "description": "max findings to scan (default 20000)"},
		}, "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if !s.m.pg.GetBool(settingEndpointReconstructor, false) {
				return actool.Errorf("feature disabled: endpoint_reconstructor (enable it in Settings → Endpoint reconstructor)"), nil
			}
			var a struct {
				Target string `json:"target"`
				Limit  int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			target := strings.TrimSpace(strings.ToLower(a.Target))
			if target == "" {
				return actool.Errorf("target is required"), nil
			}
			counts, errs := s.runReconAssetSync(ctx, target, a.Limit)
			out := map[string]any{"target": target, "counts": counts}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// runReconAssetSync is the shared deterministic promotion used by BOTH the
// sync_recon_assets tool and the automatic on-run-completion hook: it upserts every
// workflow-discovered asset for a target into the rich asset store and never drops a
// host/IP. maxScan<=0 defaults to 20000. Best-effort: errors are collected, not fatal.
func (s *Server) runReconAssetSync(ctx context.Context, target string, maxScan int) (map[string]int, []string) {
	counts := map[string]int{}
	var errs []string
	as := s.assetStore()
	if as == nil {
		return counts, []string{"asset store not initialized"}
	}
	if maxScan <= 0 {
		maxScan = 20000
	}
	note := func(k string) { counts[k]++ }
	noteErr := func(e error) {
		if e != nil && len(errs) < 20 {
			errs = append(errs, e.Error())
		}
	}

	// 1) Live HTTP services from the cross-run assets endpoint (richest http data: status/title/tech/ip/port).
	if data, err := reconGetJSON(ctx, "/api/v1/assets?limit=5000&q="+url.QueryEscape(target)); err == nil {
		var wrap struct {
			Items []struct {
				Host       string   `json:"host"`
				Port       int      `json:"port"`
				IP         string   `json:"ip"`
				URL        string   `json:"url"`
				Title      string   `json:"title"`
				StatusCode int      `json:"status_code"`
				Tech       []string `json:"tech"`
			} `json:"items"`
		}
		_ = json.Unmarshal(data, &wrap)
		for _, it := range wrap.Items {
			u := it.URL
			if u == "" && it.Host != "" {
				scheme := "https"
				if it.Port == 80 {
					scheme = "http"
				}
				u = scheme + "://" + it.Host
			}
			if u == "" {
				continue
			}
			req := db.UpsertHTTPServiceReq{URL: u, Technologies: it.Tech, PageTitle: it.Title}
			if it.StatusCode > 0 {
				sc := it.StatusCode
				req.StatusCode = &sc
			}
			if net.ParseIP(it.IP) != nil {
				req.IP = it.IP
			}
			if _, err := as.UpsertHTTPService(req); err != nil {
				noteErr(err)
			} else {
				note("service")
			}
		}
	} else {
		noteErr(err)
	}

	// 2) Every finding (all kinds), paginated — map structured kinds and never miss a host/IP.
	const perPage = 2000
	for offset := 0; offset < maxScan; offset += perPage {
		data, err := reconGetJSON(ctx, fmt.Sprintf("/api/v1/findings?host=%s&limit=%d&offset=%d", url.QueryEscape(target), perPage, offset))
		if err != nil {
			noteErr(err)
			break
		}
		var wrap struct {
			Total int `json:"total"`
			Items []struct {
				Kind  string          `json:"kind"`
				Host  string          `json:"host"`
				IP    *string         `json:"ip"`
				Port  *int            `json:"port"`
				URL   *string         `json:"url"`
				Name  *string         `json:"name"`
				Title *string         `json:"title"`
				Tech  json.RawMessage `json:"tech"`
			} `json:"items"`
		}
		_ = json.Unmarshal(data, &wrap)
		if len(wrap.Items) == 0 {
			break
		}
		for _, it := range wrap.Items {
			host := strings.TrimSpace(strings.ToLower(it.Host))
			var ip string
			if it.IP != nil {
				ip = strings.TrimSpace(*it.IP)
			}
			// Never miss a host/IP: promote them regardless of finding kind.
			if host != "" && net.ParseIP(host) == nil {
				if _, err := as.UpsertSubdomain(db.UpsertSubdomainReq{Domain: host}); err != nil {
					noteErr(err)
				}
			}
			if net.ParseIP(ip) != nil {
				var bd []string
				if host != "" && net.ParseIP(host) == nil {
					bd = []string{host}
				}
				if _, err := as.UpsertIP(db.UpsertIPReq{IP: ip, BoundDomains: bd}); err != nil {
					noteErr(err)
				}
			}
			switch it.Kind {
			case "subdomain":
				note("subdomain")
			case "ptr", "net", "asn":
				if net.ParseIP(ip) != nil {
					note("ip")
				}
			case "port":
				// Never lose a port. Prefer the IP (open_ports on the IP asset,
				// created if missing); if the finding has only a hostname and no IP,
				// record the port as a service asset so it still lands.
				if it.Port != nil && *it.Port > 0 {
					portIP := ""
					if net.ParseIP(ip) != nil {
						portIP = ip
					} else if net.ParseIP(host) != nil {
						portIP = host
					}
					svc := portServiceName(*it.Port) // #4 label well-known ports
					switch {
					case portIP != "":
						if _, err := as.UpsertIP(db.UpsertIPReq{IP: portIP, OpenPorts: []db.PortService{{Port: *it.Port, Service: svc}}}); err != nil {
							noteErr(err)
						} else {
							note("port")
						}
					case host != "":
						svcName := svc
						if svcName == "" {
							svcName = fmt.Sprintf("tcp/%d", *it.Port)
						}
						if _, err := as.UpsertOtherService(db.UpsertOtherServiceReq{Domain: host, Port: *it.Port, ServiceName: svcName}); err != nil {
							noteErr(err)
						} else {
							note("port")
						}
					}
				}
			case "http":
				if it.URL != nil && *it.URL != "" {
					req := db.UpsertHTTPServiceReq{URL: *it.URL, Technologies: rawToStrings(it.Tech)}
					if it.Title != nil {
						req.PageTitle = *it.Title
					}
					if net.ParseIP(ip) != nil {
						req.IP = ip
					}
					if _, err := as.UpsertHTTPService(req); err != nil {
						noteErr(err)
					} else {
						note("service")
					}
				}
			case "url", "endpoint":
				u := endpointURLFrom(it.URL, it.Name, host)
				if u == "" {
					continue
				}
				src := "crawl"
				if it.Kind == "endpoint" {
					src = "recon"
				}
				nu := normalizeEndpointURL(u) // #3 dedup variants
				if _, err := as.UpsertEndpoint(db.UpsertEndpointReq{URL: nu, Method: "GET", Extra: map[string]any{"source": src, "appraisal": appraiseEndpoint(nu, "GET", nil)}}); err != nil {
					noteErr(err)
				} else {
					note("endpoint")
				}
			case "param":
				u := endpointURLFrom(it.URL, nil, host)
				if u == "" || it.Name == nil || strings.TrimSpace(*it.Name) == "" {
					continue
				}
				params := []map[string]any{{"location": "query", "name": strings.TrimSpace(*it.Name)}}
				nu := normalizeEndpointURL(u) // #3 dedup variants
				if _, err := as.UpsertEndpoint(db.UpsertEndpointReq{URL: nu, Method: "GET", Params: params, Extra: map[string]any{"source": "param-discovery", "appraisal": appraiseEndpoint(nu, "GET", params)}}); err != nil {
					noteErr(err)
				} else {
					note("param")
				}
			}
		}
		if offset+perPage >= wrap.Total {
			break
		}
	}
	return counts, errs
}

// seedEndpointAgent presets the "Endpoint reconstructor" custom agent (builtin=false,
// editable/deletable in the UI) and binds its tools. One-time, settings-flag guarded:
// once the user deletes it, it is not recreated. No trigger — the operator starts a
// chat with it manually, and the gating settings keep it inert until enabled.
// Dependency: endpointReconTools were already SeedTool'd into the DB above this call.
func (s *Server) seedEndpointAgent() {
	const flag = "endpoint_recon_agent_seed_v2" // v2: retry even if a v1 run got stuck "done" without creating the row
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	// Already present (seeded earlier or created by hand) → mark done, don't overwrite.
	if exist, _ := s.m.pg.GetAgentByKey("endpoint_recon"); exist != nil {
		_ = s.m.pg.SetSetting(flag, "true")
		return
	}
	a, err := s.m.pg.CreateAgent("endpoint_recon", "Endpoint reconstructor",
		"Harvests recon/JS endpoints, reconstructs full requests (method+params), replays them safely, and writes rich endpoint assets with an attack-surface appraisal.")
	if err != nil {
		// Do NOT set the flag on failure — retry on the next startup instead of
		// getting stuck "done" with no agent row.
		log.Printf("[endpoint-recon] failed to create agent: %v", err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, agent.EndpointReconDefaultPrompt); err != nil {
		log.Printf("[endpoint-recon] failed to seed prompt: %v", err)
	}
	// Bind the endpoint tools + the rich-asset reader (for dedup). The recon_* read
	// tools are global (no DB row) so they reach every agent without binding.
	if err := s.m.pg.AddAgentToToolBinding("endpoint_recon", []string{
		"extract_js_endpoints", "replay_endpoint", "upsert_endpoint_asset",
		"sync_recon_assets", "list_assets",
	}); err != nil {
		log.Printf("[endpoint-recon] failed to bind tools: %v", err)
	}
	_ = s.m.pg.SetSetting(flag, "true") // mark done only after the agent row exists
	log.Printf("[endpoint-recon] preset the \"Endpoint reconstructor\" agent + tool bindings")
}

// seedWorkerEndpointTools binds the endpoint-recon tools to the built-in worker so
// EVERY pentest worker can run the JS endpoint flow itself (extract/replay/upsert +
// sync), matching the task template's per-worker JS requirement. The tools are still
// gated by the endpoint_reconstructor setting at call time. One-time, flag-guarded;
// a user who later unbinds them is not overridden.
func (s *Server) seedWorkerEndpointTools() {
	const flag = "worker_endpoint_tools_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("worker", []string{
		"extract_js_endpoints", "replay_endpoint", "upsert_endpoint_asset", "sync_recon_assets",
	}); err != nil {
		log.Printf("[endpoint-recon] failed to bind endpoint tools to worker: %v", err)
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[endpoint-recon] bound endpoint tools to worker (per-worker JS recon)")
}
