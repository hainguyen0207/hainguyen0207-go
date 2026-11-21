package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Telegram delivery of a finding's full Markdown report (event
// finding_report_ready). The report is rendered to Telegram HTML and split into
// as many messages as needed (Telegram caps a message at 4096 characters), then
// the exact report.md is attached as a document so it can be forwarded/submitted.

// telegramReportBudget is the per-message size budget for report parts, counted
// in runes of the HTML source (tags included), so the visible text is always
// below Telegram's 4096 limit.
const telegramReportBudget = 3800

// telegramPartGap spaces consecutive sends to the same chat (Telegram allows
// about one message per second per chat).
const telegramPartGap = 1100 * time.Millisecond

var (
	mdHeadingRe = regexp.MustCompile(`^#{1,6}\s+(.*)$`)
	mdBoldRe    = regexp.MustCompile(`\*\*([^*\n]+?)\*\*`)
	mdListRe    = regexp.MustCompile(`^(\s*)(?:[-*+]|\d+[.)])\s+(.*)$`)
	mdHRRe      = regexp.MustCompile(`^\s*([-*_])(\s*[-*_]){2,}\s*$`)
	htmlTagRe   = regexp.MustCompile(`<[^>]+>`)
)

// telegramInline renders one line's inline Markdown: `code` spans are only
// escaped (Telegram rejects entities nested inside code), **bold** elsewhere
// becomes <b>. Unbalanced markers are kept as literal text.
func telegramInline(s string) string {
	parts := strings.Split(s, "`")
	if len(parts)%2 == 0 { // odd number of backticks: no code spans
		return mdBoldRe.ReplaceAllString(telegramEscape(s), "<b>$1</b>")
	}
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 1 {
			if p != "" {
				b.WriteString("<code>" + telegramEscape(p) + "</code>")
			}
			continue
		}
		b.WriteString(mdBoldRe.ReplaceAllString(telegramEscape(p), "<b>$1</b>"))
	}
	return b.String()
}

// telegramMDLine renders a non-code Markdown line; "" means a blank line.
func telegramMDLine(raw string) string {
	t := strings.TrimRight(raw, " \t")
	if strings.TrimSpace(t) == "" {
		return ""
	}
	if m := mdHeadingRe.FindStringSubmatch(strings.TrimSpace(t)); m != nil {
		return "<b>" + telegramEscape(strings.Trim(m[1], "*# ")) + "</b>"
	}
	if mdHRRe.MatchString(t) {
		return "──────────"
	}
	if m := mdListRe.FindStringSubmatch(t); m != nil {
		return m[1] + "• " + telegramInline(m[2])
	}
	return telegramInline(t)
}

// splitRunes cuts s into pieces of at most n runes.
func splitRunes(s string, n int) []string {
	if n < 1 {
		n = 1
	}
	r := []rune(s)
	var out []string
	for len(r) > n {
		out = append(out, string(r[:n]))
		r = r[n:]
	}
	return append(out, string(r))
}

// telegramReportChunks renders Markdown into self-contained Telegram-HTML chunks:
// every chunk is valid on its own (a code block split across chunks is closed
// and reopened). firstBudget applies to the first chunk (it shares the message
// with the header), budget to the rest.
func telegramReportChunks(md string, firstBudget, budget int) []string {
	if firstBudget < 200 {
		firstBudget = 200
	}
	var chunks []string
	var cur strings.Builder
	limit := firstBudget
	size := func() int { return utf8.RuneCountInString(cur.String()) }
	flush := func() {
		if s := strings.TrimRight(cur.String(), "\n"); strings.TrimSpace(s) != "" {
			chunks = append(chunks, s)
		}
		cur.Reset()
		limit = budget
	}
	addLine := func(rendered, raw string) {
		n := utf8.RuneCountInString(rendered) + 1
		if size() > 0 && size()+n > limit {
			flush()
		}
		if n > limit { // one giant line: drop formatting and hard-split it
			for _, piece := range splitRunes(raw, limit/6) {
				if size() > 0 && size()+utf8.RuneCountInString(piece)*5 > limit {
					flush()
				}
				cur.WriteString(telegramEscape(piece) + "\n")
			}
			return
		}
		cur.WriteString(rendered + "\n")
	}
	var code []string
	flushCode := func() {
		const pre, endPre = "<pre>", "</pre>\n"
		open := false
		for _, l := range code {
			el := telegramEscape(l)
			if utf8.RuneCountInString(el)+len(pre)+len(endPre)+1 > limit {
				el = telegramEscape(TruncateRunes(l, (limit-32)/6))
			}
			n := utf8.RuneCountInString(el) + 1
			if open && size()+n+len(endPre) > limit {
				cur.WriteString(endPre)
				open = false
				flush()
			}
			if !open {
				if size() > 0 && size()+len(pre)+n+len(endPre) > limit {
					flush()
				}
				cur.WriteString(pre)
				open = true
			}
			cur.WriteString(el + "\n")
		}
		if open {
			cur.WriteString(endPre)
		}
		code = code[:0]
	}
	inCode := false
	for _, l := range strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			if inCode {
				flushCode()
			}
			inCode = !inCode
			continue
		}
		if inCode {
			code = append(code, l)
			continue
		}
		r := telegramMDLine(l)
		if r == "" {
			if size() > 0 && !strings.HasSuffix(cur.String(), "\n\n") {
				cur.WriteString("\n")
			}
			continue
		}
		addLine(r, l)
	}
	if inCode {
		flushCode()
	}
	flush()
	return chunks
}

// telegramPlain turns rendered HTML back into plain text: the fallback when
// Telegram refuses to parse a part's entities.
func telegramPlain(html string) string {
	s := htmlTagRe.ReplaceAllString(html, "")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	return strings.ReplaceAll(s, "&amp;", "&")
}

// severityMark is the colored marker shown before a report's header line.
func severityMark(sev string) string {
	switch sev {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	}
	return "⚪"
}

// telegramReportHeader is the single header line "🟠 [high] task — title",
// capped to fit Telegram's 1024-character caption limit.
func telegramReportHeader(m Message) string {
	it := m.Items[0]
	sev := strings.ToLower(strings.TrimSpace(it.Severity))
	if sev == "" {
		sev = "info"
	}
	line := "[" + sev + "] " + OneLine(it.Title(), 0)
	if it.TaskName != "" {
		line = "[" + sev + "] " + OneLine(it.TaskName, 0) + " — " + OneLine(it.Title(), 0)
	}
	h := severityMark(sev) + " <b>" + telegramEscape(TruncateRunes(line, 900)) + "</b>"
	if v := strings.TrimSpace(it.Verification); v != "" {
		h += "\n" + telegramEscape(TruncateRunes(v, 100))
	}
	return h
}

// telegramCheck parses a Bot API response, mapping errors like Send does.
func telegramCheck(raw []byte) error {
	var res struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("failed to parse Telegram response: %w (%s)", err, snippet(raw))
	}
	if res.OK {
		return nil
	}
	if res.ErrorCode == 429 {
		return fmt.Errorf("Telegram rate limited: %s", res.Description)
	}
	return Permanent(fmt.Errorf("Telegram returned error %d: %s", res.ErrorCode, res.Description))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// sendReport delivers a report_ready item as ONE message: the report.md file
// with the header line ("🟠 [high] task — title") as its caption. If the file
// upload fails, the header + report are sent as rendered text instead so the
// report is never lost.
func (c telegramChannel) sendReport(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	endpoint, err := telegramEndpoint(cfg)
	if err != nil {
		return 0, Permanent(err)
	}
	it := m.Items[0]
	chatID := cfgString(cfg, "chat_id")
	header := telegramReportHeader(m)
	docURL := strings.TrimSuffix(endpoint, "sendMessage") + "sendDocument"
	name := fmt.Sprintf("finding-%d-report.md", it.FindingID)
	raw, err := doMultipart(ctx, docURL, map[string]string{"chat_id": chatID, "caption": header, "parse_mode": "HTML"},
		"document", name, []byte(it.Report))
	if err == nil {
		err = telegramCheck(raw)
	}
	if err == nil {
		return 1, nil
	}
	if !IsPermanent(err) {
		return 0, err // transient (network / 429): let the delivery retry
	}
	log.Printf("[notify] telegram report finding=%d file upload rejected, sending as text: %v", it.FindingID, err)
	send := func(text string) error {
		raw, err := doJSON(ctx, "POST", endpoint, nil, map[string]any{
			"chat_id": chatID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true})
		if err == nil {
			err = telegramCheck(raw)
		}
		if err != nil && IsPermanent(err) { // entity-parse rejection: resend as plain text
			if raw2, err2 := doJSON(ctx, "POST", endpoint, nil, map[string]any{
				"chat_id": chatID, "text": TruncateRunes(telegramPlain(text), telegramTextLimit), "disable_web_page_preview": true}); err2 == nil {
				err = telegramCheck(raw2)
			}
		}
		return err
	}
	chunks := telegramReportChunks(it.Report, telegramReportBudget-utf8.RuneCountInString(header)-4, telegramReportBudget)
	for i, ch := range chunks {
		text := ch
		if i == 0 {
			text = header + "\n\n" + ch
		} else if sleepCtx(ctx, telegramPartGap) != nil {
			break
		}
		if err := send(text); err != nil {
			if i == 0 {
				return 0, err
			}
			log.Printf("[notify] telegram report finding=%d text part %d/%d failed: %v", it.FindingID, i+1, len(chunks), err)
		}
	}
	return 1, nil
}

// doMultipart POSTs a multipart/form-data request with one file field, with the
// same error semantics and credential redaction as doJSON.
func doMultipart(ctx context.Context, url string, fields map[string]string, fileField, fileName string, content []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return nil, Permanent(fmt.Errorf("failed to build request body: %w", err))
		}
	}
	fw, err := w.CreateFormFile(fileField, fileName)
	if err != nil {
		return nil, Permanent(fmt.Errorf("failed to build request body: %w", err))
	}
	if _, err := fw.Write(content); err != nil {
		return nil, Permanent(fmt.Errorf("failed to build request body: %w", err))
	}
	if err := w.Close(); err != nil {
		return nil, Permanent(fmt.Errorf("failed to build request body: %w", err))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, &buf)
	if err != nil {
		return nil, Permanent(fmt.Errorf("invalid request address: %s", redactRequestTarget(url)))
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %s", redactTransportError(err))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	if readErr != nil {
		return nil, fmt.Errorf("failed to read response: %w", readErr)
	}
	// Telegram reports business errors in the JSON body (checked by the caller);
	// pass 4xx bodies through so telegramCheck can read error_code.
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return raw, nil
	}
	return nil, fmt.Errorf("peer service error (HTTP %d): %s", resp.StatusCode, snippet(raw))
}
