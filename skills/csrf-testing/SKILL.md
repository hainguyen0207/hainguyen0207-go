---
name: csrf-testing
description: "Invoke this skill when testing an authorized state-changing request for cross-site request forgery (coverage class `csrf`): missing or unbound anti-CSRF tokens, weak SameSite posture, method and content-type tricks, JSON CSRF, and CORS misconfiguration, proven by a crafted cross-origin request that performs the action on a test account and recorded on the coverage matrix."
---

# CSRF Testing (coverage class: `csrf`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, action)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: replay a state-changing
request without its anti-CSRF defenses through the recording proxy, read the
app's reaction, adapt, and record the trail. Use it alongside `api-security`
(which maps where state-changing endpoints and their auth context live) — this
skill decides whether a given action can be driven from a foreign origin on a
victim's authenticated session.

Attribution: adapted from the `csrf-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix;
no source was copied verbatim.

## Boundaries

- Authorized scope only. The endpoint and the action must be in the task's scope;
  never drive a state change on a host, account, or resource the engagement did
  not authorize.
- Non-destructive by default. Prove the forgery against a benign, reversible
  action (profile field, non-sensitive preference, a flag you can set back) on a
  **test account you control**. A forged password reset, email takeover, fund
  transfer, deletion, or privilege change on a real account is destructive and
  irreversible — it crosses the red line and requires the operator's sign-off
  (the red-set gate), not your own decision.
- Proof, not exfiltration. The proof is that the action executed cross-origin on
  the victim session — shown by the server's response and the state change on your
  test account — not harvested data. One controlled action is enough.
- Proof is a real cross-origin request, not an HTML file on disk: the attempt must
  be issued with the victim's ambient credentials (`credentials: include` or an
  auto-submitting cross-site form), land at the target, and be captured in the
  recording proxy alongside the before/after state of the test account.

## Method

Work one action at a time. Baseline the protected request first, then strip
defenses one at a time and only escalate as the response justifies it.

### 1. Reach and baseline
- Identify a state-changing request (POST/PUT/PATCH/DELETE, or a mutating GET) and
  capture a full successful legitimate instance through the proxy: method, path,
  headers, body, and every token or custom header it carries. Record the
  authenticated success response (status, body, resulting state) so every
  stripped-down variant is judged against a real baseline.

### 2. Detection (read-only)
- **Token presence / validation / binding.** Does the request carry an
  unpredictable anti-CSRF token (hidden form field, `X-CSRF-Token`/`X-XSRF-Token`
  header, double-submit cookie)? Replay the baseline with the token removed,
  emptied, set to a well-formed value from a *different* session/account, and
  replayed from an earlier request. Still succeeding means the token is
  decorative, or valid-but-not-bound to the session — equivalent to no token.
- **Origin/Referer check.** Replay with `Origin`/`Referer` removed, set to a
  foreign origin, and to look-alikes a loose regex may accept
  (`https://target.com.evil.com`, `https://evil.com/?target.com`). A blind-accept
  or a bypassable check is the signal.
- **SameSite posture.** Read `Set-Cookie` for the session cookie. No attribute
  defaults to `Lax` on modern browsers (not `None`); `SameSite=Lax` still leaves
  state-changing `GET`s and top-level navigations exposed; `None; Secure` is
  fully cross-site-sendable; `Strict` blocks the classic send. The posture bounds
  which delivery vectors are viable.

### 3. Context identification
- Classify the content type the endpoint actually requires. A form-encoded,
  `multipart/form-data`, or `text/plain` body is forgeable with a plain
  cross-site `<form>` (no preflight). A request that *requires*
  `application/json` or a custom header (`X-Requested-With`, `X-CSRF-Token`)
  forces a CORS preflight a simple form cannot satisfy — the defense may rest
  entirely on that requirement.
- Pick the delivery vector from the posture and method: auto-submitting form
  (form-encoded body), `<img>`/navigation (mutating GET), or scripted `fetch`
  with `credentials: include` (simple-request shapes, or where CORS is
  misconfigured).

### 4. Bounded confirmation
- **Method / content-type trick.** If the endpoint accepts a form-encoded or
  `text/plain` body (replay the JSON action re-encoded as form data, or as
  `enctype="text/plain"` with the JSON smuggled across a field name/value split),
  it is reachable without preflight — confirm with one auto-submitting cross-site
  form to a benign field on your test account.
- **JSON CSRF.** A real finding only if a browser can send the request cross-site
  without preflight: the server parses `text/plain` as JSON, or CORS misconfig
  lets a `credentials: include` `fetch` through. Prove it — a JSON endpoint that
  strictly requires `Content-Type: application/json` is generally not forgeable
  by a simple request.
- **CORS as a related vector.** If the endpoint reflects `Origin` into
  `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true` (or
  allows `null`), a credentialed cross-origin `fetch` both drives the change and
  reads the response — confirm from a foreign `Origin`, capturing the permissive
  ACAO/ACAC headers.
- **The proof.** A crafted cross-origin request — auto-submitting form or scripted
  `fetch` — that performs the action on the test account using the victim's
  ambient cookies, with the accepting response and the state change captured. Stop
  at one successful action.

### 5. Filter / defense adaptation
- If a token or Origin check blocks the attempt, record the exact defense and try
  in-scope bypasses: Referer suppression
  (`<meta name="referrer" content="no-referrer">`); Origin look-alikes against a
  loose regex; GET/method override (`?_method=POST`, `X-HTTP-Method-Override`)
  where the framework honors it; SameSite gaps (mutating GET under `Lax`,
  sibling-subdomain delivery). A request *blocked* by a working token or
  `SameSite=Strict` is itself worth recording — evidence toward a proven `n/a`,
  not a bare failure.

## Recording the result

Record every `csrf` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `csrf`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | replay the action with defenses stripped, issue the crafted cross-origin request with ambient creds, capture request/response for `traffic_ref` | always available |
| Burp (MCP, when connected) | Repeater for variant replay; Engagement tools → Generate CSRF PoC for the auto-submit form | only where a Burp instance is wired |
| OWASP ZAP | anti-CSRF token detection / replay | NOT installed by default — verify (`command -v zap.sh` / `command -v zaproxy`) before use; if absent, use the manual method above and record the attempts. When present, keep it within scope and non-destructive: no active-scan floods, no destructive forged actions against real accounts. |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`) — an
      actual cross-origin attempt sent during this task, not a source read or a
      PoC file that was never issued.
- [ ] The proof was a cross-origin request with the victim's ambient credentials
      that performed the action; the test account's before/after state is captured.
- [ ] Confirmation used a benign, reversible action on a test account; no
      destructive or irreversible forgery ran against a real account without the
      red-set sign-off.
- [ ] Any `n/a` cites captured evidence that a bound token or `SameSite=Strict`
      blocks every viable vector, not an assumption from the endpoint.
