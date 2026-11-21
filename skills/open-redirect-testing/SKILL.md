---
name: open-redirect-testing
description: "Invoke this skill when testing an authorized endpoint/parameter for an open redirect (coverage class `open_redirect`): unvalidated redirect/return/next/url/callback targets, scheme and slash bypasses, whitelist-host tricks, and CRLF, where proof is a 3xx Location or client-side redirect to an attacker-controlled host. Covers detection, non-destructive confirmation, and recording the cell on the coverage matrix."
---

# Open Redirect Testing (coverage class: `open_redirect`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, param)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: send redirect attempts through
the recording proxy, read where the app sends the browser, adapt past the filter,
and record the trail. Use it alongside `api-security` (which maps where redirect
parameters live) — this skill decides whether a given input steers the redirect
target to a host you control.

Original bcpen content for the `open_redirect` coverage class — there is no
upstream AntiFox equivalent, so no attribution-to-AntiFox line applies here.

## Boundaries

- Authorized scope only. The endpoint must be in the task's scope; never pivot to a
  host or parameter the engagement did not authorize. The redirect *target* you
  inject is a benign marker host you control (e.g. `example.com`, a collaborator
  domain), never a third party's site.
- Non-destructive by default. Detection and confirmation only observe where a
  request is redirected — reading a `Location` header or a client-side navigation,
  changing no server state.
- The red line stays with the operator. Chaining a confirmed open redirect into a
  live OAuth/SSO token theft, a real SSRF against internal infrastructure, or any
  action touching a victim account or internal service is destructive / irreversible
  and crosses the red line — it needs the operator's sign-off (the red-set gate),
  never your own decision. Prove only the redirect primitive; describe the chain as
  impact.
- Proof, not exfiltration. The proof is one redirect to an attacker-controlled host.
  Do not harvest real users' OAuth codes, session tokens, or internal responses; a
  single controlled hop to your marker host is sufficient. Test accounts only.
- Every claim needs a replayable artifact: the exact request and the exact response
  (the `3xx` + `Location`, or the HTML/JS that performs the redirect), captured in
  the recording proxy.

## Method

Work one parameter at a time. Baseline first, then escalate only as the response
justifies it. A redirect sink takes a user-supplied target and sends the browser
there: `redirect`, `return`/`returnUrl`, `next`, `url`, `dest`, `goto`, `callback`,
`redirect_uri`, `back`, `success_url`, and login/logout flows.

### 1. Reach and baseline
- Confirm the parameter actually drives a redirect. Request the endpoint with a
  known in-scope value (e.g. `?next=/dashboard`) and record the normal reaction:
  the status (often `301`/`302`/`303`/`307`), the exact `Location` header, and
  whether the redirect is server-side (3xx) or client-side (`<meta http-equiv>`,
  `window.location`, a JS router). A parameter that never changes the destination
  is a candidate `n/a` once you show it reaches no redirect context.

### 2. Detection (read-only)
- Absolute-URL probe: set the parameter to your marker host,
  `?next=https://example.com`. A 3xx whose `Location` is `https://example.com` (or
  a client navigation there) is a direct open redirect — capture it.
- Observe the filter. If the absolute URL is rejected, stripped, or forced back to
  a same-origin path, note exactly how (prefix check? substring allow-list? scheme
  block?). The reaction tells you which bypass family to try next.

### 3. Context identification
- Server-side vs client-side: a 3xx `Location` is server-controlled; a reflected
  value used by `window.location`/meta-refresh is client-side (and may be
  DOM-XSS-adjacent via `javascript:` — out of this class, note for `xss`).
- Validation style: distinguish a *prefix/startswith* check, a *substring/contains*
  allow-list, a *host-parse* check, and a naive scheme/`//` filter. Each fails to a
  different bypass family in step 4.

### 4. Bounded confirmation (bypass families)
Pick the evasions that match the observed filter. Use your marker host as
`evil.com` below; confirm with one working payload, then stop.
- Scheme-relative / backslash (beats `startsWith("/")` and validators that miss
  `\`; browsers resolve to a different host): `//evil.com`, `/\evil.com`,
  `/\/evil.com`, `https:/\evil.com`.
- Malformed scheme (parser sees a path, browser sees a host):
  `https:evil.com`, `https:/evil.com`.
- Credential/`@` confusion vs a host allow-list (real host follows `@`):
  `https://trusted.com@evil.com`, `https://trusted.com%2f@evil.com`.
- Allow-list string tricks: `https://trusted.com.evil.com` (suffix a `contains`
  check misses), `https://evil.com/trusted.com`, `https://evil.com#trusted.com`.
- Encoding (filter trims, browser does not): `%2f%2fevil.com`,
  `https%3a%2f%2fevil.com`, `%252f%252fevil.com`, `/%09/evil.com`.
- CRLF, where the target lands in a response header, to set your own `Location`:
  `/%0d%0aLocation:%20https://evil.com` — capture the raw response headers.
- Confirm the hop: the proof is a single `3xx` with `Location:` pointing at your
  marker host, or a client-side navigation to it. One captured redirect is enough.

### 5. Filter / WAF adaptation
- If payloads are blocked, record the filter behavior and iterate within scope:
  combine families (encoded backslash + `@`), vary case (`HtTpS:`), and test each
  redirect-shaped parameter separately — some flows validate `next` but not
  `callback`. A blocked-by-WAF result is itself worth recording; it is not a proven
  `n/a`.
- Chain note (impact only): an open redirect on an OAuth `redirect_uri` or SSO
  `return` can leak authorization codes/tokens to the attacker host, and a
  server-side fetcher that follows it can become an SSRF pivot — record as potential
  impact; the live step needs the red-set gate (see Boundaries).

## Recording the result

Record every `open_redirect` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `open_redirect`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | send payloads, capture the 3xx/`Location` and raw headers for `traffic_ref` | always available. `curl -sD - -o /dev/null` shows headers without following; do NOT add `-L` during proof — not following the redirect is what keeps it non-destructive |
| Burp (MCP, when connected) | Repeater/Intruder for iterating bypass families; a Collaborator payload as the marker host to confirm an out-of-band hop | only where a Burp instance is wired |
| a browser / headless browser | confirm a client-side redirect curl cannot see | verify with `command -v` first; else infer the sink from the captured HTML/JS and record that |

Any class-specific automation (e.g. an open-redirect fuzzer) is NOT installed by
default — verify with `command -v <tool>` before use; if absent, use the manual
curl/proxy method and record the attempts. When present, keep it in-scope and
non-destructive: benign marker target only, never follow the redirect into a live
OAuth/SSO or internal endpoint.

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`) sent
      during this task, not a source read.
- [ ] Confirmation used a benign marker host; no real OAuth code, token, or internal
      response was captured, and the live token-theft/SSRF step was not run without
      the red-set gate.
- [ ] A finding records the exact `Location` (or client-side sink) and the
      validation style it bypassed, with any OAuth/SSRF chain noted as impact only.
- [ ] Any `n/a` cites evidence that input cannot reach a redirect sink, not an
      assumption from the parameter name.
