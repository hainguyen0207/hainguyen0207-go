---
name: ssrf-testing
description: "Invoke this skill when testing an authorized URL-taking input for server-side request forgery (coverage class `ssrf`): webhooks, fetchers, avatar/image importers, PDF/preview renderers, and API proxies reaching internal or cloud-metadata targets. Covers read-only detection, out-of-band confirmation, scheme/encoding/DNS-rebinding bypass, and recording the result."
---

# SSRF Testing (coverage class: `ssrf`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, param)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: drive a server-side fetch
through the recording proxy, watch where the request lands, adapt, and record the
trail. Use it alongside `api-security` (which maps where URL-taking parameters
live — webhooks, importers, proxies) — this skill decides whether a given input
makes the server issue an attacker-controlled request.

Attribution: adapted from the `ssrf-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix;
no source was copied verbatim.

## Boundaries

- Authorized scope only, and SSRF makes this sharp: the *destination* of the
  forged request must stay inside the task's authorized scope and its egress
  allowlist. Pointing a server at arbitrary internal hosts (RFC1918 ranges, other
  tenants, a provider's wider fleet) can breach scope even when the vulnerable
  endpoint itself is in scope. Prefer a callback to an out-of-band host you
  control (Burp Collaborator or an equivalent allowlisted domain) over blind
  internal probing.
- Non-destructive by default. Detection and confirmation prove only that the
  server fetches a target you chose. Do not use the reachable fetch to drive
  internal side effects — no Redis/FastCGI/`gopher://` command injection, no
  writes to internal services, no reverse-shell gadgets — against a live target.
  Those cross the destructive line and require the operator's sign-off (the
  red-set gate), not your own decision.
- Proof, not exfiltration. Confirm with the minimum: a DNS/HTTP hit on your
  collaborator, or a single distinguishing response (a banner line, a 302, one
  metadata field name). If cloud credentials are reachable, prove reachability —
  do not harvest or use live keys; stop and escalate.
- Internal port probing is a few targeted requests to show the class, never a
  swept range that loads internal infrastructure; keep volume low.
- Every claim needs a replayable artifact: the exact request you sent, the
  server's response (or the out-of-band interaction), captured in the recording
  proxy.

## Method

Work one parameter at a time. Baseline first, then escalate only as the response
justifies it. Always send through the recording proxy so each attempt is captured.

### 1. Reach and baseline
- Confirm the parameter drives a server-side fetch: supply a URL to an
  out-of-band host you control and watch for the inbound DNS/HTTP hit. No hit, no
  reflected fetch behavior, and no response change is a candidate `n/a` once you
  have shown the input never reaches an outbound request.
- Record the normal response (status, length, timing, content type, any
  fetched-content echo) so every later payload is judged against a real baseline.

### 2. Detection (read-only, out-of-band first)
- Collaborator probe: point the parameter at `http://<your-collaborator>/<nonce>`.
  An inbound request confirms a server-side fetch even when the body never returns
  the fetched content (blind SSRF); the nonce ties the hit to this attempt.
- Response-based probe: where fetched content is reflected, request a benign
  external page and confirm its body/headers appear in the response.
- Confirm the fetch originates from the server's egress IP, not the browser — the
  collaborator's recorded source address and server timing establish this.

### 3. Context identification
- Classify the sink: full-URL fetch, host-only field, scheme-restricted
  (`https`-only), or a parser that pre-validates. Note the allowlist/denylist
  behavior from how rejections differ.
- Enumerate reachable intent targets inside scope: the loopback stack
  (`127.0.0.1`, `localhost`, `0.0.0.0`, `[::1]`), and the cloud metadata endpoints
  relevant to the host — AWS/Azure `169.254.169.254` (Azure needs
  `Metadata: true` plus `?api-version=`), GCP `metadata.google.internal`
  (needs `Metadata-Flavor: Google`), Alibaba `100.100.100.200`. Probe metadata
  only when the host is in authorized scope.

### 4. Bounded confirmation
- Prove impact with the least data: one out-of-band callback for blind SSRF; a
  single internal response that differs from an unreachable control (open vs
  closed port by status/timing) for a targeted in-scope service; one metadata
  field name (not its secret value) for a reachable metadata service.
- Stop at proof. A DNS hit plus one distinguishing in-scope response is a
  finding; do not pivot into the internal network or pull credentials.

### 5. Filter / WAF adaptation
When a target is blocked, record the filter behavior and try context-appropriate,
in-scope bypasses — a block is itself worth recording, not a proven `n/a`:
- IP encodings of a loopback/allowed host: decimal (`2130706433`), hex
  (`0x7f000001`), octal (`0177.0.0.1`), IPv6-mapped (`[::ffff:127.0.0.1]`),
  zero-compression (`127.1`).
- Alternate hostnames that resolve inward: a wildcard-DNS host
  (`127.0.0.1.nip.io`), `localtest.me`, or your own A-record.
- DNS rebinding: a host you control that resolves to an allowed address on the
  validation lookup and an internal one on the fetch — the modern TOCTOU bypass
  for allowlists that validate then re-resolve.
- Authority parser confusion: `http://allowed@target`, `http://target#@allowed`,
  embedded credentials, and `?`/`#` splitting differently in validator vs client.
- Open redirect chaining: an in-scope endpoint that 302s to an internal target,
  when the fetcher follows redirects.
- Scheme swaps where accepted (`file://`, `gopher://`, `dict://`) — note
  reachability for the report, but do not weaponize them against a live target
  (see Boundaries).

## Recording the result

Record every `ssrf` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `ssrf`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | send URL payloads, capture request/response for `traffic_ref` | always available |
| out-of-band collaborator | catch blind-SSRF DNS/HTTP callbacks you control | use an allowlisted domain; Burp Collaborator via MCP when wired |
| Burp (MCP, when connected) | Repeater/Intruder for iterative targets, Collaborator payloads | only where a Burp instance is wired |
| SSRFmap | automated SSRF detection/exploitation | NOT installed by default — verify (`command -v ssrfmap` / check the repo) before use; if absent, use the manual method above and record the attempts. When present, keep it within scope and non-destructive: no `portscan` sweeps of out-of-scope hosts, no `redis`/`fastcgi`/exploit modules that write to or execute on a live internal service. |
| Gopherus | craft `gopher://` protocol payloads | NOT installed by default — verify before use; crafting payloads against a live internal service is destructive and needs operator sign-off, so do not run it on a live target without the red-set gate. |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`)
      sent during this task, not a source read.
- [ ] Every forged-request destination stayed inside authorized scope and the
      egress allowlist; no arbitrary internal host was probed.
- [ ] Confirmation used the minimum: a callback, one distinguishing response, or a
      field name — no live credentials were harvested or used.
- [ ] No destructive protocol payload (`gopher`/`dict`/Redis/FastCGI) ran against
      a live target without operator sign-off.
- [ ] Any `n/a` cites evidence that the input cannot produce a server-side
      request, not an assumption.
