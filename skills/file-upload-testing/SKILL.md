---
name: file-upload-testing
description: "Invoke this skill when testing an authorized file-upload endpoint for unrestricted/unsafe upload (coverage class `file_upload`): extension, content-type, and magic-byte bypass, double extension, null-byte (legacy), path traversal in the filename, polyglots, and stored XSS via SVG/HTML — detection, bounded confirmation, and recording the result."
---

# File Upload Testing (coverage class: `file_upload`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one upload-endpoint cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: craft uploads, send them
through the recording proxy, read how the server validates and serves the file,
adapt, and record the trail. Use it alongside `api-security` (which maps where the
multipart endpoints live) — this skill decides whether an upload field accepts a
file the server should have rejected, and whether that file is reachable and
interpreted after storage.

Attribution: adapted from the `file-upload-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix;
no source was copied verbatim.

## Boundaries

- Authorized scope only. The upload endpoint and the host that serves the stored
  file must both be in the task's scope; never pivot to a parameter, path, or host
  the engagement did not authorize.
- Non-destructive by default. Prove the control is missing by retrieving a benign
  marker, not by running code on the target. A webshell is acceptable only against
  a resource the test itself created on a disposable/test instance, and even then
  the proof is retrieval of the marker — never an interactive shell, file write, or
  command execution on a production host.
- Destructive or irreversible steps cross the red line and need the operator's
  sign-off (the red-set gate), not your own decision: overwriting existing files
  via path traversal, uploading an executable the runtime will interpret on a live
  host, planting a `.htaccess`/`web.config`, or anything that persists past a
  cleanup you control.
- Proof, not exfiltration. The minimum evidence is the stored file served back
  with your unique marker intact (or the marker executed in the viewer's context
  for the XSS variants). Use test accounts and test-created resources; do not read
  or overwrite other users' files.
- Every claim needs a replayable artifact: the exact upload request, the exact
  retrieval request, and the response that shows the marker, captured in the
  recording proxy.

## Method

Work one upload field at a time. Always carry a unique marker (e.g.
`bcpen-<rand>`) in the payload so you can distinguish your file from noise and
prove retrieval. Baseline first, escalate only as the server's reaction justifies.

### 1. Reach and baseline
- Submit a plainly-legitimate file (a real PNG/JPEG the field expects) and
  capture the full round trip: the multipart request, the response, and —
  critically — how the file is retrieved afterward (returned URL, predictable
  path, id-based download, or not served at all). Note whether the stored name is
  reused, randomized, or re-encoded.
- An endpoint that stores to object storage under a random key and serves through
  a renderer that never interprets the file is a candidate `n/a` — but only once
  evidence shows the file is not reachable in an interpretable context.

### 2. Detection (read-only intent, benign content)
Change one dimension at a time from the known-good baseline; keep the body benign:
- Extension: try a server-executable extension for the stack (`.php`/`.php5`/
  `.phtml`/`.phar`, `.jsp`/`.jspx`, `.asp`/`.aspx`, `.cshtml`) and alternates the
  filter may miss. Observe accept/reject and the stored name.
- Content-Type: hold a rejected extension but set `Content-Type: image/png` (and
  the reverse) to locate which layer validates.
- Magic bytes: prepend the expected signature (`GIF89a;`, JPEG `FF D8 FF`, PNG
  `\x89PNG`) to otherwise-rejected content, to test signature-only validation.
- Filename structure: double extension (`shell.php.png`, `shell.png.php`),
  trailing dot/space/`::$DATA` (Windows), case variation (`.PhP`), and the legacy
  null-byte trick `shell.php%00.png` (only effective on old PHP<5.3.4 / C-string
  parsers — one probe, do not assume it works).
- Path traversal in the filename field: `../../marker.txt`, `..%2f..%2fmarker.txt`,
  absolute paths — to test whether the storage path is attacker-derived. A
  traversal that would OVERWRITE an existing file is a red-set step (§Boundaries);
  confirm the write lands in a new, non-colliding path.

### 3. Context identification
- Determine how the stored file is served before claiming impact: under the web
  root? Static Content-Type, or passed to an interpreter? Behind a CDN that forces
  `Content-Disposition: attachment`? The same file is a critical RCE in one
  context and inert in another.
- Fingerprint the stack (headers, error text, existing extensions) so the
  executable extension and any interpreter directive you try are correct.

### 4. Bounded confirmation
- Interpreter reachability: upload a marker file whose content the server reveals
  only if interpreted — e.g. for PHP, a one-liner that echoes a unique string;
  retrieve it and confirm the string (not the source) comes back. Do this only
  against a test-created resource on a non-production/disposable instance; on a
  live host, stop at "executable file accepted and stored at a reachable path" and
  escalate to the operator.
- Stored XSS via markup: an `.svg` carrying `<script>`/`<foreignObject>` or an
  HTML file served inline is confirmed by the marker script executing in the
  viewer's origin — capture the served response showing `Content-Type` and the
  active payload. This needs no server-side code execution and is the preferred
  proof when the upload renders in a browser.
- Polyglot: a file valid as both image and script (e.g. a GIF/JPEG header then
  payload) passes a magic-byte check while staying interpretable — confirm via
  retrieval of the marker only.
- Stop at proof. One retrieved marker establishes the finding; do not weaponize,
  persist, or pivot.

### 5. Filter / WAF adaptation
- If uploads are blocked, record the exact rejection and try context-appropriate
  evasions within scope: alternate executable extensions, MIME/magic-byte
  combinations, multipart quirks (duplicated `filename`, mismatched boundaries,
  charset tricks), and content-level obfuscation. A blocked-by-filter result is a
  `tested` cell, not a proven `n/a`.

## Recording the result

Record every `file_upload` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `file_upload`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | craft multipart uploads, retrieve the stored file, capture request/response for `traffic_ref` | always available (`curl -F`; raw `--data-binary` for hand-built boundaries) |
| Burp (MCP, when connected) | Repeater/Intruder for iterating extensions, MIME, and multipart structure | only where a Burp instance is wired |
| exiftool / ImageMagick | build polyglots and inject markers into image metadata | NOT installed by default — verify (`command -v exiftool`) before use; else construct the header by hand |
| upload fuzzers (fuxploider, Upload_Bypass) | automated extension/MIME enumeration | NOT installed by default — verify (`command -v <tool>`) before use; if present, keep it in-scope and non-destructive (benign markers only, no live-host webshell, file-write, or reverse-shell payloads), else use the manual method and record the attempts |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`)
      sent during this task, not a source read.
- [ ] Each bypass dimension tried is in the evidence trail with the server's
      reaction, and confirmation is retrieval of a unique marker — not a live
      webshell on a production host.
- [ ] No destructive step (overwrite via traversal, interpreted executable on a
      live host, persistent server-config file) ran without operator sign-off.
- [ ] Only test accounts and test-created resources were touched.
- [ ] Any `n/a` cites evidence that no reachable interpretable serving path
      exists, not an assumption.
