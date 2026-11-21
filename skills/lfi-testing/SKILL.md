---
name: lfi-testing
description: "Invoke this skill when testing an authorized endpoint/parameter for local file inclusion or path traversal (coverage class `lfi`): ../ traversal and its encodings, absolute paths, PHP wrappers (php://filter, data://, expect://), /proc/self/environ and log poisoning, and null-byte truncation on legacy stacks. Covers detection, non-destructive confirmation, and a single-file proof, then recording the result (report_finding when confirmed)."
---

# Local File Inclusion / Path Traversal Testing (coverage class: `lfi`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, param)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: send attempts through the
recording proxy, read the app's reaction, adapt, and record the trail. Use it
alongside `api-security` (which maps where parameters live) — this skill decides
whether a given input reaches a filesystem read or an `include`/`require` sink.

Original bcpen content for the `lfi` coverage class — there is no AntiFox
equivalent, so no upstream attribution applies.

## Boundaries

- Authorized scope only. The endpoint must be in the task's scope; never pivot to
  a host or parameter the engagement did not authorize.
- Non-destructive by default. Detection and confirmation are read-only: you read a
  single non-sensitive file to prove the primitive. Never write files, overwrite
  logs beyond a single benign marker, or turn an inclusion into code execution
  (`expect://`, log poisoning to RCE, uploaded-shell inclusion) against a live
  target — those cross the destructive/irreversible line and require the
  operator's sign-off (the red-set gate), not your own decision.
- Proof, not exfiltration. Confirm with the minimum: `/etc/hostname`, or the first
  line of `/etc/passwd` (`root:x:0:0:...`), or `C:\Windows\win.ini` on Windows. Do
  not pull application secrets, private keys, `.env`, or `/etc/shadow`; one
  non-sensitive file is sufficient evidence. Read only test-owned resources where a
  file must be chosen.
- Every claim needs a replayable artifact: the exact request, the exact response
  (the file content returned, or the differential that revealed it), captured in
  the recording proxy.

## Method

Work one parameter at a time. Baseline first, then escalate only as the response
justifies it.

### 1. Reach and baseline
- Find parameters that name a resource: `?file=`, `?page=`, `?template=`,
  `?lang=`, `?path=`, `?download=`, `?include=`, and the like. Note any extension
  the app appends (`.php`, `.html`) or prefix directory it prepends.
- Record the normal response for a known-good value: status, length, body, timing,
  and any error, so every later payload is judged against a real baseline.
- Decide the likely sink: a raw filesystem read (returns file bytes) versus an
  `include`/`require` that executes PHP (traversal to a `.php` returns rendered
  output, not source) — the proof technique differs.

### 2. Detection (read-only)
- Traversal probe: step `../` up a few levels to a stable target,
  e.g. `../../../../etc/hostname` (Linux) or
  `..\..\..\..\Windows\win.ini` (Windows). A changed, file-shaped response versus
  the baseline is the signal — capture it.
- Absolute path: try `/etc/hostname` or `/proc/self/cmdline` directly; some sinks
  take an absolute path with no traversal needed.
- Prefix/suffix handling: if the app appends `.php`, confirm whether a PHP wrapper
  or a path that ends at a real file is needed; if it prepends a directory, climb
  out of it first.

### 3. Context identification and filter encoding
- Identify what the filter removes or normalizes, then encode to match:
  - URL-encode the dots/slashes: `%2e%2e%2f`; double-encode when one decode pass is
    applied: `%252e%252e%252f`.
  - Non-recursive `../` stripping is defeated by `....//` (collapses back to `../`).
  - Overlong/UTF-8 and backslash variants on the relevant stack: `..%c0%af`,
    `..%5c`.
- Depth: traversal is forgiving — climbing too far (`../` × 10) still lands at
  root, so prefer extra `../` over too few.

### 4. Bounded confirmation
- Raw-read sink: return one non-sensitive file (`/etc/hostname`, or the first
  `root:x:0:0:` line of `/etc/passwd`). That single file is the proof; stop.
- PHP source disclosure without execution: `php://filter` with a base64 wrapper —
  `php://filter/convert.base64-encode/resource=index.php` — returns the file
  base64-encoded so an `include` sink reveals source instead of running it. Decode
  only enough to confirm it is the expected file.
- `data://` / inline: `data://text/plain;base64,<marker>` to confirm the wrapper is
  enabled, using a harmless marker string, not a payload.
- `/proc/self/environ` and `/proc/self/cmdline` to confirm process-level read
  access (non-sensitive confirmation), without poisoning anything.
- Null byte (`%00`) only on a legacy target (PHP < 5.3.4) where an appended
  extension blocks the read — note it as legacy-specific; it does not work on
  current PHP.
- Stop at proof. One file or one source listing is enough; do not walk the
  filesystem or chain to RCE.

### 5. WAF / filter adaptation
- If payloads are filtered, record the filter behavior and try context-appropriate
  evasions within scope: the encodings above, case variation, nested/overlong
  sequences, wrapper alternatives. A blocked-by-WAF result is itself worth
  recording — it is not a proven `n/a`.

## Recording the result

Record every `lfi` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `lfi`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | send traversal/wrapper payloads, capture request/response for `traffic_ref` | always available |
| Burp (MCP, when connected) | Repeater/Intruder for iterative encodings and traversal depth | only where a Burp instance is wired |
| LFISuite / dotdotpwn / fimap | automated traversal fuzzing and LFI detection | NOT installed by default — verify (`command -v dotdotpwn`, `command -v fimap`) before use; if absent, use the manual method above and record the attempts. When present, keep it within scope and non-destructive: detection/read only, no log-poisoning-to-shell, no file write, no reverse shell on a live target. |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`) sent
      during this task, not a source read.
- [ ] Confirmation used one non-sensitive file (`/etc/hostname` / first `passwd`
      line / `win.ini`); no secrets, keys, `/etc/shadow`, or bulk files were read.
- [ ] No write, log poisoning, or inclusion-to-RCE ran against the live target.
- [ ] Any `n/a` cites evidence that input cannot reach a filesystem/`include` sink,
      not an assumption.
