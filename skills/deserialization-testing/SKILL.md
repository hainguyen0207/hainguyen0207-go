---
name: deserialization-testing
description: "Invoke this skill when testing an authorized endpoint/parameter for insecure deserialization (coverage class `rce`): serialized blobs in cookies, bodies, or headers across Java (ysoserial gadget chains), PHP (`unserialize`/POP chains), Python (`pickle`), .NET (`BinaryFormatter`), and Ruby (Marshal). Covers blob detection, benign out-of-band confirmation, and a bounded proof, then recording the result (report_finding when confirmed)."
---

# Deserialization Testing (coverage class: `rce`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, param)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: identify where the app turns
attacker-controlled bytes back into objects, send attempts through the recording
proxy, read the reaction, adapt, and record the trail. Use it alongside
`api-security` (which maps where parameters and tokens live) — this skill decides
whether a given input reaches a deserialization sink and records the `rce` class.

Attribution: adapted from the `deserialization-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix;
no source was copied verbatim.

## Boundaries

- Authorized scope only. The endpoint must be in the task's scope; never pivot to
  a host, token, or parameter the engagement did not authorize.
- Non-destructive by default. Confirm with a benign, out-of-band gadget — a DNS or
  HTTP callback to your Collaborator/interactsh host, or a single bounded `sleep` —
  that proves the chain fires without executing an attacker command. A real
  `Runtime.exec`, `system()`, file write, or reverse shell against a live target
  crosses the destructive/irreversible line and requires the operator's sign-off
  (the red-set gate), never your own decision.
- Proof, not exfiltration. A received DNS lookup, a measured delay, or one
  non-sensitive echoed value is sufficient evidence of code paths. Do not stage a
  shell, read arbitrary files, or pivot once the chain is confirmed.
- Payloads are bounded: fire a confirming gadget once and observe; do not loop
  heavy chains or oversized blobs that degrade the service.
- Every claim needs a replayable artifact: the exact request (the serialized blob
  as sent), the exact response or the out-of-band interaction, captured in the
  recording proxy.

## Method

Work one input at a time. Baseline first, identify the format, then escalate only
as the response justifies it. Prefer the manual workflow (recording proxy + curl,
with a Collaborator/interactsh callback); use Burp via MCP when it is wired.

### 1. Reach and baseline
- Find where serialized objects cross the trust boundary: cookies and `session`
  values, `Authorization`/custom headers, request bodies, hidden form fields,
  `viewstate`, cache keys, message-queue payloads, and file uploads.
- Record the normal request/response (status, length, timing, any error shape) so
  every later payload is judged against a real baseline.

### 2. Detection (read-only) — recognize the format
Magic bytes and prefixes identify the serializer before you touch it:
- **Java native**: bytes `AC ED 00 05`; Base64 begins `rO0AB`; gzip+Base64 begins
  `H4sIA`. `Content-Type: application/x-java-serialized-object` is a tell.
- **PHP**: readable `O:8:"stdClass":…`, `a:2:{…}`, `s:4:"…"`, often Base64/URL encoded.
- **Python pickle**: starts `\x80\x04`/`\x80\x03`; Base64 begins `gAS`/`gAN`.
- **.NET**: `BinaryFormatter` streams start `00 01 00 00 00 FF FF FF FF`;
  `ViewState` is Base64 beginning `/wEP` — look for `__VIEWSTATE` without a MAC.
- **Ruby Marshal**: starts `\x04\x08`.
- Also flag typed JSON/XML deserializers: Jackson default typing
  (`@class`/polymorphic fields), Fastjson/Fastjson2 (`@type`), XStream, SnakeYAML
  (`!!` tags), and .NET `TypeNameHandling`.

Corrupt one byte of the blob and resend. A deserialization-layer exception,
class-not-found error, or distinct 500 versus the baseline is strong signal that
the bytes are deserialized. Capture it.

### 3. Context identification
- Fingerprint the runtime and, where possible, the library and version from error
  text, stack traces, framework headers, or dependency hints. The viable gadget
  chain depends on what is on the classpath (Commons-Collections 3.1 vs 3.2.1,
  Spring, ROME, Jackson) or in the PHP/Python codebase.
- Decide whether a MAC/integrity check guards the blob (e.g. signed .NET
  ViewState, signed cookies). If so, note it — a filter/signature result is not a
  proven `n/a`.

### 4. Bounded confirmation (benign gadget only)
Prove the sink fires using a chain whose only effect is an observable signal:
- **Java**: generate a URLDNS or an out-of-band JRMP/sleep chain with ysoserial
  (`java -jar ysoserial.jar URLDNS "http://<id>.<collab-host>"`), Base64-encode,
  and place it where the blob lives. A DNS hit on your Collaborator confirms the
  object graph was deserialized without running a command. Escalate to a
  classpath-specific exec gadget only under red-set sign-off.
- **PHP**: confirm reach with a crafted `__wakeup`/`__destruct` object touching a
  benign property or triggering an outbound request; `phpggc` can emit
  callback-style gadgets when a POP chain exists.
- **Python pickle**: confirm reachability with a `__reduce__` returning a benign,
  observable call (a DNS resolution or a one-shot `sleep`) rather than
  `os.system('id')`. A callback or measured delay is the proof.
- **.NET**: for unsigned ViewState or a `BinaryFormatter` sink, use ysoserial.net
  to build an out-of-band/sleep gadget; a signed ViewState needs the machine key
  (out of scope unless provided).
- **Ruby**: a Marshal payload reaching a universal gadget — confirm with a benign
  observable, not a command.

Stop at the first unambiguous benign signal. One DNS interaction or one bounded
delay confirms the class; command execution is not needed and is gated.

### 5. Filter / WAF adaptation
- If a raw blob is blocked, record the behavior and try context-appropriate,
  in-scope transforms: Base64, gzip+Base64, URL-encoding, or an alternate gadget
  family (if Commons-Collections is filtered, try Spring/ROME; if one Fastjson
  gadget is patched, try another `@type`). A blocked-by-WAF or blocked-by-MAC
  result is itself worth recording — it is not a proven `n/a`.

## Recording the result

Record every `rce` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `rce`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | send blobs, capture request/response and out-of-band hits for `traffic_ref` | always available |
| Burp (MCP, when connected) | Repeater for iterative blobs; Collaborator for DNS/HTTP confirmation | only where a Burp instance is wired |
| ysoserial | Java gadget-chain generation | NOT installed by default — verify (`command -v ysoserial`, or the jar path) before use; if absent, use the manual method and record the attempt. When present, keep it in-scope: benign `URLDNS`/sleep/JRMP callbacks only, no `Runtime.exec`/file-write/reverse-shell on a live target without red-set sign-off. |
| ysoserial.net | .NET gadget / ViewState generation | NOT installed by default — verify before use; benign out-of-band gadgets only; a signed ViewState needs a provided machine key. |
| phpggc | PHP POP-chain generation | NOT installed by default — verify (`command -v phpggc`) before use; prefer callback/benign gadgets; no `system()` RCE on a live target without sign-off. |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`) sent
      during this task, not a source read.
- [ ] The serialized format was identified (magic bytes/prefix) and the detection
      reasoning is in `evidence`.
- [ ] Confirmation used a benign out-of-band gadget or bounded delay; no attacker
      command, file write, or shell ran against the live target.
- [ ] Any destructive escalation was gated on operator (red-set) sign-off, not
      decided here.
- [ ] Any `n/a` cites evidence that input cannot reach a deserialization sink, not
      an assumption.
