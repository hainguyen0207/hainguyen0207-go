---
name: ssti-testing
description: "Invoke this skill when testing an authorized endpoint/parameter for server-side template injection (coverage class `ssti`): detect with a math polyglot, identify the engine (Jinja2/Twig/Freemarker/Velocity/ERB/Handlebars), prove impact with a bounded non-destructive check, then record the result on the coverage matrix."
---

# Server-Side Template Injection Testing (coverage class: `ssti`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, param)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: send attempts through the
recording proxy, read how the template engine evaluates the input, adapt, and
record the trail. Use it alongside `api-security` (which maps where parameters
live) — this skill decides whether an input is rendered as a template expression
rather than inert text.

Original bcpen content for the `ssti` coverage class — not adapted from AntiFox,
which has no equivalent skill.

## Boundaries

- Authorized scope only. The endpoint must be in the task's scope; never pivot to
  a host or parameter the engagement did not authorize.
- Non-destructive by default. Detection, identification, and confirmation use
  evaluation-only payloads (arithmetic, string ops, a benign object read, an
  out-of-band callback). Never drop to code/command execution — no
  `os.popen`/`Runtime.exec`/backtick/`system()`, no file read or write, no
  reverse shell — against a live target. Full RCE exploitation crosses the
  destructive/irreversible line and requires the operator's sign-off (the red-set
  gate), not your own decision.
- Proof, not exfiltration. Confirm with the minimum: the reflected arithmetic
  result, the engine name, or a single benign non-sensitive value (a config
  constant you are authorized to read, or an OOB DNS/HTTP hit). Do not read
  `/etc/passwd`, environment secrets, or application source to "prove" it.
- Out-of-band callbacks target only an interaction host you control for this
  engagement (Burp Collaborator or equivalent); one hit confirms execution — do
  not loop or stage further payloads through it.
- Every claim needs a replayable artifact (request + response, or the recorded
  OOB interaction) captured in the recording proxy.

## Method

Work one parameter at a time. Baseline first; detection stays read-only,
confirmation stays bounded.

### 1. Reach and baseline

- Confirm the input reaches a rendered context (a page, an email/PDF template, a
  filename, an error message, or an SSR component). A value that never appears in
  rendered output is a candidate `n/a` once shown not template-evaluated anywhere.
- Record the normal response (status, length, how the value is echoed) as a
  baseline, and distinguish template evaluation from plain reflection early —
  plain reflection is XSS territory (`xss`), not `ssti`.

### 2. Detection (read-only)

- Math polyglot: send a value valid in several engines that evaluates to an
  unmistakable result — `${7*7}` · `{{7*7}}` · `#{7*7}` · `<%= 7*7 %>` ·
  `*{7*7}` · `@(7*7)`. A reflected `49` is the positive signal; the literal
  `7*7` coming back means no evaluation in that syntax. Capture each
  request/response.
- Disambiguate from expression reflection with `{{7*'7'}}` — Jinja2/Twig return
  `7777777`, a non-evaluating context returns the literal.
- Keep detection to evaluation only: arithmetic and string ops. No object or
  method access yet — that is confirmation.

### 3. Context / engine identification

Fingerprint the engine from the detection results, so later syntax is correct.
Record which delimiter evaluated and which did not — that mapping is the engine
evidence.

- `{{7*7}}` → `49`: Jinja2 or Twig. Distinguish `{{7*'7'}}` (`7777777` → Jinja2)
  vs a Twig filter (`{{'%s'|format(7*7)}}` → `49`, Twig).
- `${7*7}` → `49`: Freemarker (`${"x"?upper_case}`), Velocity (`#set($x=7*7)$x`),
  or a JSP EL / Spring context.
- `#{7*7}` → `49`: Ruby ERB or Spring SpEL — confirm with `<%= 7*7 %>` (ERB) vs
  `#{T(java.lang.Math).PI}` (SpEL, read-only constant).
- `{{7*7}}` literal but `{{7}}` → `7`: Handlebars / Mustache — logic-less, so
  arithmetic will not evaluate; identification relies on helper/`#with` behavior.

### 4. Bounded confirmation

Prove impact with the least, safest expression the engine allows — a benign read,
never a command. In every branch, object/constant access plus the reflected `49`
is sufficient proof; the RCE gadget that follows it is the red-set escalation,
not yours to run on a live target.

- Jinja2 (Python): `{{ self }}` / `{{ [].__class__ }}` shows object access —
  do NOT walk `__subclasses__` into `os.popen`/`subprocess`.
- Twig (PHP): `{{ _self }}` or `{{ ['id']|map('upper')|join }}` — stop before
  `registerUndefinedFilterCallback` chains.
- Freemarker (Java): a benign built-in (`${"x"?upper_case}` → `X`) — do NOT
  reach for `freemarker.template.utility.Execute`.
- Velocity (Java): `#set($x=7*7)$x` — stop before `.getRuntime()` reflection.
- ERB (Ruby): `<%= 7*7 %>` evaluates — do NOT send `<%= system(...) %>`.
- Spring SpEL (Java): `#{T(java.lang.Math).PI}` read-only constant — stop before
  `T(java.lang.Runtime)`.
- Handlebars: a safe helper or `{{#with}}` context access — do not stage the
  prototype-pollution/`require` chain.
- Blind output: where the engine can make a network call through a benign
  built-in, trigger one DNS/HTTP hit to your interaction host and confirm it in
  the OOB log. One interaction is proof; do not pivot it into a data channel.

A reflected `49`, the identified engine, and one bounded read (or OOB hit) is a
complete `finding`.

### 5. Filter / WAF adaptation

If delimiters or keywords are filtered, record the behavior and try
context-appropriate, in-scope evasions: alternate delimiters the engine also
honors (`${}` vs `{{}}` vs `#{}`), whitespace/newline inside the braces, bracket
access instead of dotted (`['__class__']`), concatenation to split a blocked
token (`{{'__cla'~'ss__'}}`), or case variation. A blocked-by-WAF result is
itself worth recording — it is an attempt and its reaction, not a proven `n/a`.

## Recording the result

Record every `ssti` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `ssti`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | send polyglots, capture request/response for `traffic_ref` | always available |
| Burp (MCP, when connected) | Repeater/Intruder for iterative polyglots; Collaborator for OOB confirmation | only where a Burp instance is wired |
| tplmap | automated SSTI detection/engine identification | NOT installed by default — verify (`command -v tplmap`) before use; if absent, use the manual method above and record the attempts. When present, keep it within scope and non-destructive: detection/identification only, never `--os-shell`/`--os-cmd`/`--upload`/`--download` or a reverse shell on a live target. |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`)
      sent during this task, not a source or template read.
- [ ] Detection distinguished template evaluation from plain reflection
      (`{{7*7}}` → `49`, `{{7*'7'}}` → `7777777`), not just an echoed string.
- [ ] The identified engine is backed by which delimiters did and did not
      evaluate, captured in evidence.
- [ ] Confirmation used the minimum (reflected arithmetic, engine name, one
      benign read / one OOB hit) — no command execution, file read, or secret.
- [ ] No RCE gadget, shell, or file-write payload ran against the live target
      without the red-set gate.
