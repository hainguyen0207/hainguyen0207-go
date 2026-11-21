---
name: sql-injection-testing
description: "Invoke this skill when testing an authorized endpoint/parameter for SQL injection (coverage class `sqli`): error-based, boolean/time blind, UNION, stacked, and second-order, across MySQL, PostgreSQL, MSSQL, Oracle, and SQLite. Covers detection, non-destructive confirmation, and a bounded proof, then recording the result (report_finding when confirmed)."
---

# SQL Injection Testing (coverage class: `sqli`)

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
whether a given input reaches a SQL sink.

Attribution: adapted from the `sql-injection-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix and
recording proxy; no source was copied verbatim.

## Boundaries

- Authorized scope only. The endpoint must be in the task's scope; never pivot to
  a host or parameter the engagement did not authorize.
- Non-destructive by default. Detection and confirmation use read-only payloads
  (`SELECT`, boolean, timing). Never run `UPDATE`/`DELETE`/`DROP`, stacked writes,
  or `xp_cmdshell`/`LOAD_FILE`/`INTO OUTFILE` against a live target — those cross
  the destructive line and require the operator's sign-off (the red-set gate), not
  your own decision.
- Proof, not exfiltration. Confirm the vulnerability with the minimum: the
  database version, `current_user`, or a single non-sensitive row. Do not dump
  tables of real user data; one controlled value is sufficient evidence.
- Timing payloads are bounded: use a short, unambiguous delay (e.g. `SLEEP(3)`)
  once to confirm, not a scaled or repeated load that degrades the service.
- Every claim needs a replayable artifact: the exact request, the exact response
  (or the measured delay), captured in the recording proxy.

## Method

Work one parameter at a time. Baseline first, then escalate only as the response
justifies it.

### 1. Reach and baseline
- Confirm the input actually reaches the backend (reflected, affects results, or
  changes an error). A parameter that never alters the response is a candidate
  `n/a` once you have shown input does not reach a SQL context.
- Record the normal response: status, length, timing, and any result set, so every
  later payload is judged against a real baseline.

### 2. Detection (read-only)
- Error probe: a single `'`, then `"`, then `)`. A SQL error, a 500, or a changed
  result shape is a signal — capture it.
- Boolean pair on the same parameter: a true form vs a false form that should
  differ only in the boolean, e.g. `… AND 1=1` vs `… AND 1=2` (adapt the quoting
  and comment to the context: `'`, `"`, numeric, `)`, `--`, `#`, `/* */`).
  A consistent true/false divergence is strong evidence.
- Time-based, when output is blind: one bounded delay (`… AND SLEEP(3)` / `pg_sleep(3)`
  / `WAITFOR DELAY '0:0:3'`), compared against the baseline timing. Confirm once;
  do not loop.

### 3. Context identification
- Determine the injection context (string vs numeric, in `WHERE`/`ORDER BY`/`LIMIT`,
  inside a function) from how the quoting and comments behave.
- Fingerprint the DBMS from error text or version probes
  (`@@version`, `version()`, `sqlite_version()`), so later syntax is correct.

### 4. Bounded confirmation
- Prove impact with the least data: `UNION SELECT` the version/`current_user`, or a
  boolean/time oracle extracting a single harmless value. Column count via
  `ORDER BY n` or progressive `UNION SELECT NULL,…`.
- Second-order: when a stored value is later used in a query, inject at the store
  and observe at the sink; capture both requests.
- Stop at proof. Extracting schema or one controlled row is enough; mass dumping is
  out of bounds.

### 5. WAF / filter adaptation
- If payloads are filtered, record the filter behavior and try context-appropriate
  evasions within scope: inline comments, case/whitespace variation, alternate
  operators, encoding. A blocked-by-WAF result is itself worth recording — it is
  not a proven `n/a`.

## Recording the result

Record every `sqli` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `sqli`, the payload
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
| Burp (MCP, when connected) | Repeater/Intruder for iterative payloads | only where a Burp instance is wired |
| sqlmap | automated detection/exploitation | NOT installed by default — verify (`command -v sqlmap`) before use; if absent, use the manual method above and record the attempts. When present, keep it within scope and non-destructive: `--level`/`--risk` low, no `--os-shell`/`--file-write`/`--sql-shell` on a live target. |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`) sent
      during this task, not a source read.
- [ ] Confirmation used the minimum data; no table of real user data was dumped.
- [ ] No destructive or stacked-write payload ran against the live target.
- [ ] Any `n/a` cites evidence that input cannot reach a SQL sink, not an assumption.
