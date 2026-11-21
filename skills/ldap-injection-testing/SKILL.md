---
name: ldap-injection-testing
description: "Invoke this skill when testing an authorized login or directory-search endpoint for LDAP injection in the query filter (special chars ( ) * \\ / | & =, filter manipulation, blind boolean): detection, non-destructive confirmation, and a bounded proof. LDAP injection is not a fixed coverage class — record what you tested in your result, and report a confirmed one with report_finding."
---

# LDAP Injection Testing (methodology gap, not a coverage class)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-technique testing playbook for LDAP injection: when user input reaches an
LDAP search or bind filter without proper escaping, an attacker can rewrite the
filter to bypass authentication or read directory entries they should not see.
Unlike `sqli`, LDAP injection is **not one of the fixed coverage-matrix classes**,
so it has no `(endpoint, param)` cell to turn `tested`. Record it as a methodology
gap instead (see below). Use it alongside `api-security` (which maps where
parameters live and which inputs feed auth/search) — this skill decides whether a
given input reaches an LDAP filter sink.

Attribution: adapted from the `ldap-injection-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix; no
source was copied verbatim.

## Boundaries

- Authorized scope only. The endpoint must be in the task's scope; never pivot to
  a host, directory, or parameter the engagement did not authorize.
- Non-destructive by default. Detection and confirmation use read-only filter
  probes (equality, presence, boolean). LDAP write operations — `add`, `modify`,
  `delete`, `modifyDN`, or a filter that changes a group membership or an account
  attribute — cross the destructive line and require the operator's sign-off (the
  red-set gate), never your own decision.
- Proof, not exfiltration. Confirm with the minimum: an authentication bypass into
  a test account, the presence of one attribute, or a single non-sensitive entry.
  Do not enumerate the whole directory or dump real users' attributes; one
  controlled result is sufficient evidence.
- Blind boolean oracles are bounded: send the handful of requests needed to prove
  the true/false divergence, not a character-by-character extraction of real
  secrets. Extracting one harmless known value to demonstrate the oracle is enough.
- Every claim needs a replayable artifact: the exact request, the exact response
  (or the observed login/no-login outcome), captured in the recording proxy.

## Method

Work one parameter at a time. Baseline first, then escalate only as the response
justifies it. LDAP filters use prefix notation — `(&(a=x)(b=y))` is `a=x AND b=y`,
`(|(a=x)(b=y))` is OR, `(!(a=x))` is NOT — so injection is about closing the
current clause and grafting on your own.

### 1. Reach and baseline
- Find inputs that plausibly feed an LDAP filter: login username/password,
  directory/people search, group or org-unit lookups, address-book fields.
- Record the normal response for a valid and an invalid input: status, length,
  login outcome, result count, and any error text, so every later payload is
  judged against a real baseline.

### 2. Detection (read-only)
- Special-character probe, one at a time: `(`, `)`, `*`, `\`, `/`, `|`, `&`, `=`,
  and a lone `)` or `*)`. In LDAP, `*` is the wildcard and the parentheses/`\`
  are structural. A 500, a malformed-filter error, a changed result count, or a
  different login outcome is a signal — capture each.
- Wildcard test on a search field: submit `*` where an exact value is expected. If
  one entry comes back for a specific term but many come back for `*`, input is
  reaching the filter unescaped.
- Boolean pair on the same parameter: a form that should be true vs one that should
  be false, differing only in the injected clause, e.g. value `*)(objectClass=*)`
  vs `*)(objectClass=nonexistent12345)`. A consistent true/false divergence in
  result count or login outcome is strong evidence.

### 3. Context identification
- Determine where the input lands in the filter: inside an equality value
  (`(uid=INPUT)`), as a whole clause, or across the username/password pair of a
  bind filter `(&(uid=INPUT)(userPassword=INPUT))`.
- Decide how many parentheses you must close and whether a trailing clause is left
  dangling. If a dangling `)` breaks the filter, neutralize it with a
  `(&)` / `(|)` absolute-true/false clause or a wildcard that the server tolerates,
  adapting until the filter parses.

### 4. Bounded confirmation
- Authentication bypass: in a bind filter, inject `*)(uid=*))(|(uid=*` or the
  classic `admin)(&)` / `*)(&` depending on how many parens must close, so the
  password clause is neutralized and the bind succeeds as a test account you are
  authorized to use. Prove it by landing an authenticated session, not by asserting
  it.
- Wildcard disclosure: on a search endpoint, confirm that `name=*` or
  `value*)(uid=*` returns entries beyond the one the UI intended — one extra
  controlled entry is proof; stop before enumerating real records.
- Blind boolean, when output is uniform: use an absolute-true `(&)` vs
  absolute-false `(|)`, or a presence filter `(attr=*)` vs `(attr=nonexistent)`, as
  the oracle, and extract a single harmless known value to demonstrate the channel.
  Do not loop it over real secrets.
- Stop at proof. One bypassed login, one extra entry, or one working oracle is
  enough; mass enumeration is out of bounds.

### 5. Filter / WAF adaptation
- If payloads are filtered, record the filter behavior and try context-appropriate
  evasions within scope: URL-encoding the structural characters (`%28` `%29` `%2a`
  `%5c`), escaping variants, case changes on attribute names (LDAP attribute names
  are case-insensitive), alternate attributes (`cn`, `sAMAccountName`, `mail`,
  `member`) for the same logical test, and whitespace. A blocked-by-WAF result is
  itself worth recording — it is not a proven absence of the bug.

## Recording the result

`ldap-injection` is outside the fixed class list, so record it precisely:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point, and the demonstrated impact.
- **Tested, not vulnerable** - in your result, list each technique you exercised, the parameter, what the
  target did, and why you stopped, so the planner does not repeat it.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | send filter payloads, capture request/response for `traffic_ref` | always available |
| Burp (MCP, when connected) | Repeater/Intruder for iterative filter payloads and login-outcome diffing | only where a Burp instance is wired |
| `ldapsearch` (OpenLDAP client) | craft/replay raw filters against an in-scope directory | NOT installed by default — verify (`command -v ldapsearch`) before use; if absent, use the manual method above and record the attempts. When present, keep it read-only and in-scope: search binds only, never `ldapmodify`/`ldapadd`/`ldapdelete` against a live target. |
| `python3` + `ldap3` | scripted, bounded confirmation of a filter | NOT installed by default — verify (`command -v python3` and the module import) before use; keep operations read-only (search), no writes on a live directory. |

## Completion self-check

- [ ] Every attempted technique was recorded in your result, citing a
      real proxy request (`traffic_ref`) sent during this task, not a source read.
- [ ] Any confirmed injection was promoted to a finding with a replayable
      request/response and the filter context.
- [ ] Confirmation used the minimum data; no directory enumeration or dump of real
      users' attributes.
- [ ] No LDAP write (`add`/`modify`/`delete`/`modifyDN`) ran against the live target
      without operator sign-off.
- [ ] A blocked-by-WAF outcome was recorded as such, not mistaken for absence of the
      vulnerability.
