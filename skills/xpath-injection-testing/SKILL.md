---
name: xpath-injection-testing
description: "Invoke this skill when testing an authorized endpoint/parameter that feeds an XPath or XQuery expression over XML (login forms, XML search, config/record lookups): quote-breaking, boolean/blind extraction of the XML tree, and string-length/character oracles. Not a fixed coverage class — record the methodology gap, promoting a confirmed one to a finding."
---

# XPath / XQuery Injection Testing (methodology gap, not a matrix class)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook for inputs that are concatenated into an XPath or
XQuery expression evaluated against an XML document or store. When the app builds
a query like `//user[name='…' and pass='…']` from raw input, a broken quote lets
you rewrite the predicate: bypass the match, enumerate the tree, and read nodes
character by character through a boolean oracle. Use it alongside `api-security`
(which maps where parameters live and how the endpoint is reached) — this skill
decides whether a given input reaches an XPath/XQuery sink.

XPath/XQuery injection is **not** one of the fixed exploit-coverage-matrix classes,
so there is no `(endpoint, param)` cell to close. Record it instead with
your result: log the technique you exercised and what the target did.
If you confirm a real injection, promote the gap to a finding with
`report_finding`. 

Attribution: adapted from the `xpath-injection-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix;
no source was copied verbatim.

## Boundaries

- Authorized scope only. The endpoint must be in the task's scope; never pivot to
  a host, parameter, or XML backend the engagement did not authorize.
- Non-destructive by default. Detection and confirmation are read-only: predicate
  rewrites, boolean comparisons, and `string-length`/`substring` oracles only read
  the existing document. Never send XQuery update/`insert`/`delete`/`replace`
  expressions, `doc()`/`collection()` writes, or `fn:put()` against a live target —
  those cross the destructive line and need the operator's sign-off (the red-set
  gate), never your own decision.
- Mind the sibling sinks. If the endpoint also parses XML you supply, XXE and SSRF
  (external entities, `doc('http://…')` to an internal host) are separate,
  higher-impact classes — flag and hand off, don't fire blind external fetches here.
- Proof, not exfiltration. Confirm with the minimum: the count of top-level nodes,
  one element name, or a few characters of a single non-sensitive field. Do not
  extract whole credential stores; one controlled value proves the oracle.
- Every claim needs a replayable artifact: the exact request, the exact response
  (or the measured divergence), captured in the recording proxy.

## Method

Work one parameter at a time. Baseline first, then escalate only as the response
justifies it. XPath is unauthenticated query logic with no comment syntax and no
privilege model, so the whole document is reachable once the predicate breaks.

### 1. Reach and baseline
- Confirm the input reaches an XML query (reflected in results, changes a match,
  or alters an error). A parameter that never changes the response is a candidate
  methodology-gap `n/a` once you show it does not reach an XPath context.
- Record the normal response: status, length, result set, and any XML/XPath error
  text, so every later payload is judged against a real baseline.

### 2. Detection (read-only)
- Quote probe: send a single `'`, then `"`, then `]`, then `)`. An
  `XPathException`, a 500, `Invalid expression`, `javax.xml.xpath`, or a changed
  result shape is a signal — capture it. Unterminated-string or syntax errors
  point straight at string concatenation.
- Boolean pair on the same parameter: a true form vs a false form that should
  differ only in the boolean. For a single-quoted string context,
  `x' or '1'='1` (true) vs `x' or '1'='2` (false), or numeric `1 or 1=1` vs
  `1 or 1=2`. A consistent true/false divergence is strong evidence.
- Match the surrounding syntax: common closers are `']`, `')`, `')]`. XPath 1.0 has
  no comment, so balance the rest of the predicate (e.g. `… or '1'='1`), not
  truncate it.

### 3. Context identification
- Determine the quoting (single vs double vs numeric) and the structure you sit in
  (`[predicate]`, a function argument, an axis step) from how each closer behaves.
- Note the engine where you can: an error naming `javax.xml.xpath` (Java),
  `System.Xml.XPath` (.NET), `libxml2`/`lxml` (PHP/Python), or BaseX/eXist/Saxon
  tells you whether XPath 2.0/3.1 or XQuery functions are in reach.

### 4. Bounded confirmation
- Authentication bypass: where the predicate gates a match, break out so it is
  always true — username `admin' or '1'='1` produces
  `//user[name='admin' or '1'='1' and pass='…']`. Prove it returns a record you are
  authorized to reach; do not ride it into another user's data.
- Blind tree extraction via boolean oracle, the minimum to prove it:
  - Node count: `… or count(/*)=N or …`, raise `N` until the true/false flips, to
    learn the document breadth.
  - String length: `… or string-length(//user[1]/name)=K or …`.
  - Character read: `… or substring(//user[1]/name,1,1)='a' or …`, stepping the
    index — demonstrate a few characters, not the whole value.
- Where the boolean does not reflect, an XPath-2.0 `error()` oracle on a true
  branch or a plain response-diff oracle are read-only alternatives.
- Stop at proof. One element name, one length, or a few characters is enough;
  dumping the document is out of bounds.

### 5. Filter / WAF adaptation
- If payloads are filtered, record the filter behavior and try context-appropriate,
  in-scope evasions: swap `'1'='1` for `'a'='a`, use `or true()`/`not(false())` or
  `or 1` where numeric, `contains()` in place of `substring()`, `position()=1` for
  `[1]`, or URL/double-URL/XML-entity encoding of the quote. A blocked-by-WAF result
  is itself worth recording — it is not a proven `n/a`.

## Recording the result

`xpath-injection` is outside the fixed class list, so record it precisely:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point, and the demonstrated impact.
- **Tested, not vulnerable** - in your result, list each technique you exercised, the parameter, what the
  target did, and why you stopped, so the planner does not repeat it.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | send payloads, capture request/response for the traffic reference | always available |
| Burp (MCP, when connected) | Repeater for iterative predicate rewrites, Intruder for the char/length oracle | only where a Burp instance is wired |
| xcat | automated XPath blind extraction | NOT installed by default — verify (`command -v xcat`) before use; if absent, use the manual oracle above and record the attempts. When present, keep it within scope and read-only: no out-of-band `doc()`/entity fetches, no file read/write against a live target. |

## Completion self-check

- [ ] Every recorded gap / finding cites a real proxy request (traffic reference)
      sent during this task, not a source read.
- [ ] Confirmation used the minimum data; no credential store or full document was
      extracted.
- [ ] No XQuery update, external-entity, or out-of-band fetch ran against the live
      target; XXE/SSRF were handed off, not fired blind.
- [ ] A confirmed injection was promoted to `report_finding`; an unexploitable
      parameter was recorded in your result.
- [ ] Any `n/a` cites evidence that input cannot reach an XPath/XQuery sink, not an
      assumption.
