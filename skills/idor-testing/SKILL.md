---
name: idor-testing
description: "Invoke this skill when testing an authorized endpoint/parameter for broken object-level access control / IDOR (coverage class `idor`): enumerate numeric ids and UUIDs, run a two-session replay where account A requests account B's object, and swap HTTP method or role — proving the authorization boundary with a second account, then recording the result (report_finding when confirmed)."
---

# IDOR / Object-Level Access Control Testing (coverage class: `idor`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, param)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: send attempts through the
recording proxy, read the app's reaction, adapt, and record the trail. Use it
alongside `api-security` — this skill is the depth behind that skill's Phase 3
(BOLA/IDOR/BFLA), deciding whether a given object reference is actually
enforced per-caller.

Attribution: adapted from the `idor-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix;
no source was copied verbatim.

The defining rule for this class: **an IDOR finding only exists once a SECOND
account or role has proven the boundary is real.** Guessing an id and getting a
200 back from your own session proves nothing — the object may be yours, public,
or unauthenticated by design. The finding is the *cross-account* read or write.

## Boundaries

- Authorized scope only. The endpoint must be in the task's scope; never pivot to
  a host, path, or object the engagement did not authorize.
- Non-destructive by default. Detection and confirmation are read-only
  cross-account reads. A write, update, or delete that proves object-level
  authorization on a *write* endpoint crosses the destructive line and requires
  the operator's sign-off (the red-set gate), not your own decision — and even
  then only against resources created for the test.
- Proof, not exfiltration. One cross-account record you are authorized to touch
  (test account B, or a single record the engagement designated) is sufficient.
  Do not loop over an id range to pull real users' data; stop at one controlled
  object that proves the boundary. The two sessions should be accounts you
  control (A and B) or roles the engagement provisioned, not real customers.
- Every claim needs a replayable artifact: both requests (A's and B's), both
  responses, and the session/authorization context that produced each, captured
  in the recording proxy.

## Method

Work one object reference at a time. You need two authenticated contexts ready
before you start: session A and session B (or a privileged role and an
unprivileged one). Baseline first, then escalate only as the response justifies.

### 1. Reach and baseline
- Identify the object reference the endpoint consumes: a path segment
  (`/api/v1/invoice/1042`), a query param (`?user_id=1042`), a body field
  (`{"account":"1042"}`), or a header. Note its shape — sequential int,
  UUIDv4, Base64, hashid, composite.
- With session A, capture the *authorized* baseline: fetch A's own object and
  record status, length, and the identifying fields in the body. This is the
  response shape a successful cross-account read would reproduce for B's data.

### 2. Detection (read-only, single probe)
- Enumerate a *neighbouring* id that you have reason to believe belongs to
  another tenant: `/invoice/1042` → `/invoice/1041`. One probe, not a sweep.
- For UUIDs and opaque ids: do not blind-guess. Harvest a *known* B-owned id from
  B's session or a reference in another response, then replay it under A. UUIDv4
  is not a security control, but it is not enumerable — a real finding needs a
  real B-owned id, not a random guess.
- Read the result against A's baseline: same shape but B's data = candidate
  IDOR; `403`/`404`/empty = boundary likely enforced (record it, keep going).

### 3. Context identification
- Horizontal: A reading/altering B's same-privilege object (the common IDOR).
- Vertical (BFLA-adjacent): an unprivileged role reaching a privileged object or
  endpoint (`/admin/user/1042`, `/settings`, `/audit-log`).
- Determine *where* authorization should live: the object id, the session, or
  both. A server that trusts the id in the request and ignores the session is the
  bug.

### 4. Bounded confirmation — the two-session replay
- This is the load-bearing step. Take the exact request that succeeds for its
  owner, swap *only* the session credential (cookie / `Authorization` bearer /
  API key) to the other account, replay, and diff the responses.
  - A's request for B's object, authenticated as A → if A receives B's data, the
    object-level check is missing. Confirmed horizontal IDOR.
  - Unauthenticated replay (strip the credential entirely) → if the object still
    returns, it is unauthenticated exposure.
- Capture both the owner request and the cross-account request so the pair is
  replayable. The credential swap, with everything else held constant, is the
  proof.
- Stop at one object. One cross-account read that returns B's data closes the
  cell as a `finding`; enumerating the range is exfiltration, not proof.

### 5. Method / role swap and filter adaptation
- Method swap: if `GET /invoice/1042` is authorized, try `PUT`/`PATCH`/`DELETE`
  on the same reference as the non-owner — read-only unless the red-set gate is
  cleared. A read enforced but a write unenforced is a real finding.
- Variation when the obvious reference is blocked: alternate names (`id`, `uid`,
  `user_id`, `account`), parameter pollution (`?id=A&id=B`), version/path
  variants (`/v1/` vs `/v2/`, trailing slash), wrapped-id forms, and id
  obfuscation (re-encode B's id to test whether a Base64/hashid wrapper is
  decorative). A blocked attempt is worth recording — it is not a proven `n/a`.

## Recording the result

Record every `idor` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `idor`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | replay a request under two sessions, diff responses, capture `traffic_ref` | always available — the core workflow for this class |
| Burp (MCP, when connected) | Repeater for the credential swap; Autorize / AuthMatrix for automated two-session diffing; Intruder for bounded id probes | only where a Burp instance is wired |
| ffuf / custom scripts | id probing | NOT installed by default — verify (`command -v ffuf`) before use; if absent, use the manual curl replay. When present, keep it in-scope and non-destructive: one neighbouring id, not a range sweep over real users' data. |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`)
      sent during this task, not a source read.
- [ ] Each `finding` was confirmed by a two-session replay: the same request
      under a second account/role, with both requests and responses captured.
- [ ] Confirmation stopped at one controlled cross-account object; no id range of
      real user data was enumerated.
- [ ] No write/update/delete ran against a live target without the red-set gate.
- [ ] Any `n/a` cites evidence the object is public-by-design or session-bound,
      not an assumption from the endpoint.
