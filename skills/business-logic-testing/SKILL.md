---
name: business-logic-testing
description: "Invoke this skill when testing an authorized workflow/endpoint for business-logic flaws (coverage class `business_logic`): price/coupon/quantity tampering, step-skipping and state-rollback, replay, negative values, and TOCTOU races with a few concurrent requests, proven on test accounts only."
---

# Business Logic Testing (coverage class: `business_logic`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(endpoint, workflow)` cell of the
exploit-coverage matrix from `untested` into `tested`, `finding`, or a proven
`n/a`. It is the hunting detail behind the matrix: send attempts through the
recording proxy, read how the server's business rules respond, adapt, and record
the trail. Use it alongside `api-security` (which maps where parameters and
endpoints live, and carries the broad logic checklist) — this skill is the
depth behind that checklist: it decides whether a specific flow can be driven
into a state the application's rules should forbid.

Attribution: adapted from the `business-logic-testing` skill of
[AntiFox-AI/antifox](https://github.com/AntiFox-AI/antifox) (AGPL-3.0). Rewritten
in English, gated for authorized engagements, and bound to the coverage matrix;
no source was copied verbatim.

## Boundaries

- Authorized scope only. The workflow and its endpoints must be in the task's
  scope; never pivot to a host, flow, or account the engagement did not authorize.
- Non-destructive by default. Detection and confirmation drive the application's
  own flow on test accounts and test resources — a controlled cart, a disposable
  coupon, your own second user. Never confirm a flaw by moving real money, altering
  another tenant's records, or completing an irreversible action (fulfilment,
  payout, account deletion) against live data.
- Destructive or irreversible steps cross the red line. Completing a real payout,
  finalizing a real order, draining a real balance, or any one-way state change on
  production requires the operator's explicit sign-off (the red-set gate), never
  your own decision. Confirm up to the last reversible step and stop.
- Proof, not exfiltration. Prove impact with the minimum: one order priced to a
  controlled value, one coupon redeemed twice, one transition that should be
  impossible. Do not harvest other users' data or rack up real transactions.
- Races use a handful of concurrent requests, not load. A few parallel sends to
  catch a TOCTOU window is testing; volume that degrades the service is denial of
  service and out of bounds. No load testing.
- Every claim needs a replayable artifact: the exact request(s), the exact
  response(s) or the resulting state, and the account/role context, captured in
  the recording proxy.

## Method

Work one workflow at a time. Baseline the intended flow, then probe only the
server-enforced rule you are questioning.

### 1. Baseline the intended flow
- Walk the workflow once as a normal user through the recording proxy
  (registration, checkout, withdrawal, approval). Record each step's request and
  the state it sets, so every later attempt is judged against a real baseline.
- Note what is client-supplied vs server-derived: price, totals, quantity,
  discount, status, step token, user/owner id. Client-supplied values the server
  should re-derive are the primary targets.

### 2. Detection (read-only reasoning, then minimal probes)
- Identify the trust assumption behind each rule: does the server re-read the
  price from the catalog, or trust the body? Re-check the coupon, or count on the
  UI to stop reuse? Enforce step order, or accept the final step directly?
- Probe one assumption with one bounded request and compare against the baseline
  state — do not chain changes yet.

### 3. Context identification (which flaw family applies)
- **Parameter tampering** — resubmit with a client value the server should ignore:
  `price` lowered (`100.00` to `0.01`), `amount`/`total` reduced, `currency` swapped,
  `quantity`/`amount` negative (`-1`) to flip a sign or inflate a balance, or
  quantity past a per-order cap. Also HTTP parameter pollution (`?role=user&role=admin`)
  and mass assignment (`is_admin: true`, `owner_id`, `status`) added to a body.
- **Workflow / step control** — request the final step directly (payment-confirm
  without payment), reorder steps, or replay a step the flow expects once.
- **State transition abuse** — drive a status the state machine forbids via the
  status-changing endpoint: roll a `paid`/`completed` order back to `pending`, or
  jump `cart` straight to `shipped`.
- **Replay / idempotency** — resend a one-time action: redeem a single-use coupon
  twice, reuse a used nonce/receipt, re-POST a withdrawal. A missing or ignored
  idempotency key is the signal.
- **Privilege / role matrix** — run the same workflow as admin, standard user, and
  read-only, diffing what each may reach; a lower role reaching a higher-role action
  is the finding (coordinate object/function-level access with `api-security`'s
  BOLA/BFLA checks).

### 4. Bounded confirmation
- Confirm with the least impact on test data: one checkout that settles at the
  tampered price, one coupon accepted a second time, one forbidden transition the
  server accepts. Capture the request(s) and the resulting state.
- For TOCTOU (double-spend of a balance, over-redeeming a limited stock or coupon),
  send a small burst of identical requests in parallel — enough to hit the window,
  typically a handful — and show two succeeded where one should have. Stop once the
  race is demonstrated.
- Stop at the last reversible step. If proof would require a real, irreversible
  completion, record the state reached and escalate to the operator instead.

### 5. Filter / WAF adaptation
- If a value is rejected, record the rejection and try context-appropriate
  variants within scope: alternate encodings or types (string vs number for an
  amount), nested vs flat JSON, duplicate keys, array vs scalar, the same value in
  a header or path the server also reads. A blocked attempt is itself worth
  recording — it is not a proven `n/a`.

## Recording the result

Record every `business_logic` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `business_logic`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | drive the workflow, tamper values, replay, fire a small parallel burst; capture request/response for `traffic_ref` | always available |
| Burp (MCP, when connected) | Repeater for flow replay, Intruder for value sweeps, Turbo Intruder / the single-packet race for a tight TOCTOU window | only where a Burp instance is wired |
| jwt_tool | inspect/forge role or `sub` claims when a privilege-matrix test needs it | NOT installed by default — verify (`command -v jwt_tool`) before use; if absent, tamper the token manually and record the attempt. Keep it to test accounts, non-destructive. |

A short `curl` loop with `&` (or `xargs -P`) sending a handful of identical
requests is enough for a race; never scale it into a load tool. Every tool stays
in-scope, on test accounts/resources, and never completes an irreversible action
on a live target.

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`) sent
      during this task, not a source read.
- [ ] Confirmation used test accounts/resources and minimum impact; no real user
      data was exfiltrated and no real money or inventory moved.
- [ ] No irreversible/destructive completion ran on the live target without
      operator sign-off (the red-set gate).
- [ ] Any race used a handful of concurrent requests, not load.
- [ ] Any `n/a` cites evidence that no client-trusted value or skippable/forbidden
      transition exists, not an assumption.
