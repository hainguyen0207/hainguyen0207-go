---
name: auth-bypass-testing
description: "Invoke this skill when testing an authorized app for authentication/authorization bypass (coverage class `auth_bypass`): forced browsing to protected pages, parameter/role tampering, session fixation, weak/guessable session tokens, JWT/SSO logic (alg:none, key confusion), 2FA/OTP bypass, and password-reset flaws (host-header, token leakage/predictability). Covers detection, non-destructive confirmation, and a bounded proof, then recording the result (report_finding when confirmed)."
---

# Auth Bypass Testing (coverage class: `auth_bypass`)

> **Platform note (hainguyen0207):** this skill comes from a variant with an exploit-coverage matrix. This platform has
> no `record_coverage_cell` / `record_methodology_gap` tools. Wherever the text says to record or close a matrix
> "cell" (one endpoint × parameter), follow **Recording the result** below instead: `report_finding` for a
> confirmed issue, otherwise a per-parameter test summary in your result. `traffic_ref` = the request ids you get
> from `traffic_search` (the recording proxy). Destructive steps are gated by the platform's red-set sign-off.

A per-class testing playbook that turns one `(route, role)` or `(endpoint, param)`
cell of the exploit-coverage matrix from `untested` into `tested`, `finding`, or a
proven `n/a`. It is the hunting detail behind the matrix: send attempts through
the recording proxy, read the app's reaction, adapt, and record the trail. This
is the dedicated playbook for identity and access-control logic — forced
browsing, role/parameter tampering, session and token weaknesses, JWT/SSO logic,
2FA/OTP, and password reset. It complements the `api-security`
authentication/authorization phases (which sweep an API surface); this skill is
the deeper, cell-closing drill behind a single access boundary.

Original bcpen content for the `auth_bypass` coverage class (no AntiFox
equivalent). Written for authorized engagements, bound to the coverage matrix and
the recording proxy.

## Boundaries

- Authorized scope only. The route, parameter, or account must be in the task's
  scope; never pivot to a host, tenant, or identity the engagement did not
  authorize.
- Non-destructive by default. Detection and confirmation are read-only: observe
  what a lower-privileged or unauthenticated context can reach. Never delete,
  disable, or lock out a real account, rotate a real user's credentials, or
  overwrite another user's data to "prove" access — those cross the destructive
  line and require the operator's sign-off (the red-set gate), not your own
  decision.
- Proof, not exfiltration. Confirm the boundary with the minimum: one object you
  are authorized to touch, your own second test account, or a single field a
  lower role should not see. Do not harvest other users' PII, sessions, or reset
  tokens; one controlled crossing is enough.
- Test accounts only. Account-takeover, reset, and 2FA chains run end-to-end only
  against accounts created for the test (A attacks B, both yours).
- Every claim needs a replayable artifact: the exact request, the exact response
  (status, redirect, body diff, or `Set-Cookie`), captured in the recording
  proxy — including the authorization context (which session/role sent it).

## Method

Work one boundary at a time. Establish an authorized baseline first, then test
what a weaker context can reach. Access-control claims need two contexts: the
privileged/owner view and the unprivileged/attacker view.

### 1. Baseline and context
- Authenticate as each role the task provides (admin, user, anonymous) and
  capture a known-good request/response for the protected resource from the
  context that SHOULD have it. This is the oracle every bypass is judged against.
- Record the session mechanism: cookie flags (`HttpOnly`, `Secure`, `SameSite`),
  bearer/JWT, or server session id; note where authorization is decided
  (gateway, app, per-object).

### 2. Detection (read-only)
- Forced browsing / missing function-level auth: request a protected route
  directly as a lower or anonymous context (no referer, no UI step). Try method
  swaps (`GET`↔`POST`/`PUT`/`DELETE`), trailing-slash and case variants
  (`/admin`, `/admin/`, `/Admin`), and `/v1` vs `/v2`. A 200 with real content
  where a 401/403/redirect is expected is the signal.
- Parameter / role tampering: flip client-trusted fields —
  `role=user`→`role=admin`, `isAdmin=false`→`true`, HTTP parameter pollution
  (`?role=user&role=admin`), and mass-assignment of a privilege field the server
  should ignore.
- Session fixation: set a known pre-auth session id, authenticate, and check
  whether the server issued a fresh one. No rotation on privilege change is the
  flaw.
- Weak/guessable tokens: collect several session ids or reset/invite tokens and
  inspect for sequential counters, timestamps, short length, or
  base64/hex-decodable structure. Predictability is the signal; do not brute a
  live endpoint under load.

### 3. JWT / SSO logic (read-only on captured tokens)
- `alg:none`: rewrite the header `{"alg":"none"}`, keep/raise claims (`sub`,
  `role`, `exp`), strip the signature, and replay. Acceptance = critical.
- Key confusion (RS256→HS256): re-sign with HMAC using the server's RSA public
  key as the secret; if the verifier treats it as HS256, it validates.
- Weak HMAC secret: offline dictionary attack against a captured token (never a
  live oracle). Claim tampering: edit `exp`/`iat`/`sub`/`role`/`aud` and observe
  enforcement. `kid`/`jku`/`x5u` abuse: path traversal or attacker-hosted key
  references, within scope.

### 4. 2FA / OTP and password reset (bounded, on test accounts)
- 2FA/OTP: can the post-password step be skipped (call the authenticated endpoint
  directly before completing 2FA)? Is a `verified` flag client-trusted? Check OTP
  reuse/replay, missing rate-limiting (report the mechanism with a handful of
  attempts, never a flood), and OTP or "remember-device" token leakage in a body.
- Password reset: host-header / `X-Forwarded-Host` poisoning to point the reset
  link at an attacker host; reset token predictability or leakage (URL, `Referer`,
  body, wrong account); token not bound to the user, not single-use, or not
  expired. Takeover chains run A→B between your own test accounts only.

### 5. Bounded confirmation
- Confirm with two contexts: the attacker context retrieving/altering what only
  the owner/privileged context should, judged against the owner view as the
  oracle. Capture both requests with their auth context.
- Stop at proof: one crossed boundary, one unauthorized field, or one forged
  token accepted. Do not enumerate every object or escalate further.

### 6. Filter / WAF / guard adaptation
- If a guard blocks a probe, record its behavior and try scope-appropriate
  variation: alternate encodings, method/case/path-normalization quirks, header
  casing. A blocked attempt is worth recording — it is not a proven `n/a`.

## Recording the result

Record every `auth_bypass` outcome so nothing is lost and nothing is re-tested:
- **Confirmed** - call `report_finding` with the exact replayable request and response (cite the proxy request
  ids from `traffic_search`), the injection point/context, and the demonstrated impact. The reporter agent then
  writes the full report; do not exaggerate severity beyond what you proved.
- **Tested, not vulnerable** - in your result, list each (endpoint, parameter) you tested for `auth_bypass`, the payload
  families tried, the app's reaction to each, the follow-ups those reactions prompted, and why you stopped. A
  single bare payload on a reachable parameter is NOT "tested" - adapt to what the response tells you.
- **Not applicable** - only with a proven reason the class cannot apply here (shown by evidence), never an
  assumption from the endpoint's name.

Reading source code or a config is not testing: a negative claim must rest on real requests sent through the
recording proxy.

## Tools

| Tool | Use | Notes |
|---|---|---|
| recording proxy + curl | replay requests across sessions/roles, capture request/response for `traffic_ref` | always available |
| Burp (MCP, when connected) | Repeater for token/claim edits; Autorize/AuthMatrix for two-session authorization diffing | only where a Burp instance is wired |
| jwt_tool | JWT attack automation (alg:none, key confusion, secret dictionary) | NOT installed by default — verify (`command -v jwt_tool`) before use; if absent, forge/edit tokens manually (base64url header/payload + the chosen signing) and record the attempts. Operate on captured tokens; keep secret cracking offline, not against a live oracle. |

## Completion self-check

- [ ] Every `tested`/`finding` cell cites a real proxy request (`traffic_ref`)
      sent during this task, not a source read.
- [ ] Each bypass finding is backed by two contexts: the attacker request and
      the privileged/owner oracle it was judged against.
- [ ] Confirmation used the minimum crossing; no real user's data, sessions, or
      reset tokens were harvested, and no real account was locked, reset, or
      taken over (takeover/reset/2FA chains ran only between test accounts).
- [ ] Any `n/a` cites evidence the route exposes no privileged state, not an
      assumption from its name.
