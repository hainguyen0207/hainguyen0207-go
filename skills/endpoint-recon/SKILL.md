---
name: endpoint-recon
description: Use when turning a target's JavaScript and recon output into a complete endpoint asset inventory — extract endpoints from JS, reconstruct full requests (method + params), probe port-aware (incl. vhosts), and write rich endpoint assets with an attack-surface appraisal.
metadata:
  type: offensive
  phase: recon
  tools: sync_recon_assets, extract_js_endpoints, replay_endpoint, upsert_endpoint_asset, linkfinder, jsluice, katana, curl
---

# Endpoint Reconstruction & Appraisal

Under an **authorized** engagement, build the most complete, fully-processed **endpoint asset inventory** for a target and appraise each endpoint's value as attack surface. This is recon/inventory — not exploitation. Stay strictly in scope.

The dedicated tools (`extract_js_endpoints`, `replay_endpoint`, `upsert_endpoint_asset`, `sync_recon_assets`) are live only when the operator enables the **Endpoint reconstructor** setting; when they return `feature disabled`, fall back to Bash (`linkfinder`/`jsluice`/`katana -jc` + `curl`) and `insert_assets type=endpoint`.

## The loop (per target)

1. **Aggregate first.** `sync_recon_assets(target)` — deterministically promotes every subdomain/IP/port/service/url/param the workflows found (nothing missed). Returns counts by type.
2. **Enumerate every host AND port.** A target is many sites. List all live hosts (subdomains **and** vhost-bound hosts) via `recon_assets`. For each host read its **open ports** (`recon_findings kind=port` / `recon_graph`): a vhost only adds a Host header to its IP, so probe **every open web port** (80/443/8080/8443/8000/8888/3000…), not just the default — a vhost may answer only on a non-standard port.
3. **Extract endpoints from JS.** Find the host's `.js` (and `.js.map`) files (`recon_findings kind=url` ending in `.js`). For each, `extract_js_endpoints(js_url)` to pull paths/routes/API calls hiding inside. Resolve relative paths against that host:port. Tag `source=js`, `from_js=<js_url>`. Do not stop at the apex — sweep subdomains and vhosts too.
4. **Reconstruct the request.** For each endpoint build a full signature: method (GET default; POST/PUT/… only when the source implies a write), absolute URL with explicit `:port`, params (query + body + path + header) with safe placeholder values, and headers (`Content-Type`, session/`Authorization` when the task provides them). Keep path-template markers (`/user/{id}`).
5. **Replay (safe).** `replay_endpoint` to observe the real response (status, length, content-type, title, auth-gate, redirect). Default GET/HEAD; write methods only when `endpoint_replay_write` is on. Never use destructive payloads.
6. **Write the asset.** `upsert_endpoint_asset` with the FULL data: url, method, params[], observed status/length/content-type, `source`, `from_js`, `reconstructed`, `synthetic`, and the appraisal. This is the deliverable.

## Appraisal rubric (score 0–100, higher = test first)

- **Sensitive path** (+10..30): `admin` `internal` `debug` `graphql` `actuator` `swagger`/`openapi`/`api-docs` `upload` `.git` `.env` `backup` `console` `metrics` `config` `phpinfo` `jenkins` `kibana` `grafana` `phpmyadmin` `heapdump`.
- **Suspicious param** (+12 each): `id|uid|user|account` → IDOR · `file|path|dir|page` → LFI · `url|uri|dest|callback|target` → SSRF · `redirect|return|next` → open-redirect · `cmd|exec|command` → RCE · `q|query|search|filter|sort` → injection · `token|key|apikey|password|secret` → secret · `role|is_admin|admin` → privesc · `template` → SSTI.
- **Write method** (+8): POST/PUT/PATCH/DELETE.
- **Telling status**: 200 unauth, 401/403 (auth-gated surface), 500 (leak); undocumented (JS-only) endpoints rank higher.

`score ≥ 60` = high-value (probe auth/IDOR/injection first); `≥ 30` = medium; else low. Record `{score, tags, hint}` in the asset's appraisal. Do **not** report findings here — just tag value so a pentester knows where to look.

## Discipline

- Every stored value must come from a real tool return (a finding, a replay). Never invent a status or a param. Mark `reconstructed`/`synthetic` honestly so this data is never mistaken for the app's genuine traffic.
- Work in increments; dedupe against `list_assets`. Store normalized URLs (`/user/{id}`) so variants collapse instead of flooding the inventory.
- Breadth first: get every host's JS endpoints in before deep-diving one.
