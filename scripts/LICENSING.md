# Offline licensing — vendor guide

The platform is **locked** until a valid license key is activated. Without a key,
reads work but running tasks / workflows / agents (any state change) is refused
with `402 license required`. You (the vendor) issue a signed code and send it to
the customer; they paste it in **System → License**. Verification is fully
offline — no activation server, no internet.

## How it works

- **Ed25519 signature.** You hold the private key; the product binary embeds only
  the public key (`licensing/pubkey.go`). A code is `base64(payload).base64(sig)`.
- A code carries: customer, tier, expiry, limits, optional feature list, and an
  optional **machine binding**.
- The private key lives at `scripts/license-private-key.b64` (gitignored, **never
  commit**). Keep an offline backup — losing it means re-keying every install.

## Issue a code

```bash
# any-machine, perpetual, pro
go run ./cmd/gen-license -key scripts/license-private-key.b64 \
    -customer "ACME Corp" -tier pro

# bound to the customer's machine, expires end of 2026, capped
go run ./cmd/gen-license -key scripts/license-private-key.b64 \
    -customer "ACME Corp" -tier pro -expires 2026-12-31 \
    -targets 10 -tasks 5 -machine <machine-id-from-customer>
```

The code is printed to **stdout** (pipe-friendly); the human-readable summary
goes to stderr. Send the stdout line to the customer.

### Machine-bound flow (recommended, anti-copy)
1. Customer installs → **System → License** shows their **Machine ID**.
2. Customer sends you that Machine ID.
3. You run `gen-license … -machine <id>` and send back the code.
4. The code activates only on that machine; copying it elsewhere fails.

Omit `-machine` for an any-machine code (simpler, but copyable).

## Flags

| flag | meaning | default |
|------|---------|---------|
| `-customer` | customer name (required) | — |
| `-tier` | `community` / `pro` / `enterprise` | `pro` |
| `-expires` | `YYYY-MM-DD`, empty = perpetual | perpetual |
| `-targets` / `-tasks` / `-tokens` | caps, 0 = unlimited | 0 |
| `-features` | comma list of allowed feature keys, empty = ALL | all |
| `-machine` | bind to one Machine ID, empty = any machine | any |
| `-key` | private key file (or `LICENSE_PRIVATE_KEY` env) | — |

## Rotating the signing key

```bash
go run ./cmd/gen-license keygen
```

Paste the printed **public** key into `licensing/pubkey.go` (`publicKeyB64`),
rebuild/ship the binary, and keep the new **private** key offline. All existing
codes stop verifying after a rotation, so re-issue them.

## Security note (honest)

This is offline + trust-based: a determined customer with the binary could patch
out the check. Machine-binding + keeping the private key offline raises the bar
for ordinary customers. For stronger guarantees add an online revocation check
later.
