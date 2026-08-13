# DUCAT Oracle (cre-hmac) — Security Audit

_Multi-agent audit: 7 dimension reviewers → 2-lens adversarial verification per finding → manual confirmation of every critical. 81 agents, 30 findings confirmed after verification, 4 disputed, 2 refuted. Secret values are fingerprinted (length + first/last 2 chars), never printed._

---

## Executive verdict

**Posture: the cryptography is good; the operational security around it is not.** The core commitment scheme is sound — ladder secrets are HMAC-committed and only revealed on breach, private keys are range-validated, comparisons are constant-time, and there is no premature secret exposure. But that careful crypto is wrapped in a trust model with holes big enough to move the published price or impersonate the oracle. The three things that matter for money infrastructure — *is the signing key secret, is the price authentic, can only the oracle move it* — currently each have a confirmed failure. **The oracle signing key is in public git history. The production workflow consumes price-adjustment events with no signature/author check. The Chainlink price is trusted on HTTPS alone with no DON-signature verification.** Treat the current oracle keypair as compromised and rotate it before anything else.

---

## Findings (verified, by severity)

| # | Sev | Title | Location |
|---|-----|-------|----------|
| C1 | **CRITICAL** | Oracle signing key + Chainlink client secret in **public** git history, key still in HEAD | `crypto_test.go:10`, history `ee59899:run_all_tests.sh:10`, `README.md:124` |
| C2 | **CRITICAL** | Production workflow consumes price-adjustment control with **no signature/author check** (regression vs dev) | `hmac/relay.go:425-484`, `hmac/handlers.go` |
| C3 | **CRITICAL** | Live `DUCAT_PRIVATE_KEY` stored cleartext in `.claude/settings.local.json` (mode 0644) | `.claude/settings.local.json` |
| H1 | HIGH | Chainlink Data Streams DON signatures never verified — price read from body, HTTPS-only trust | `hmac/price.go:170-215,269-334`; `hmac-dev/price.go` |
| H2 | ~~HIGH~~ → **LOW** | Relay writes carry no auth header — but live testing confirmed the relay enforces a pubkey write-allowlist (`blocked: pubkey not in whitelist`), so not exploitable. No code change. | `hmac/relay.go:43-50,380-387` |
| H3 | HIGH | Price staleness checked against unauthenticated server-time, not the signed report stamp; stale → warning only | `hmac/price.go:93-130,217-247` |
| H4 | HIGH | Dev workflow (with price-adjustment HTTP controls) wired to a **mainnet** environment | `project.yaml`, `hmac-dev/config.alpha-mainnet-unified.json` |
| H5 | HIGH | Price-adjustment magnitude/duration unbounded — published price can be pinned arbitrarily far from Chainlink | `hmac-dev/handlers.go` (`applyActiveAdjustment`, bounds) |
_M-series re-verified against current code (post H1/C2/H3/H5). Dispositions:_

| M1 | ~~MED~~ → **FALSE-POSITIVE** | No response decompression exists in code (only outbound request gzip); body is a materialized []byte capped by the CRE 200KB platform limit, from the write-allowlisted relay. No fix. | `hmac/relay.go` |
| M2 | ~~MED~~ → **FIXED (LOW)** | `.env` was 0644; `chmod 600` applied. Gitignored, so local-only hygiene. | `.env` |
| M3 | MED → **OPS** | One EVM key (`8b9e…D837`) is both workflow owner and HTTP-trigger authorizer across prod-testnet/testnet4/alpha-mainnet. No code fix — segregate keys per env/role and rotate (folds into the C1 rotation). | `project.yaml` |
| M4 | ~~MED~~ → **FIXED (LOW)** | `ValidateCallbackURL` added (https-only; blocks localhost/metadata/private-IP + trailing-dot & alt-numeric-IP SSRF bypasses) and wired into request + Config validation. Auth-gated, so low. | `shared/validation.go`, `shared/types.go` |
| M5 | ~~MED~~ → **MOOT** | Every reachable `float64→uint32` price cast is bounds-checked `<1e6` upstream (validatePriceForEncoding); relay-data casts are gated by the key-bound commitment check. No overflow reachable. | `hmac/handlers.go` |
| M6 | ~~MED~~ → **FALSE-POSITIVE** | Both `int64(f)` and `uint32(f)` truncate toward zero on the same float; verified `uint32(f)==uint32(int64(f))` over the entire valid range (0 mismatches). No divergence. | `hmac/handlers.go` |
| M7 | MED → **FIXED (LOW)** | Quote/ladder reads now pin `authors:[oraclePubkey]` + re-check `event.PubKey` + verifyNostrEvent, fail-closed, both trees. (Relay write-allowlist already blocked squatting; this is defense-in-depth.) | `hmac/relay.go`, `hmac-dev/relay.go` |
| M8 | ~~MED~~ → **FALSE-POSITIVE** | `chain_network` is operator-set config, not attacker-controlled, and the commitment is key-bound — no exploitable preimage collision. Changing it would be consensus-breaking. | `crypto/crypto.go` |
| M9 | MED → **FIXED** | Prod `applyActiveAdjustment` had no pct bound (H5 only landed in dev) and `evaluateQuotes` fed the adjusted price into the breach decision unvalidated. Ported the H5 apply-time pct bound to prod + added `validatePriceForEncoding` after adjustment in both trees. | `hmac/handlers.go` |
| L1–L10 | LOW | Sscanf-from-error-string time parse w/o success check; raw error strings reflected to callers; `client_id` in tracked configs; no `DisallowUnknownFields`; loose ladder/HTTP-budget bound; kind-10001 pre-publishes base price; HMAC reuses signing key as MAC secret; Hash160 (80-bit) for a money commitment; kind-10001 artifact leakage | `price.go`, `handlers.go`, `crypto/crypto.go`, configs |

---

## Critical & high detail

### C1 — Oracle key + client secret in public git history (and the key is still in HEAD)
`DUCAT_PRIVATE_KEY="<64-hex, 8c..0e>"` and `DUCAT_CLIENT_SECRET="<128-char base62, mN..rK, len 128>"` are exported as **real values** in the initial commit `ee59899` — in both `run_all_tests.sh:10` and `README.md:124`. The repo `DUCAT-UNIT/cre-hmac` is **PUBLIC** (`gh repo view` → `isPrivate:false`). The same private key `8c..0e` is **still present in HEAD** at `crypto/crypto_test.go:10` as `testPrivateKey`. I derived its x-only pubkey: **`6b5008a2...`**. Anyone who has ever cloned or scraped the repo has this private key; if `6b5008a2...` is the live oracle Nostr pubkey, they can sign arbitrary kind-10000/30000/30078 events as the oracle and reveal any ladder secret at will — total compromise of the commitment scheme. _One thing the repo cannot tell me: whether `6b5008a2...` is actually the production oracle identity. **Check the published oracle pubkey on `relay-mutinynet.staging.ducatprotocol.com` against `6b5008a2...`** — if it matches, this is a live key-theft incident, rotate immediately._ The client secret authenticates to the Chainlink Data Streams API and should be rotated regardless.
_Precondition: read access to a public GitHub repo. None._

### C2 — Production consumes price-adjustment events with no signature/author check
Prod `fetchAdjustmentControl` (`hmac/relay.go:425-484`) builds a NIP-01 filter `kinds:[30078], #d:[price_adjustment_control], limit:1` with **no `authors` filter**, then `json.Unmarshal`s `events[0].Content` into `PriceAdjustmentControl` with **no `event.PubKey` comparison and no `verifyNostrEvent` call**. The dev tree (`hmac-dev/relay.go:336-340`) *does* both checks — this is a security regression in the production path. Anyone who can write a self-signed kind-30078 event with that d-tag to the relay the prod oracle reads can set an arbitrary adjustment percentage and move the published BTC/USD price, which drives liquidations.
_Precondition: write access to the prod/staging strfry relay — satisfied by the open-write Nostr default unless the relay enforces NIP-42/an allowlist (see H2)._

### C3 — Live signing key cleartext in `.claude/settings.local.json` (0644)
Two allowlisted Bash permission entries embed `DUCAT_PRIVATE_KEY=<64-hex, bd..a2>` and `CRE_WEBHOOK_PUBKEY=<64-hex, a1..1e>` in cleartext. The file is mode 0644 (world/group-readable) on local disk. It is **gitignored** (not in the repo), so blast radius is local-machine / backup / any process that can read the home dir — but it is a live key in plaintext at rest. Note this key (`bd..a2`) is **different** from the git-history key (`8c..0e`), so there may be two distinct keys in play; reconcile which is the current production signer.

### H1 — Chainlink DON signatures never verified
`fetchPriceOnce` → `decodePrice` (`hmac/price.go:170-215,269-334`; identical in `hmac-dev`) hex-decodes `report.Report.FullReport` and reads the price field **without verifying the report's DON signatures**. The price is trusted purely because it arrived over HTTPS from the configured Data Engine URL. Anyone who can forge that HTTPS response as seen by the DON nodes (TLS-MITM at a node, a malicious/compromised data-engine endpoint, or config substitution of `data_stream_url`) controls the oracle price with no cryptographic backstop.

### H2 — Relay writes unauthenticated; TLS default — **DOWNGRADED to LOW after live investigation**
`publishEvent`/`publishEventsBatch`/`publishAdjustmentControl` (`hmac/relay.go:43-50,380-387,524`) POST with only `Content-Type`, no auth/signature header. The audit flagged this HIGH *conditionally* — "effectively critical IF the relay accepts arbitrary-pubkey writes."

**Live investigation (2026-06-10) disproved that condition.** A validly-signed event from a throwaway (non-oracle) key was rejected with `HTTP 400 "blocked: pubkey not in whitelist"` on ALL THREE relays — `relay.staging`, `dev-relay`, AND `relay.alpha` (mainnet-adjacent) — and was not stored. (An earlier malformed-event probe returned `invalid: unexpected id size` because strfry validates event structure *before* the whitelist check, which made it look open.) TLS cert chains validated cleanly on all three.

Conclusion: **the relay enforces a pubkey write-allowlist**, so the C2 precondition does not hold and no attacker can inject events. The oracle's pubkey *is* its write credential (strfry checks the event signature against the whitelist) — there is no token to add and adding one would not increase security. No code change warranted; downgraded HIGH → LOW/informational.

**Ops note (rotation runbook):** the whitelist is load-bearing. When `DUCAT_PRIVATE_KEY` is rotated (per C1), the new oracle pubkey MUST be added to all three relays' whitelists or the oracle will get `blocked: pubkey not in whitelist` and silently fail to publish.

### H3 — Staleness measured against unauthenticated server time
Price age is computed against a server-time handshake value parsed from an error string, not the signed report timestamp, and a stale price only logs a warning rather than rejecting. Combined with H1, an attacker replaying an old signed report faces no staleness gate.

### H4/H5 — Dev adjustment controls reachable on mainnet, unbounded
A config named `config.alpha-mainnet-unified.json` lives in the **dev** tree, which carries the HTTP price-adjustment controls, and `project.yaml` defines an `alpha-mainnet` deploy target. The adjustment magnitude/duration are not tightly bounded, so an authorized caller (or, via C2/H2, an unauthorized one) can pin the published price arbitrarily far from the real Chainlink price on a mainnet deployment. The dev manual-override mechanism should not exist on any mainnet build.

---

## Remediation plan

### P0 — do now (incident response)
1. **Rotate the oracle keypair and the Chainlink client secret.** (C1, C3) Generate a new signing key in the CRE vault, update the relay's accepted oracle pubkey, rotate `DUCAT_CLIENT_SECRET` with Chainlink. Treat `8c..0e` and `bd..a2` and `mN..rK` as burned. **First, confirm whether `6b5008a2...` is the live oracle pubkey on `relay-mutinynet.staging.ducatprotocol.com`** — that determines whether this is an active breach. **Effort: M.**
2. **Restore signature + author verification in the prod adjustment path.** (C2) In `hmac/relay.go:425-484`, port the dev-tree guards: add `authors:[oraclePubkey]` to the filter, compare `events[0].PubKey` to the pinned author, and call `verifyNostrEvent` before unmarshalling content. **Effort: S.**
3. **Purge keys from git history and HEAD.** (C1) Replace `crypto_test.go:10` with a clearly-throwaway test vector (generate a fresh random key with a `// test-only, not a real key` comment). Run `git filter-repo` (or BFG) to scrub `ee59899:run_all_tests.sh` and `README.md` history, force-push, and rotate anyway since history scrubbing on a public repo is best-effort. **Effort: M.**
4. **Remove the cleartext key from settings and `chmod 600` secret files.** (C3, M2) Delete the `DUCAT_PRIVATE_KEY=...`/`CRE_WEBHOOK_PUBKEY=...` permission entries from `.claude/settings.local.json`; load secrets from env/keychain at run time instead of baking them into allow-rules. `chmod 600 .env`. **Effort: S.**

### P1 — this week
5. **Verify Chainlink DON report signatures in `decodePrice`.** (H1) Parse and verify the report's signer set against the expected DON config before trusting the price; reject on failure. **Effort: L.**
6. **Reject stale reports using the signed report timestamp.** (H3) Gate on `report.timestamp` vs a max-age constant; return an error (not a warning) when exceeded. **Effort: S.**
7. **Lock down relay writes.** (H2) Enforce NIP-42 auth or a write allowlist on the strfry relay; if not feasible, add an app-layer write token. Confirm TLS cert validation is not disabled. **Effort: M** (relay-side).
8. **Remove dev adjustment controls from any mainnet build; bound them everywhere.** (H4, H5, M9) Compile the adjustment HTTP handlers out of mainnet configs; clamp adjustment pct/duration to a small documented range and re-validate bounds in `evaluateQuotes`. **Effort: M.**

### P2 — hardening
9. **Pin the oracle author on all reads.** (M7) Add `authors:[oraclePubkey]` to quote/ladder lookups so a third party can't squat lookup tags.
10. **Fix the price-encoding divergence and use the validated truncation helper.** (M5, M6) Route all `float64`→`uint32` price conversions through `TruncatePriceToUint32`; make stored and preimage encodings identical (`uint32`) so wallet lookups can't miss.
11. **Disambiguate the commit-hash preimage.** (M8) Length-prefix or fixed-pad the `network` field so the variable-length field can't create preimage collisions. _(Coordinate with `core-ts` — this is a consensus-breaking change to `commit_hash`.)_
12. **Bound relay response decoding.** (M1) Cap body size and reject oversized/over-ratio decompression before `json.Unmarshal`.
13. **Validate `callback_url`** against an allowlist/scheme check (M4); add `DisallowUnknownFields` and stop reflecting raw internal errors to callers (L-series).

---

## Already done well
- **Commitment scheme is sound** — ladder secrets are HMAC-committed (`HMAC(seckey, commit_hash)`) and only the breached threshold's secret is revealed; one revealed secret cannot derive others. No premature exposure.
- **Key hygiene in `crypto/`** — private keys validated to `(0, n)` against the curve order; `subtle.ConstantTimeCompare` for commitment checks; secrets zeroed via `defer`.
- **Schnorr/Nostr signing** correctly delegates to `btcec/schnorr` (BIP-340) rather than hand-rolling; event-ID comparison is constant-time.
- **Dev tree got the adjustment authz right** — it verifies author + signature; the bug is that production *regressed* from it (so the fix is a known-good port, not new design).
- **Atomic in-process promotion + NIP-33 replacement** make failed cycles self-healing.

---

### Appendix — checked and refuted / disputed
- _Refuted:_ "`crypto_test.go` key is a throwaway test vector" — it is labeled as a test vector but is the **same key leaked in history**, so it is a real leak, not a harmless vector (folded into C1).
- _Refuted:_ "no real secret in `run_all_tests.sh` history" — a redaction-regex artifact in an early pass; the value **is** present (corrected, C1).
- _Disputed (split verifier verdicts):_ exact blast radius of M3 (key reuse across roles) and whether M8 preimage ambiguity is practically exploitable vs. defense-in-depth; treated as medium/hardening pending `core-ts` review.
- _Confirmed clean:_ `secrets.yaml` holds only secret **names** (CRE vault refs), not values; no raw EVM private keys in `project.yaml` history (public addresses only); dependencies reviewed clean at audit cutoff.
