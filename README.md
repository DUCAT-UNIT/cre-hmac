# DUCAT Oracle (cre-hmac)

Privacy-preserving BTC/USD price-threshold commitments published to Nostr,
powered by Chainlink CRE workflows running as WASM.

The oracle publishes a *ladder* of pre-committed liquidation thresholds every
minute. Wallets read the current snapshot from the relay, derive a
`commit_hash`, and look up the matching ladder event — the secret behind each
event becomes revealable only when the threshold is breached.

---

## TL;DR

Two workflow trees:

| Dir | Purpose | Network |
|---|---|---|
| `hmac/` | Legacy workflow (single binary, single cron) | deprecated |
| `hmac-dev/` | Unified workflow (single binary, single cron, plus HTTP adjustment controls) | mutinynet / testnet4 / alpha |

This README documents the **dev tree**. `hmac/` is the simpler ancestor.

---

## The unified cycle

CRE recently raised the per-execution HTTP-call cap from 10 to **20**, which
lets the full publish → ladder → promote cycle run in a single workflow
execution. Previously the dev tree was split into three workflows (publisher,
ladder worker, promoter) coordinated through Nostr completion markers; that
split is gone.

```
                ┌─────────────────────────────────────────────────┐
                │        <network> workflow (one cron)            │
                │             cron: 0 * * * * *                   │
                │                                                 │
                │   1. fetch BTC/USD from Chainlink Data Streams  │
                │   2. apply price adjustment (if active)         │
                │   3. publish kind-10001 (pending snapshot)      │
                │   4. publish kind-30000 ladder (7 chunks)       │
                │   5. publish kind-10000 (current snapshot)      │
                └──────────────────────┬──────────────────────────┘
                                       │
                                       ▼
                ┌─────────────────────────────────────────────────┐
                │              Nostr relay (strfry)               │
                └──────────────────────┬──────────────────────────┘
                                       │
                                       ▼
                ┌─────────────────────────────────────────────────┐
                │   wallets read kind-10000 + kind-30000 lookups  │
                └─────────────────────────────────────────────────┘
```

Because steps 4 and 5 happen in the same execution, step 5 runs only if step 4
fully succeeded — no completion-marker scheme is needed. A failure anywhere
returns an error and the next cron tick re-runs the whole cycle. NIP-33
replacement makes everything idempotent.

---

## HTTP-call accounting

CRE caps each execution at 20 outbound HTTP calls. The unified happy path
uses 11:

| Step | Calls | Notes |
|---|---|---|
| 1. Chainlink price fetch | 1 | up to `unifiedPriceMaxAttempts` retries |
| 2. adjustment-control read | 1 | best-effort, ignored on error |
| 3. kind-10001 publish | 1 | up to `unifiedSnapshotPubMaxAttempts` retries |
| 4. ladder chunks | 7 | 865 events / 130 per chunk |
| 5. kind-10000 publish | 1 | up to `unifiedCurrentPubMaxAttempts` retries |
| **Total happy path** | **11** | leaves 9 calls of retry headroom |

The ladder loop budgets per chunk so every chunk gets at least one attempt
even if early chunks burn retries.

---

## Cycle timing

| Workflow | Cron | Fires at | What it does |
|---|---|---|---|
| `mutinynet` / `testnet4` / `alpha` | `0 * * * * *` | every minute @ :00 | publishes everything for that network's cycle |

CRE workflows take ~10s of warm-up before user code runs. End-to-end a wallet
sees a fresh kind-10000 within ~30s of the top of the minute (vs ~45s under
the old 3-workflow split).

---

## Nostr event kinds

| Kind | Replaceable? | Read by | Written by | Purpose |
|---|---|---|---|---|
| `30000` | yes (parameterized by `#d`) | wallets, oracle-portal | unified cycle | One event per `commit_hash` — the threshold commitment + revealable secret |
| `10001` | yes (NIP-33) | (none in steady state) | unified cycle | Intermediate snapshot published before the ladder. Kept as an artifact for debugging cycles that failed before step 5. |
| `10000` | yes (NIP-33) | wallets, oracle-portal | unified cycle | The snapshot wallets must always read |

A kind-10000 always has its matching kind-30000 ladder on the relay, because
the unified cycle only publishes kind-10000 after every chunk of the ladder
succeeded.

---

## The commit_hash flow (wallet-side)

```
wallet                                              oracle
  │                                                    │
  │   read kind-10000 (current snapshot)               │
  │ ────────────────────────────────────────────────►  │
  │                                                    │
  │   {base_price, base_stamp, network, pubkey}        │
  │ ◄────────────────────────────────────────────────  │
  │                                                    │
  │   compute target rate                              │
  │   thold_price = ⌈base_price × 1.35 / rate⌉         │
  │   (rate rounded to 2 decimals)                     │
  │                                                    │
  │   commit_hash = BIP-340 tagged-hash                │
  │     "ducat/price_contract_commit"                  │
  │     of (pubkey ‖ network ‖ base_price              │
  │         ‖ base_stamp ‖ thold_price)                │
  │                                                    │
  │   read kind-30000 #d=<commit_hash>                 │
  │ ────────────────────────────────────────────────►  │
  │                                                    │
  │   {threshold event with revealable secret}         │
  │ ◄────────────────────────────────────────────────  │
```

Spec (matches `core-ts/src/lib/price/util.ts`):

```ts
const TAG     = 'ducat/price_contract_commit'
const tagHash = sha256(utf8(TAG))
const preimage = concat(
  hexToBytes(oraclePubkey),     // 32 bytes
  utf8(chainNetwork),           // variable
  uint32BE(basePrice),          // 4 bytes
  uint32BE(baseStamp),          // 4 bytes
  uint32BE(tholdPrice),         // 4 bytes
)
const commit_hash = sha256(concat(tagHash, tagHash, preimage)).hex
```

Both wallet and oracle compute this identically. Mismatch = wallet sees no
matching event and is stuck.

---

## Reliability features

### In-process atomic promotion

kind-10000 is published in the same execution as the ladder. If any ladder
chunk fails, kind-10000 is not published — wallets keep reading the previous
cycle's kind-10000, and the next cron tick re-runs everything.

### Float-precision normalization

Each rate is normalized to 2 decimals (`math.Round(rate * 100) / 100`) before
computing `thold_price` and `commit_hash`. Otherwise float accumulation
drifts (e.g. 3.95 → 3.949999999999959), and the wallet's clean 3.95 lookup
misses.

### NIP-33 replacement

Everything published by this workflow is replaceable. A failed mid-cycle
publish is automatically corrected by the next successful cycle — no manual
recovery needed.

---

## Repo layout

```
cre-hmac/
├── README.md                  this file
├── crypto/                    pure-Go crypto lib (HMAC-SHA256, Hash160,
│                              BIP-340 tagged hashes). Testable, non-WASM.
├── datastream/                Chainlink Data Streams report decode +
│                              DON-signature verification (pure Go, testable)
├── shared/                    types and validation shared across workflows
├── wasmtest/                  handler tests with a mock CRE runtime
├── integration/               integration tests against a live relay
├── cre-tester/                diagnostic workflow: fetch a real report and log
│                              the decoded price + recovered DON signer addresses
├── hmac/                      legacy production workflow (being deprecated)
│   ├── handlers.go            createQuote / evaluateQuotes / generateQuotes
│   ├── config.json            workflow config
│   ├── workflow.yaml          cre-cli deploy descriptor
│   └── ...
├── hmac-dev/                  dev workflow (unified) — the successor
│   ├── handlers.go            HTTP trigger handlers + runUnifiedCycle
│   ├── relay.go               strfry-http client (/api/quotes, /api/query)
│   ├── crypto.go              wasm-side wrappers around crypto/
│   ├── price.go               Chainlink Data Streams adapter
│   ├── types.go               kinds, DTOs
│   ├── config.*.json          one config per environment
│   └── workflow.yaml          deploy descriptor
├── secrets.yaml
├── project.yaml
└── go.mod / go.sum
```

---

## Quick start

```bash
# build the WASM binary
cd hmac-dev && GOOS=wasip1 GOARCH=wasm go build -o main.wasm

# run unit tests against the mock runtime
cd ../wasmtest && go test ./...

# integration tests against a real relay
cd ../integration && go test ./...
```

### Deploy

From the repo root:

```bash
cre workflow deploy ./hmac-dev -T mutiny
```

`cre workflow deploy` upserts by name — same name = update, new name =
create. Workflow IDs are content-addressed (hash of binary + config), so a
config-only change still produces a new workflow ID.

---

## Deployments

Every network is a target in `project.yaml` (RPCs, DON family, owner) and a
matching block in each tree's `workflow.yaml` (workflow name, config). The two
workflow trees:

- `hmac/` — the original single-cron workflow (`config.json`). Deprecated.
- `hmac-dev/` — the unified workflow (publish → ladder → promote in one cron),
  with HTTP price-adjustment controls. One config per network.

**This is a testnet system.** All current targets — including the one named
`alpha-mainnet` — source price from the
**Chainlink testnet** Data Engine (`api.testnet-dataengine.chain.link`,
feed `0x0003de60…c8aa`, `BTC/USD-RefPrice-DF-Global-001-mercury` — the
predecessor feed `0x00039289…9722` was rotated out). The `-mainnet` names are
deployment targets, not
mainnet price feeds.

### CRE workflow naming convention

There is exactly **one CRE workflow per oracle network**. The workflow name is
the canonical network slug operators should recognize; it is not the relay
environment and not the implementation shape.

| Oracle network | CRE workflow name | Target key | Canonical relay |
|---|---|---|---|
| Mutinynet | `mutinynet` | `mutiny` | `https://relay-mutinynet.dev.ducatprotocol.com` |
| Testnet4 | `testnet4` | `testnet4` | `https://relay-testnet4.dev.ducatprotocol.com` |
| Alpha | `alpha` | `alpha-mainnet` | `https://relay-mainnet.alpha.ducatprotocol.com` |

General rule: use `<network-slug>`.

- Use lowercase names.
- Keep names stable and human-facing.
- Do not include environment prefixes like `dev-`, `staging-`, or `prod-`.
- Do not include implementation suffixes like `-unified`, `-worker`, or `-promoter`.
- Relays for different environments mirror from the canonical network relay over
  WebSocket; they do not get separate CRE workflows.

Examples of good future names: `signet`, `mainnet`, `regtest`, `testnet5`.

### Environment matrix (`hmac-dev/`, the unified workflow)

| Target | Workflow name | Config | Relay | Rate range / step | Cron |
|---|---|---|---|---|---|
| `local-simulation` | `mutinynet` | `config.dev-unified.json` | relay-mutinynet.dev | 1.36–10.00 / 0.01 | `0 * * * * *` |
| `mutiny` | `mutinynet` | `config.dev-unified.json` | relay-mutinynet.dev | 1.36–10.00 / 0.01 | `0 * * * * *` |
| `testnet4` | `testnet4` | `config.testnet4-unified.json` | relay-testnet4.dev | 1.36–10.00 / 0.01 | `0 * * * * *` |
| `alpha-mainnet` | `alpha` | `config.alpha-mainnet-unified.json` | relay-mainnet.alpha | 1.36–10.00 / 0.01 | `0 * * * * *` |

The legacy `hmac/` tree used workflow name `hmac` with `config.json`
(network `Mutinynet`, relay `relay-mutinynet.staging`, rate 1.36–5.00, cron
`0 */2 * * * *`). It should not be used for new deploys.

### Deployed workflow IDs

Workflow IDs are content-addressed hashes of (binary + config), assigned on the
on-chain Workflow Registry at deploy time. They change whenever the binary or
config changes. Record the current IDs here after each deploy (from the
`cre workflow deploy` output / the Workflow Registry):

| Target | Workflow name | Workflow ID |
|---|---|---|
| `mutiny` | `mutinynet` | `009b4f5f1344e906ca710e812e477d3aed66a6e9ddc8a108973602686953206d` |
| `testnet4` | `testnet4` | `00b670e8176a55700faa9c34c4462a09dd3618f61cd17183fd2b31a7cb2fe002` |
| `alpha-mainnet` | `alpha` | `00b4cc842300b9b15bc3a758d6d46e2ce3ce270af316d0ce7784fa45a308d744` |

Deploy a specific environment with:

```bash
cre workflow deploy ./hmac-dev -T <target>   # e.g. -T testnet4
```

### Chainlink Data Streams report verification (H1)

The price path verifies the DON signatures on each Data Streams report
(`datastream/`), gated per environment by config:

- `report_signers` — the feed's authorized DON signer addresses
- `report_signer_threshold` — the `f+1` quorum
- `require_report_verification` — must be `true` for every non-loopback Data
  Streams endpoint; an unverified report is rejected. `false` is accepted only
  for explicit loopback development.

The signer set is **per feed `configDigest`** and **rotates on-chain**, so it is
not in the report payload. To (re-)derive it for a feed — e.g. when cutting over
to a mainnet feed — read the Verifier's `ConfigSet` event:

```
VerifierProxy.getVerifier(configDigest) -> Verifier
# then the Verifier's ConfigSet(bytes32 indexed configDigest, address[] signers, uint8 f)
```

`cre-tester/` is a diagnostic workflow that fetches one real report and logs the
decoded price plus the recovered signer addresses, runnable via
`cre workflow simulate cre-tester -T local-simulation` — use it to discover/verify
the signer set for a feed before deploying that feed configuration.

---

## CRE constraints

| Limit | Value | Where it bites |
|---|---|---|
| HTTP calls / execution | 20 | unified cycle uses 11 happy-path, 9 retry slots remain |
| HTTP body | 200 KB | batch publishes are gzipped; full ladder still needs 7 chunks |
| Workflow name | `[a-zA-Z0-9_-]{1,64}` | use `_` instead of `.` |
| WASM stdlib | wasip1 only | no real network, no goroutines, no syscalls |
| Cron syntax | 6 fields (sec min h dom mon dow) | `0 * * * * *` works |

---

## Operating the system

### Where to look

| Question | Place to look |
|---|---|
| Did a workflow execution succeed? | Chainlink CRE dashboard → trigger logs |
| What's on the relay right now? | `https://relay-mutinynet.dev.ducatprotocol.com/api/query` |
| Is wallet drift OK? | `https://oracle-mutinynet.dev.ducatprotocol.com/` (30m / 6h / 24h toggle) |
| Did anything actually liquidate? | `https://validator.staging.ducatprotocol.com/liq/api/liquidated` |

### Common symptom → cause

- **Drift spike to ~60s** → one minute's cycle failed before step 5. Check the
  trigger log for the failed minute.
- **Wallet says "commit_hash not found"** → wallet computing rate with >2
  decimals, or wallet read kind-10000 just as it was being replaced. Retry
  next cycle.

### Adding/changing the rate range

If you change `rate_min`, `rate_max`, `step_size`, or `liquidation_thold`:

1. Update the relevant network config (`config.dev-unified.json`,
   `config.testnet4-unified.json`, or `config.alpha-mainnet-unified.json`).
2. Verify the ladder still fits in 7 chunks (`ceil((rate_max - rate_min) /
   step_size / 130) ≤ 7`) so it fits in the 20-call HTTP budget.
3. Deploy.

---

## Cryptography primitives

- **HMAC-SHA256** — deterministic secret derivation from `(client_secret, domain)`
- **Hash160** — `RIPEMD160(SHA256(secret))`, Bitcoin-compatible
- **BIP-340 Schnorr** — Nostr event signatures and tagged-hash commitments
- **DON consensus** — Byzantine-fault-tolerant aggregation across Chainlink Data Streams

All in pure Go in `crypto/` so they're testable outside WASM.

---

## License

MIT
