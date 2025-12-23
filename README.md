# DUCAT - Threshold Commitment Oracle (CRE)

Privacy-preserving price threshold commitments for Bitcoin hashlocks using Chainlink CRE and Nostr.

## What It Does

Creates Hash160 commitments to price thresholds that reveal their secret only when breached.

**Example**: "If BTC drops below $94k, reveal secret X" - the threshold stays hidden until the price crosses it.

## Architecture

```
┌──────────────┐       ┌──────────────┐
│  CRE (WASM)  │──────▶│ Nostr Relay  │
└──────────────┘       └──────────────┘
       │
  Chainlink DON
 (price consensus)
```

This repo contains the **CRE WASM workflow** that runs on Chainlink's Decentralized Oracle Network.

## Operations

### 1. Create Quote (HTTP Trigger)
Creates a new threshold commitment at a specific price.

```
HTTP Trigger → CRE → Nostr
{thold_price: 94000, domain: "..."}
```

### 2. Evaluate Quotes (HTTP Trigger)
Batch check quotes for breach, reveals secrets if price crossed.

```
HTTP Trigger → CRE → Nostr
{action: "evaluate", thold_hashes: [...]}
```

### 3. Generate Quotes (Cron Trigger)
Auto-generates quotes at collateral rate intervals (135% to 500%).

```
Cron (every 90s) → CRE → Nostr (366 quotes)
```

## Quote Generation Flow

The cron job generates quotes using a parallel-create, batch-publish pattern:

```
1. Fetch Price          Single consensus request to Chainlink DON
        ↓
2. Create Contracts     Parallel crypto operations (fast, local)
   (366 quotes)         - HMAC-SHA256 for threshold secrets
                        - Hash160 for commitments
                        - Schnorr signatures for each contract
        ↓
3. Sign Nostr Events    Local signing of all 366 events
        ↓
4. Batch Publish        Single HTTP POST to /api/quotes/batch
   (with retry)         - Atomic: all succeed or none
                        - Retries up to 3 times on failure
```

**Why batch publish?**
- Atomic guarantee: all quotes for a price point publish together or not at all
- Reduced network overhead: 1 request vs 366 individual requests
- Relay can optimize storage for batch inserts
- Retry logic ensures reliability without partial state

## Relay API

The Nostr relay must implement these endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/quotes` | POST | Publish single event |
| `/api/quotes/batch` | POST | Publish array of events (atomic) |
| `/api/quotes?d={hash}` | GET | Fetch event by d-tag (commit_hash) |
| `/api/quotes/{id}` | GET | Fetch event by ID |

### Batch Request Format

```json
POST /api/quotes/batch
Content-Type: application/json

[
  {"id": "...", "pubkey": "...", "created_at": 1234, "kind": 30078, "tags": [["d", "..."]], "content": "...", "sig": "..."},
  {"id": "...", "pubkey": "...", "created_at": 1234, "kind": 30078, "tags": [["d", "..."]], "content": "...", "sig": "..."},
  ...
]
```

Response: `200 OK` or `201 Created` on success.

## Quick Start

### 1. Prerequisites

- **Go 1.24+**
- **CRE CLI** (Chainlink Runtime Environment)
- **Nostr relay** with batch endpoint support

### 2. Setup

```bash
git clone https://github.com/DUCAT-UNIT/cre-hmac
cd cre-hmac
go mod download
```

### 3. Configure Secrets

```bash
# Secp256k1 private key (32 bytes hex)
export DUCAT_PRIVATE_KEY="your_64_char_hex_key"

# HMAC secret (min 32 bytes)
export DUCAT_CLIENT_SECRET="your_secret_here"
```

### 4. Derive Public Key

```bash
cd tools && go run derive_key.go
```

Add the output public key to your Nostr relay whitelist.

### 5. Run Tests

```bash
go test ./... -v
```

### 6. Build WASM

```bash
cd hmac

# Development build
GOOS=wasip1 GOARCH=wasm go build -o main.wasm

# Production build with version info
GOOS=wasip1 GOARCH=wasm go build -ldflags "\
  -X main.Version=v1.0.0 \
  -X main.GitCommit=$(git rev-parse --short HEAD) \
  -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o main.wasm
```

## Project Structure

```
cre-hmac/
├── hmac/                    # CRE WASM workflow
│   ├── main.go              # Entry point, HTTP/Cron triggers
│   ├── handlers.go          # createQuote, evaluateQuotes, generateQuotesParallel
│   ├── crypto.go            # Crypto delegation
│   ├── types.go             # Data structures
│   ├── constants.go         # Constants
│   ├── price.go             # Chainlink price fetching
│   ├── relay.go             # Nostr relay operations (single + batch)
│   ├── config.json          # CRE configuration
│   └── workflow.yaml        # CRE workflow definition
│
├── crypto/                  # Testable crypto library
│   ├── crypto.go            # BIP-340 Schnorr, Hash160, HMAC-SHA256
│   └── crypto_test.go
│
├── shared/                  # Shared validation and types
│   ├── types.go             # Request/response types
│   ├── constants.go         # Field length constants
│   ├── validation.go        # Input validation
│   └── *_test.go
│
├── wasmtest/                # WASM handler tests
│   ├── handlers_test.go
│   ├── mock_runtime.go      # CRE runtime mock
│   └── nostr.go
│
├── integration/             # Integration tests
│   └── integration_test.go
│
├── tools/
│   └── derive_key.go        # Public key derivation utility
│
└── README.md
```

## CRE Configuration

### Config (hmac/config.json)

```json
{
  "client_id": "your-client-id",
  "data_stream_url": "https://api.testnet-dataengine.chain.link",
  "feed_id": "0x00037da06502da...",
  "relay_url": "http://localhost:8080",
  "network": "mutinynet",
  "authorized_key": "0x...",
  "cron_schedule": "0 */90 * * * *",
  "rate_min": 1.35,
  "rate_max": 5.00,
  "step_size": 0.01
}
```

| Field | Description |
|-------|-------------|
| `data_stream_url` | Chainlink Data Streams API |
| `feed_id` | BTC/USD price feed ID |
| `relay_url` | Nostr relay for event storage |
| `network` | Bitcoin network (mutinynet, signet, etc.) |
| `authorized_key` | Ethereum address for HTTP trigger auth |
| `cron_schedule` | Cron expression for batch generation |
| `rate_min/max` | Collateral rate range (1.35 = 135%) |
| `step_size` | Step between rates (0.01 = 1%) |

### Secrets (secrets.yaml)

```yaml
secretsNames:
  private_key:
    - DUCAT_PRIVATE_KEY
  client_secret:
    - DUCAT_CLIENT_SECRET
```

## Response Format

All quote operations return `PriceContractResponse`:

```json
{
  "chain_network": "mutinynet",
  "oracle_pubkey": "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621",
  "base_price": 105000,
  "base_stamp": 1734567890,
  "commit_hash": "a1b2c3d4...",
  "contract_id": "e5f6g7h8...",
  "oracle_sig": "deadbeef...",
  "thold_hash": "240c124e4a188281668b4899b6456c101c568de8",
  "thold_key": null,
  "thold_price": 141750
}
```

When breached, `thold_key` contains the revealed secret.

## Nostr Event Structure

Price contracts are stored as NIP-33 replaceable events (kind 30078).

| Tag | Description |
|-----|-------------|
| `d` | `commit_hash` - NIP-33 replaceable identifier |

## Security

### Cryptographic Primitives

- **HMAC-SHA256**: Deterministic secret generation from oracle key + commit hash
- **Hash160**: Bitcoin-compatible commitments (RIPEMD160(SHA256))
- **BIP-340 Schnorr**: Signs contracts and Nostr events
- **Input validation**: Domain, price, hash format checks
- **Retry logic**: Batch publish retries up to 3 times on failure

### Security Assumptions

This system assumes the following trust boundaries:

| Component | Trust Level | Assumption |
|-----------|-------------|------------|
| **Chainlink DON** | Trusted | Byzantine fault tolerant consensus provides accurate BTC/USD prices |
| **CRE Runtime** | Trusted | WASM execution environment is secure and isolated |
| **Oracle Private Key** | Secret | Only accessible via CRE secrets management, never logged |
| **Nostr Relay** | Semi-trusted | Stores events but cannot forge signatures; availability not guaranteed |

### Threat Model

**What we protect against:**
- Price manipulation: DON consensus requires majority agreement
- Commitment forgery: Schnorr signatures bind oracle identity to each contract
- Threshold guessing: Hash160 preimage resistance (~80 bits security)
- Secret prediction: HMAC-SHA256 with domain separation prevents secret derivation
- Replay attacks: Timestamps and network identifiers in commit hash

**What we do NOT protect against:**
- DON collusion: If >2/3 of DON nodes collude, prices can be manipulated
- Oracle key compromise: Attacker with private key can create valid signatures
- Relay unavailability: System fails if relay is down (no local storage)
- Front-running: Observable threshold prices could inform trading strategies

### Error Handling

Error messages returned to clients are sanitized to prevent information leakage:
- Internal prices, timestamps, and hashes are logged but not returned
- Clients receive error codes (e.g., `PRICE_FETCH_FAILED`) without internal details

## Benchmarks

Run benchmarks to verify performance:

```bash
go test -bench=. -benchmem ./crypto
```

Example results (Apple M1 Max):

| Benchmark | ops/sec | time/op | allocs/op |
|-----------|---------|---------|-----------|
| DeriveKeys | ~27k | 37μs | 8 |
| Hash160 | ~2.8M | 354ns | 3 |
| SignSchnorr | ~3.6k | 274μs | 32 |
| CreatePriceContract | ~3.6k | 275μs | 59 |
| VerifyPriceContract | ~5.7k | 176μs | 24 |
| BatchContractCreation (366) | 10 | 102ms | 21,594 |

## Testing

```bash
# Run all tests
go test ./... -v

# Individual packages
go test ./crypto -v
go test ./shared -v
go test ./wasmtest -v
go test ./integration -v
```
