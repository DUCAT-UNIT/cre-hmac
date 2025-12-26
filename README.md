# DUCAT - Threshold Commitment Oracle

Privacy-preserving price threshold commitments for Bitcoin hashlocks using Chainlink CRE and Nostr.

## What It Does

Creates Hash160 commitments to price thresholds that reveal their secret only when breached.

**Example**: "If BTC drops below $94k, reveal secret X" - the threshold stays hidden until the price crosses it.

## System Integration

The CRE is a **reactive WASM module** - it responds to HTTP triggers from the Gateway/Regulator.

### Endpoints (HTTP Triggers)

| Trigger | Input | Action | Frequency |
|---------|-------|--------|-----------|
| **CREATE** | `{domain, thold_price}` | Create new threshold commitment | On-demand |
| **CHECK** | `{domain, thold_hash}` | Check if price breached threshold | Every 90s (liquidation poll) |
| **Cron** | (scheduled) | Generate batch quotes at all collateral levels | Every 1.5min |

### Type Schema (v2.5 - matches client-sdk)

All prices are `float64` because HMAC computation uses `%.8f` formatting. Timestamps are `int64`.

```go
type PriceEvent struct {
    QuotePrice float64  `json:"quote_price"`   // BTC/USD at quote creation
    QuoteStamp int64    `json:"quote_stamp"`   // Unix timestamp
    OraclePK   string   `json:"oracle_pk"`     // Oracle public key
    ReqID      string   `json:"req_id"`        // Request ID hash
    ReqSig     string   `json:"req_sig"`       // Schnorr signature
    TholdHash  string   `json:"thold_hash"`    // Hash160 commitment
    TholdPrice float64  `json:"thold_price"`   // Threshold price
    IsExpired  bool     `json:"is_expired"`    // True if breached
    EvalPrice  *float64 `json:"eval_price"`    // Price at breach (null if active)
    EvalStamp  *int64   `json:"eval_stamp"`    // Timestamp at breach (null if active)
    TholdKey   *string  `json:"thold_key"`     // Secret (null until breached)
}
```

## Architecture

```
┌─────────────────┐       ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│   Client App    │──────▶│   Gateway    │──────▶│  CRE (WASM)  │──────▶│ Nostr Relay  │
└─────────────────┘       └──────────────┘       └──────────────┘       └──────────────┘
                                │                        │
                           SQLite cache            Chainlink DON
                          (base price)            (price consensus)
```

### Components

| Component | Description |
|-----------|-------------|
| **Gateway** | HTTP proxy, caches base price, routes to CRE |
| **CRE (WASM)** | Chainlink Compute Runtime - creates/evaluates quotes |
| **Nostr Relay** | Stores threshold commitment events (NIP-33) |
| **Chainlink DON** | Byzantine fault tolerant price consensus |

## Operations

### 1. Create Quote
Creates a new threshold commitment at a specific price.

```
Client → GET /api/quote?th=105000 → Gateway → CRE → Nostr
```

### 2. Evaluate Quotes
Batch check quotes for breach, reveals secrets if price crossed.

```
Client → POST /api/evaluate {thold_hashes: [...]} → Gateway → CRE → Nostr
```

### 3. Get Price
Get the current batch price (cached from CRE cron job).

```
Client → GET /api/price → Gateway (SQLite cache)
```

## Data Flow

### Batch Generation (CRE Cron - every 1.5 minutes)

```
CRE                                      Gateway
 │                                          │
 ├─ fetchPrice() → $105,000                 │
 ├─ generateQuotesParallel()                │
 │   (366 quotes at 1% collateral steps)    │
 ├─ publish all to Nostr                    │
 │                                          │
 ├─ POST /webhook/ducat ───────────────────►│
 │   {                                      │
 │     event_type: "batch_generated",       │
 │     data: {                              │
 │       base_price: 105000,                │
 │       base_stamp: 1734567890             │
 │     }                                    │
 │   }                                      │
 │                                          ├─ cache in memory + SQLite
```

### Client Gets Price & Creates Quote

```
Client                                   Gateway                         CRE
 │                                          │                              │
 ├─ GET /api/price ────────────────────────►│                              │
 │◄─ {base_price: 105000, ...} ─────────────┤                              │
 │                                          │                              │
 │  (calculates collateral %)               │                              │
 │                                          │                              │
 ├─ GET /api/quote?th=141750 ──────────────►│                              │
 │                                          ├─ triggerWorkflow() ─────────►│
 │                                          │◄─ PriceContractResponse ─────┤
 │◄─ PriceContractResponse ─────────────────┤                              │
```

## Quick Start

### 1. Prerequisites

- **Go 1.24+**
- **Docker** (for Nostr relay)
- **CRE CLI** (Chainlink Runtime Environment)

### 2. Setup

```bash
git clone https://github.com/DUCAT-UNIT/cre-hmac
cd cre-hmac
go mod download
```

### 3. Start Nostr Relay

```bash
git clone https://github.com/DUCAT-UNIT/strfry-http
cd ../strfry-http
docker-compose up -d
```

### 4. Configure Secrets

```bash
# Secp256k1 private key (32 bytes hex)
export DUCAT_PRIVATE_KEY="8ce73a2db5cbaf4b0ab3cabece9408e3b898c64474c0dbe27826c65d1180370e"

# HMAC secret (min 32 bytes)
export DUCAT_CLIENT_SECRET="your_secret_here"
```

### 5. Derive Public Key

```bash
cd tools && go run derive_key.go
```

Add the output public key to strfry whitelist.

### 6. Run Tests

```bash
./run_all_tests.sh
```

### 7. Build Gateway

```bash
cd tools
go build -o gateway-server gateway_server.go
```

### 8. Build WASM

```bash
cd hmac
GOOS=wasip1 GOARCH=wasm go build -o main.wasm
```

## Project Structure

```
cre-hmac/
├── hmac/                    # CRE WASM workflow
│   ├── main.go              # Entry point, routing
│   ├── handlers.go          # createQuote, evaluateQuotes, generateQuotesParallel
│   ├── crypto.go            # Crypto delegation
│   ├── types.go             # Data structures
│   ├── constants.go         # Constants
│   └── workflow.yaml        # CRE workflow definition
│
├── crypto/                  # Testable crypto library
│   ├── crypto.go            # Pure crypto functions
│   └── crypto_test.go       # Unit tests
│
├── internal/
│   └── ethsign/             # Ethereum signing utilities
│       ├── ethsign.go       # JWT generation, Ethereum message signing
│       └── ethsign_test.go  # Signing and recovery tests
│
├── shared/                  # Shared validation and types
│   ├── types.go             # NostrEvent, etc.
│   └── validation.go        # Input validation helpers
│
├── tools/                   # Gateway and utilities
│   ├── gateway_server.go    # HTTP gateway with SQLite cache
│   └── derive_key.go        # Key derivation tool
│
├── wasmtest/                # WASM handler tests
│   └── handlers_test.go     # 461 tests
│
├── integration/             # Integration tests
│   └── integration_test.go
│
├── GATEWAY_API.md           # Gateway API documentation
├── DOCKER.md                # Docker deployment guide
└── README.md                # This file
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
  "cron_schedule": "0 */90 * * * *",
  "rate_min": 1.35,
  "rate_max": 5.00,
  "step_size": 0.01,
  "gateway_callback_url": "http://gateway:8080/webhook/ducat"
}
```

| Field | Description |
|-------|-------------|
| `cron_schedule` | Cron expression for batch generation (every 1.5 min) |
| `rate_min` | Minimum collateral rate (1.35 = 135%) |
| `rate_max` | Maximum collateral rate (5.00 = 500%) |
| `step_size` | Step between rates (0.01 = 1%) |
| `gateway_callback_url` | URL for CRE to notify gateway of new batches |

### Secrets (secrets.yaml)

```yaml
secretsNames:
  private_key:
    - DUCAT_PRIVATE_KEY
  client_secret:
    - DUCAT_CLIENT_SECRET
```

## Gateway API

See [GATEWAY_API.md](GATEWAY_API.md) for full documentation.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/price` | GET | Get cached base price |
| `/api/quote` | GET | Create threshold quote |
| `/api/evaluate` | POST | Batch evaluate quotes |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |

## Response Format

All quote operations return `PriceContractResponse` (matches core-ts `PriceContract` schema):

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

### Event Tags

| Tag | Description |
|-----|-------------|
| `d` | `commit_hash` - NIP-33 replaceable event identifier |

### Querying Events

```bash
# Query by commit_hash (d tag)
GET /api/query?#d=<commit_hash>
```

### Event Content

The event content is the `PriceContract` JSON (no extra fields):

```json
{
  "chain_network": "mutinynet",
  "oracle_pubkey": "6b5008...",
  "base_price": 105000,
  "base_stamp": 1734567890,
  "commit_hash": "a1b2c3d4...",
  "contract_id": "e5f6g7h8...",
  "oracle_sig": "deadbeef...",
  "thold_hash": "240c124e...",
  "thold_key": null,
  "thold_price": 141750
}
```

## Performance

- **Quote generation**: 366 quotes in ~600ms (parallel)
- **Per contract**: ~840μs crypto operations
- **Contracts/second**: ~1,200 (local crypto)

CRE production estimates:
- Price fetch: ~100ms
- Parallel relay publish: ~500ms
- Total batch: ~600ms

## Security

- **HMAC-SHA256**: Deterministic, domain-separated secret generation
- **Hash160**: Bitcoin-compatible commitments (RIPEMD160(SHA256))
- **Schnorr signatures**: BIP-340 for Nostr events
- **DON consensus**: Byzantine fault tolerance for price data
- **Input validation**: Domain, price, hash format checks

## Docker Deployment

See [DOCKER.md](DOCKER.md) for deployment guide.

```bash
# Build
docker build -t ducat-gateway:latest .

# Run with SQLite persistence
docker run -d \
  -p 8080:8080 \
  -v ducat-data:/data \
  -e GATEWAY_DB_PATH=/data/gateway.db \
  --env-file .env \
  ducat-gateway:latest
```

## Testing

```bash
# Run all tests
./run_all_tests.sh

# Or individually
go test ./crypto -v
go test ./shared -v
go test ./wasmtest -v
go test ./integration -v

# Build gateway
cd tools && go build -o gateway-server gateway_server.go
```
