# DUCAT - Threshold Commitment Oracle

Privacy-preserving price threshold commitments for Bitcoin hashlocks using Chainlink CRE and Nostr.

## What It Does

Creates Hash160 commitments to price thresholds that reveal their secret only when breached.

**Example**: "If BTC drops below $94k, reveal secret X" - the threshold stays hidden until the price crosses it.

## Quick Start

### 1. Prerequisites

- **Go 1.24+**: Install from https://golang.org
- **Docker**: For running the Nostr relay
- **CRE CLI**: Chainlink Runtime Environment CLI
- **OpenSSL**: For cryptographic verification (usually pre-installed)

### 2. Clone & Setup

```bash
git clone https://github.com/DUCAT-UNIT/cre-hmac
cd cre-hmac

# Install dependencies
go mod download
```

### 3. Start Nostr Relay

DUCAT needs a Nostr relay to store threshold events. Start the included strfry relay:

```bash
git clone https://github.com/DUCAT-UNIT/strfry-http
cd ../strfry-http
docker-compose up -d

# Verify it's running
curl http://localhost:8080/health
# Expected: {"status":"ok","service":"strfry-http"}
```

The relay is now running on:
- **Port 8080**: HTTP API (used by DUCAT)
- **Port 7777**: WebSocket (standard Nostr)

### 4. Configure Cryptographic Secrets

#### Step 1: Set Your Private Key & HMAC Secret

```bash
# 32 bytes long secp256k1 private key, used to sign Nostr events
export DUCAT_PRIVATE_KEY="8ce73a2db5cbaf4b0ab3cabece9408e3b898c64474c0dbe27826c65d1180370e"
# min. 32 bytes long HMAC secret, used to generate price threshold commitments
export DUCAT_CLIENT_SECRET="mNbl97whllgPRsk6smy69J884DnS0LIhTY478bVQyFdl47sB3GMOAsHOnDg8B9JYilERQ07Eqd2CNU76NXSkb1J6SFT6MeaR5du6ow4zudWymixR00mv4va7f957qmrK"
```

**⚠️ IMPORTANT**: Use the above values for testing only. Generate a secure key for production.

**Private Key Requirements**:
- 64-character lowercase hex string (32 bytes)
- Valid secp256k1 private key
- Store securely (use Chainlink secrets management in production)

**HMAC Secret Requirements**:
- ???
- Store securely (use Chainlink secrets management in production)

#### Step 2: Derive Your Public Key

```bash
cd tools
go run derive_key.go
cd ..
```

**Expected Output**:
```
╔════════════════════════════════════════════════════════════════════╗
║               DUCAT PUBLIC KEY DERIVATION                          ║
╚════════════════════════════════════════════════════════════════════╝

Private Key:  8ce73a2db5cbaf4b0ab3cabece9408e3b898c64474c0dbe27826c65d1180370e
Public Key:   6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621
```

**Copy the public key** (you'll need it for Step 3).

#### Step 3: Whitelist Your Public Key in strfry

Edit `../strfry-http/strfry.conf` and add your public key:

```conf
relay {
    whitelistedPubkeys = "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621"

    whitelist {
        enabled = true
        pubkeys = "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621"
    }

    http {
        enabled = true
        port = 8080
        bind = "0.0.0.0"
        cors = true
    }
}
```

**Then restart strfry**:
```bash
cd ../strfry
docker-compose restart
cd ../
```

**Why?** strfry only accepts events signed by whitelisted public keys. Your DUCAT_PRIVATE_KEY signs events, and strfry verifies them using the derived public key.

### 5. Run Tests

```bash
# Make sure you're in the http-cre directory
cd ./cre-hmac
# Set secrets (if not already set)
export DUCAT_PRIVATE_KEY="8ce73a2db5cbaf4b0ab3cabece9408e3b898c64474c0dbe27826c65d1180370e"
export DUCAT_CLIENT_SECRET="mNbl97whllgPRsk6smy69J884DnS0LIhTY478bVQyFdl47sB3GMOAsHOnDg8B9JYilERQ07Eqd2CNU76NXSkb1J6SFT6MeaR5du6ow4zudWymixR00mv4va7f957qmrK"

# Run all tests
./run_all_tests.sh
```

**Expected Output**:
```
✓ Test 1 - Active quote (downside protection)
✓ Test 2 - Create quote (immediate breach)
✓ Test 3 - Breach detection & secret revelation
✓ Test 4 - Hash160 commitment verification

Results: 4/4 passed (10-15s)
ALL TESTS PASSED
```

### 6. Build WASM

```bash
cd hmac
GOOS=wasip1 GOARCH=wasm go build -o main.wasm
```

Expected: `main.wasm` created successfully.

## How It Works

### CREATE Operation

1. User provides: `domain` + `threshold_price`
2. Fetch current BTC/USD from Chainlink Data Streams
3. Generate secret threshold key: `Thold_key == HMAC(DUCAT_CLIENT_SECRET||domain || prices || timestamp)`
4. Create price threshold commitment: `Thold_hash == Hash160(Thold_key)`
5. Publish to Nostr relay with secret hidden

**Example**:
```bash
cre workflow simulate hmac \
  --target local-simulation \
  --http-payload '{"domain":"cre.com","thold_price":94000}' \
  --trigger-index 0
```

### CHECK Operation

1. User provides: `domain` + `commitment_hash`
2. Fetch current BTC/USD price
3. Check if `current_price < threshold_price`
4. If breached: regenerate secret threshold key `Thold_key` and reveal it
5. Update Nostr event with revealed secret

**Example**:
```bash
cre workflow simulate hmac \
  --target local-simulation \
  --http-payload '{"domain":"cre.com","thold_hash":"YOUR_HASH"}' \
  --trigger-index 0
```

## Architecture

```
┌─────────────────┐       ┌──────────────┐       ┌──────────────┐
│ Chainlink DON   │       │ Chainlink    │       │ Nostr Relay  │
|                 │──────▶│ Runtime Env  │──────▶│              │
│ (Data Stream)   │       │ (Processing) │       │ (Storage)    │
└─────────────────┘       └──────────────┘       └──────────────┘
        │                         │                       │
    Real-time                 Compute                NIP-33
    BTC/USD                   Hash160              Replaceable
    prices                  commitments              Events
```

**Key Components**:
- **Chainlink CRE**: Byzantine fault tolerant consensus for price data
- **HMAC-SHA256**: Domain-separated, deterministic secret generation
- **Hash160**: Bitcoin-style commitments (RIPEMD160(SHA256))
- **Schnorr Signatures**: BIP-340 for signing Nostr events
- **NIP-33**: Parameterized replaceable events (d-tag = commitment hash)

## Project Structure

```
ducat/
├── README.md                    - This file
├── run_all_tests.sh             - Test suite
├── secrets.yaml                 - CRE secrets configuration
├── project.yaml                 - CRE project configuration
│
├── hmac/                        - WASM workflow (main code)
│   ├── main.go                  - CRE entry point
│   ├── handlers.go              - CREATE/CHECK logic
│   ├── crypto.go                - Crypto delegation
│   ├── price.go                 - Chainlink Data Streams integration
│   ├── relay.go                 - Nostr relay integration
│   ├── types.go                 - Data structures
│   ├── constants.go             - Constants
│   ├── config.json              - Configuration
│   └── workflow.yaml            - CRE workflow definition
│
├── crypto/                      - Testable crypto library
│   ├── crypto.go                - Pure crypto functions
│   └── crypto_test.go           - Unit tests (8/8 passing)
│
└── tools/                       - Command-line tools
    └── derive_key.go            - Derive public key from private key
```

## Configuration

### secrets.yaml (in ducat/ directory)

```yaml
secretsNames:
  private_key:
    - DUCAT_PRIVATE_KEY
  client_secret:
    - DUCAT_CLIENT_SECRET
```

This maps environment variables to CRE secrets.

### hmac/config.json

```json
{
  "client_id": "49f249ad-788f-4297-890e-7f5522036c6d",
  "data_stream_url": "https://api.testnet-dataengine.chain.link",
  "feed_id": "0x00037da06502da...",
  "relay_url": "http://localhost:8080",
  "network": "Mutinynet"
}
```

**Change for production**:
- `data_stream_url`: Use production endpoint
- `relay_url`: Use your production relay URL
- `network`: Set to "Mainnet" for Bitcoin mainnet

## Troubleshooting

### Tests Failing with "Relay rejected event"

**Problem**: strfry is not whitelisting your public key.

**Solution**:
1. Derive your public key: `cd tools && go run derive_key.go`
2. Add it to `../strfry/strfry.conf` under `whitelistedPubkeys`
3. Restart strfry: `cd ../strfry && docker-compose restart`

### "Cannot connect to relay"

**Problem**: strfry is not running.

**Solution**:
```bash
cd ../strfry
docker-compose up -d
curl http://localhost:8080/health
```

### "Invalid private key hex encoding"

**Problem**: DUCAT_PRIVATE_KEY is not in correct format.

**Solution**: Ensure it's exactly 64 lowercase hex characters (32 bytes).

### "Commitment verification failed"

**Problem**: Secret regeneration used wrong parameters.

**Solution**: This shouldn't happen. Check test output in `/tmp/ducat_tests_*/summary.txt` for details.

## Security

**Input Validation**:
- Domain: Max 253 chars, alphanumeric + dots/hyphens/underscores
- Price: Rejects NaN/Infinity, validates $1k-$1T range
- Hash: Must be 40 lowercase hex chars (Hash160 format)

**Cryptography**:
- Constant-time comparisons (prevents timing attacks)
- Deterministic HMAC key derivation
- Schnorr signatures for Nostr events (BIP-340)

**DON Security**:
- Byzantine fault tolerance (>50% honest nodes required)
- Median price aggregation (filters outliers)
- Identical event aggregation (ensures consensus)
- Signature verification for all relay responses

## Key Decisions

### Why HMAC-SHA256?
Deterministic and domain-separated. All DON nodes regenerate identical secrets for consensus.

### Why Hash160 vs SHA256?
Bitcoin DLC compatibility. Hash160 (20 bytes) is standard for Bitcoin commitments.

### Why NIP-33 Replaceable Events?
CREATE and CHECK publish to the same d-tag (commitment hash). Nostr automatically replaces the old event - only the latest state exists.

### Breach Semantics
- **Breach**: `current_price < threshold_price` (strictly less than)
- **No breach**: `current_price >= threshold_price`

This avoids floating-point equality issues.

## Performance

- **HMAC**: ~10μs
- **Hash160**: ~5μs
- **Schnorr Sign**: ~200μs
- **End-to-End**: 2-4s (network dominated)

Bottlenecks:
1. Chainlink Data Streams API: ~1-2s
2. Nostr relay publish: ~0.5-1s
3. DON consensus: ~0.5s
4. Crypto operations: <10ms (negligible)

## API Reference

### CREATE Request
```json
{
  "domain": "cre.com",
  "thold_price": 94000.00
}
```

### CREATE Response
```json
{
  "quote_price": 106919.82,
  "thold_hash": "fc176ec8edc32092ab1d19178eb3d117a6d6b114",
  "thold_price": 94000.00,
  "event_type": "active",
  "is_expired": false
}
```

### CHECK Request
```json
{
  "domain": "cre.com",
  "thold_hash": "fc176ec8edc32092ab1d19178eb3d117a6d6b114"
}
```

### CHECK Response (breached)
```json
{
  "event_type": "breach",
  "is_expired": true,
  "thold_key": "7ab425a0e38e8c2b...",
  "current_price": 93500.50
}
```

## Known Limitations

1. **Price decode uses heuristic offsets**: Chainlink Data Streams schema is undocumented
2. **Single relay**: No multi-relay failover (add manually if needed)
3. **Static private key**: No automatic rotation mechanism
