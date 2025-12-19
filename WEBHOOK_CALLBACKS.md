# Webhook Callbacks

The DUCAT Oracle workflow uses webhooks to notify the gateway when operations complete.

## Callback Types

### 1. `create` - New Quote Created

Sent when a new threshold commitment is created via `/api/quote`.

```json
{
  "event_type": "create",
  "event_id": "263d59e582c1d4debe0f5b8dd89a1082e4872f390f617175fef297ce8f071a79",
  "domain": "test.ducat.xyz",
  "thold_hash": "240c124e4a188281668b4899b6456c101c568de8",
  "price_contract": {
    "chain_network": "mutinynet",
    "oracle_pubkey": "6b5008a293291c14...",
    "base_price": 105000,
    "base_stamp": 1734567890,
    "commit_hash": "a1b2c3d4...",
    "contract_id": "e5f6g7h8...",
    "oracle_sig": "deadbeef...",
    "thold_hash": "240c124e4a188281668b4899b6456c101c568de8",
    "thold_key": null,
    "thold_price": 141750
  }
}
```

### 2. `batch_generated` - Cron Batch Complete

Sent when the CRE cron job generates a new batch of quotes. Gateway caches this price.

```json
{
  "event_type": "batch_generated",
  "data": {
    "base_price": 105000,
    "base_stamp": 1734567890
  }
}
```

### 3. `evaluate` - Batch Evaluation Complete

Sent when `/api/evaluate` completes batch quote evaluation.

```json
{
  "event_type": "evaluate",
  "event_id": "evaluate-0",
  "domain": "eval-abc123",
  "data": {
    "results": [
      {
        "thold_hash": "240c124e4a188281668b4899b6456c101c568de8",
        "status": "active",
        "thold_key": null,
        "current_price": 105000.50,
        "thold_price": 110000.00
      },
      {
        "thold_hash": "350d235f5b299392779c5900c7567d212d679ef9",
        "status": "breached",
        "thold_key": "revealed_secret_here",
        "current_price": 105000.50,
        "thold_price": 100000.00
      }
    ],
    "current_price": 105000.50,
    "evaluated_at": 1734567890,
    "summary": {
      "total": 2,
      "breached": 1,
      "active": 1,
      "errors": 0,
      "error_messages": []
    }
  }
}
```

## Webhook Payload Structure

All webhooks share a common structure:

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | string | Type: `create`, `batch_generated`, `evaluate` |
| `event_id` | string | Unique event identifier |
| `domain` | string | Request domain (for create/evaluate) |
| `thold_hash` | string | Threshold hash (for create) |
| `price_contract` | object | PriceContract (for create) |
| `data` | object | Response data (for batch_generated/evaluate) |

## Nostr Event Structure

Events are published to Nostr as NIP-33 replaceable events (kind 30078).

### Tags

| Tag | Value |
|-----|-------|
| `d` | `commit_hash` - NIP-33 replaceable identifier |

### Content

The event content is the `PriceContract` JSON (matches core-ts schema exactly):

```json
{
  "chain_network": "mutinynet",
  "oracle_pubkey": "6b5008a293291c14...",
  "base_price": 105000,
  "base_stamp": 1734567890,
  "commit_hash": "a1b2c3d4...",
  "contract_id": "e5f6g7h8...",
  "oracle_sig": "deadbeef...",
  "thold_hash": "240c124e4a18...",
  "thold_key": null,
  "thold_price": 141750
}
```

When breached, `thold_key` contains the revealed 32-byte hex secret.

## Gateway Webhook Handler

The gateway handles webhooks at `POST /webhook/ducat`:

```go
// Handle batch_generated - cache base price
if payload.EventType == "batch_generated" {
    // Parse base_price and base_stamp
    // Store in memory + SQLite
    // Used by GET /api/price
}

// Handle create/evaluate - unblock waiting requests
// Match by domain, send result to waiting HTTP client
```

## CRE Configuration

Set the gateway callback URL in CRE config:

```json
{
  "gateway_callback_url": "http://gateway:8080/webhook/ducat"
}
```

The CRE cron job will POST `batch_generated` events to this URL after generating quotes.

## Security Considerations

1. **Internal network**: Webhook endpoint should only be accessible from CRE
2. **Idempotency**: Use `event_id` to deduplicate (DON consensus may send multiple)
3. **Signature verification**: Verify `oracle_sig` in `price_contract` for authenticity
4. **Timeouts**: Webhook should respond within 10 seconds

## Data Flow

```
CRE (cron)                               Gateway
    │                                       │
    ├─ generateQuotesParallel()             │
    ├─ publish to Nostr                     │
    │                                       │
    ├─ POST /webhook/ducat ────────────────►│
    │   event_type: "batch_generated"       │
    │   data: {base_price, base_stamp}      │
    │                                       ├─ cache in SQLite
    │                                       │
    │                                       │
CRE (HTTP trigger)                       Gateway
    │                                       │
    │◄───────────────── triggerWorkflow() ──┤
    │                                       │
    ├─ createQuote()                        │
    ├─ publish to Nostr                     │
    │                                       │
    ├─ POST /webhook/ducat ────────────────►│
    │   event_type: "create"                │
    │   price_contract: {...}               │
    │                                       ├─ unblock waiting request
    │                                       │
```
