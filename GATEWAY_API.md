# DUCAT Gateway API

Complete API documentation for the DUCAT threshold commitment gateway.

## Quick Start

1. **Start the Gateway Server:**
   ```bash
   cd tools
   ./gateway-server
   ```

2. **Create a threshold commitment:**
   ```bash
   curl "http://localhost:8080/api/quote?th=105000"
   ```

---

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/quote` | GET | Create threshold commitment |
| `/api/price` | GET | Get cached base price |
| `/health` | GET | Liveness probe |
| `/readiness` | GET | Readiness probe with dependency checks |
| `/metrics` | GET | Prometheus metrics |
| `/webhook/ducat` | POST | CRE callback endpoint (internal) |

---

## 1. CREATE Threshold (Blocking Request)

Creates a new threshold commitment. **Blocks until CRE workflow completes** (up to 60s).

### Request

```
GET http://localhost:8080/api/quote?th=105000
```

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `th` | float | Yes | Threshold price (e.g., 105000.00) |

### Expected Response (200 OK)

Returns a `PriceContract` (matches core-ts schema exactly):

```json
{
  "chain_network": "mutinynet",
  "oracle_pubkey": "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621",
  "base_price": 103315,
  "base_stamp": 1736620800,
  "commit_hash": "a1b2c3d4e5f6...",
  "contract_id": "e5f6g7h8i9j0...",
  "oracle_sig": "deadbeef1234...",
  "thold_hash": "240c124e4a188281668b4899b6456c101c568de8",
  "thold_key": null,
  "thold_price": 101500
}
```

### Expected Response (202 Accepted - if timeout after 60s)

```json
{
  "status": "timeout",
  "request_id": "req-1734567890123456789",
  "message": "Request is still processing. Use GET /status/req-1734567890123456789 to check status."
}
```

### Notes
- **This request will block** for up to 60 seconds (configurable via `BLOCK_TIMEOUT_SECONDS`)
- Watch the gateway server logs to see real-time progress
- Save the `thold_hash` from the response to evaluate the quote later

---

## 2. Health Check (Liveness)

Simple endpoint to verify the gateway is running.

### Request

```
GET http://localhost:8080/health
```

### Expected Response (200 OK)

```json
{
  "status": "healthy",
  "timestamp": "2024-12-18T12:00:00Z",
  "uptime": "2h30m15s"
}
```

---

## 3. Readiness Check

Comprehensive health check including dependency status.

### Request

```
GET http://localhost:8080/readiness
```

### Expected Response (200 OK)

```json
{
  "status": "healthy",
  "timestamp": "2024-12-18T12:00:00Z",
  "version": "1.0.0",
  "uptime": "2h30m15s",
  "dependencies": {
    "cre_gateway": {
      "status": "up",
      "latency": "45ms",
      "message": "Reachable",
      "last_checked": "2024-12-18T12:00:00Z"
    },
    "capacity": {
      "status": "up",
      "message": "Capacity available",
      "last_checked": "2024-12-18T12:00:00Z"
    },
    "authentication": {
      "status": "up",
      "message": "Private key loaded",
      "last_checked": "2024-12-18T12:00:00Z"
    }
  },
  "metrics": {
    "pending_requests": 5,
    "max_pending": 1000,
    "capacity_used_percent": 0.5
  }
}
```

---

## 4. Prometheus Metrics

Exposes metrics for monitoring.

### Request

```
GET http://localhost:8080/metrics
```

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `gateway_http_requests_total` | Counter | Total HTTP requests by endpoint/status |
| `gateway_http_request_duration_seconds` | Histogram | Request latency |
| `gateway_pending_requests` | Gauge | Current pending requests |
| `gateway_webhooks_received_total` | Counter | Webhooks received by type |
| `gateway_workflow_triggers_total` | Counter | Workflow triggers by operation/status |
| `gateway_request_timeouts_total` | Counter | Request timeouts by endpoint |

---

## Nostr Event Structure

Events are stored in Nostr as NIP-33 replaceable events (kind 30078).

### Tags

| Tag | Value |
|-----|-------|
| `d` | `commit_hash` - NIP-33 replaceable identifier |

### Content

The event content is the `PriceContract` JSON:

```json
{
  "chain_network": "mutinynet",
  "oracle_pubkey": "6b5008a293291c14...",
  "base_price": 103315,
  "base_stamp": 1736620800,
  "commit_hash": "a1b2c3d4e5f6...",
  "contract_id": "e5f6g7h8i9j0...",
  "oracle_sig": "deadbeef1234...",
  "thold_hash": "240c124e4a18...",
  "thold_key": null,
  "thold_price": 101500
}
```

When breached, `thold_key` contains the revealed 32-byte hex secret.

### Querying Nostr

```bash
# Query by commit_hash
GET /api/query?#d=<commit_hash>
```

---

## Testing

### Quick Test with curl

```bash
# Start gateway
cd tools && ./gateway-server

# Create a threshold commitment
curl "http://localhost:8080/api/quote?th=105000"

# Check health
curl http://localhost:8080/health

# Check readiness
curl http://localhost:8080/readiness
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CRE_WORKFLOW_ID` | Yes | - | CRE workflow identifier (64 hex chars) |
| `CRE_GATEWAY_URL` | No | `https://01.gateway.zone-a.cre.chain.link` | CRE gateway URL |
| `DUCAT_PRIVATE_KEY` | Yes | - | Secp256k1 private key (64 hex chars) |
| `DUCAT_AUTHORIZED_KEY` | Yes | - | Authorized Ethereum address |
| `GATEWAY_CALLBACK_URL` | Yes | - | Webhook callback URL |
| `PORT` | No | `8080` | Server port |
| `BLOCK_TIMEOUT_SECONDS` | No | `60` | Request timeout |
| `MAX_PENDING_REQUESTS` | No | `1000` | Max concurrent pending requests |
| `LOG_LEVEL` | No | `info` | Log level (debug, info, warn, error) |
| `LOG_FORMAT` | No | `console` | Log format (console, json) |

---

## Troubleshooting

### "Connection refused"
- Gateway server not running - start it with `./tools/gateway-server`

### "Request timeout in Postman"
- Postman has its own timeout (default: 30s)
- Go to Settings → General → Request timeout and set to 70000ms (70 seconds)

### "Failed to trigger workflow"
- Check that the workflow ID is correct
- Check that the private key matches the authorized address
- Check CRE gateway is accessible

### Gateway logs show "Auth failure"
- Signature verification failed
- Verify private key and authorized address match

---

## Example: Full Test Sequence

```bash
# Terminal 1: Start Gateway (set required env vars first)
export CRE_WORKFLOW_ID="your-workflow-id"
export DUCAT_PRIVATE_KEY="your-private-key"
export DUCAT_AUTHORIZED_KEY="0x..."
export GATEWAY_CALLBACK_URL="http://localhost:8080/webhook/ducat"

cd tools
./gateway-server

# Terminal 2: Test with curl
curl "http://localhost:8080/api/quote?th=105000"

# This will block... watch Terminal 1 for logs...
# After ~10-30s, you'll get the PriceContract result
```
