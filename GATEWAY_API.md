# DUCAT Blocking Gateway API - Postman Testing Guide

## Quick Start

1. **Start the Gateway Server:**
   ```bash
   cd tools
   ./gateway-server
   ```

2. **Import these requests into Postman**

---

## 1. CREATE Threshold (Blocking Request)

Creates a new threshold commitment. **Blocks until CRE workflow completes** (up to 60s).

### Request

```
POST http://localhost:8081/create
Content-Type: application/json
```

### Body (raw JSON)

```json
{
  "domain": "postman-test.ducat.xyz",
  "thold_price": 101500.00
}
```

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
  "request_id": "a1b2c3d4e5f6...",
  "message": "Request is still processing. Use GET /status/a1b2c3d4e5f6... to check status."
}
```

### Notes
- **This request will block in Postman** - you'll see the spinner for up to 60 seconds
- Watch the gateway server logs to see real-time progress
- Save the `commit_hash` from the response to query the Nostr event later

---

## 2. GET Status (Polling Fallback)

If a request times out (202 response), use this to manually poll for the result.

### Request

```
GET http://localhost:8081/status/{request_id}
```

**Example:**
```
GET http://localhost:8081/status/a1b2c3d4e5f6789012345678
```

### Expected Response (Still Pending)

```json
{
  "status": "pending",
  "request_id": "a1b2c3d4e5f6...",
  "message": "Request is still processing"
}
```

### Expected Response (Completed)

Returns the `PriceContract`:

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

---

## 3. Health Check

Simple endpoint to verify the gateway is running.

### Request

```
GET http://localhost:8081/health
```

### Expected Response (200 OK)

```
OK
```

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

## Testing Workflow

### Test 1: Basic CREATE (Happy Path)

1. Start gateway: `./tools/gateway-server`
2. In Postman, send **POST /create** with the JSON above
3. **Watch it block** - Postman will show spinner
4. After ~10-30 seconds, you'll get the `PriceContract` result
5. **Save the `commit_hash`** to query Nostr later

### Test 2: Timeout Scenario

To test the timeout fallback:

1. **Stop the gateway server** (Ctrl+C)
2. In Postman, send **POST /create**
3. **Start the gateway server** immediately
4. The request will timeout after 60s
5. You'll get a 202 with `request_id`
6. Use **GET /status/{request_id}** to poll

---

## Current Configuration

- **Gateway Server**: http://localhost:8081
- **Workflow ID**: `00035da0ef9df06335edb5c99686855121bd0c993b6938cfca03c7d3e55a813c`
- **Network**: Mutinynet (Bitcoin testnet)
- **Block Timeout**: 60 seconds
- **Authorized Address**: `0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82`

---

## Postman Collection Export

```json
{
  "info": {
    "name": "DUCAT Gateway API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "1. CREATE Threshold",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"domain\": \"postman-test.ducat.xyz\",\n  \"thold_price\": 101500.00\n}"
        },
        "url": {
          "raw": "http://localhost:8081/create",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8081",
          "path": ["create"]
        }
      }
    },
    {
      "name": "2. GET Status",
      "request": {
        "method": "GET",
        "url": {
          "raw": "http://localhost:8081/status/YOUR_REQUEST_ID_HERE",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8081",
          "path": ["status", "YOUR_REQUEST_ID_HERE"]
        }
      }
    },
    {
      "name": "3. Health Check",
      "request": {
        "method": "GET",
        "url": {
          "raw": "http://localhost:8081/health",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8081",
          "path": ["health"]
        }
      }
    }
  ]
}
```

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
# Terminal 1: Start Gateway
cd tools
./gateway-server

# Terminal 2: Test with curl
curl -X POST http://localhost:8081/create \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "curl-test.ducat.xyz",
    "thold_price": 102000.00
  }'

# This will block... watch Terminal 1 for logs...
# After ~20s, you'll get the PriceContract result
```
