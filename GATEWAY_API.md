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

### Expected Response (200 OK - if completes within 60s)

```json
{
  "status": "completed",
  "request_id": "a1b2c3d4e5f6...",
  "result": {
    "event_type": "create",
    "event_id": "a1b2c3d4e5f6...",
    "pubkey": "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621",
    "created_at": 1762876311,
    "kind": 30078,
    "tags": [
      ["d", "240c124e4a188281668b4899b6456c101c568de8"],
      ["domain", "postman-test.ducat.xyz"],
      ["event_type", "active"],
      ["thold_price", "101500.00000000"]
    ],
    "content": "{\"event_origin\":null,\"event_price\":null,\"event_stamp\":null,\"event_type\":\"active\",\"latest_origin\":\"chainlink\",\"latest_price\":103315.5,\"latest_stamp\":1736620800,\"quote_origin\":\"chainlink\",\"quote_price\":103315.5,\"quote_stamp\":1736620800,\"is_expired\":false,\"srv_network\":\"Mutinynet\",\"srv_pubkey\":\"6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621\",\"thold_hash\":\"240c124e4a188281668b4899b6456c101c568de8\",\"thold_key\":\"\",\"thold_price\":101500,\"req_id\":\"postman-test.ducat.xyz:101500.00\",\"req_sig\":\"...\"}",
    "sig": "f3a545df05289bd476aa6a2447f990034d9124ce6cd1c7b0aa748fec233ad894...",
    "nostr_event": { ... }
  }
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
- Save the `thold_hash` from the response for the CHECK test below

---

## 2. CHECK Threshold (Blocking Request)

Checks if a threshold has been breached. **Blocks until CRE workflow completes** (up to 60s).

### Request

```
POST http://localhost:8081/check
Content-Type: application/json
```

### Body (raw JSON)

**Replace `YOUR_THOLD_HASH_HERE` with the hash from the CREATE response above:**

```json
{
  "domain": "postman-test.ducat.xyz",
  "thold_hash": "240c124e4a188281668b4899b6456c101c568de8"
}
```

### Expected Response (200 OK - No Breach)

```json
{
  "status": "completed",
  "request_id": "b2c3d4e5f6...",
  "result": {
    "event_type": "check_no_breach",
    "event_id": "b2c3d4e5f6...",
    "content": "{...\"event_type\":\"active\",\"is_expired\":false,\"thold_key\":\"\"...}",
    ...
  }
}
```

### Expected Response (200 OK - BREACH!)

If the price has dropped below your threshold:

```json
{
  "status": "completed",
  "request_id": "b2c3d4e5f6...",
  "result": {
    "event_type": "breach",
    "event_id": "b2c3d4e5f6...",
    "content": "{...\"event_type\":\"breach\",\"is_expired\":true,\"thold_key\":\"YOUR_SECRET_KEY_HERE\"...}",
    ...
  }
}
```

**The secret is revealed in `result.content.thold_key`!** 🔓

---

## 3. GET Status (Polling Fallback)

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

```json
{
  "status": "completed",
  "request_id": "a1b2c3d4e5f6...",
  "result": { ...full webhook payload... }
}
```

---

## 4. Health Check

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

## Testing Workflow

### Test 1: Basic CREATE (Happy Path)

1. Start gateway: `./tools/gateway-server`
2. In Postman, send **POST /create** with the JSON above
3. **Watch it block** - Postman will show spinner
4. After ~10-30 seconds, you'll get the result
5. **Save the `thold_hash`** from the response

### Test 2: CHECK (No Breach)

1. Take the `thold_hash` from Test 1
2. Send **POST /check** with that hash
3. Should return `"event_type": "check_no_breach"`
4. Current price is still above threshold

### Test 3: Timeout Scenario

To test the timeout fallback:

1. **Stop the gateway server** (Ctrl+C)
2. In Postman, send **POST /create**
3. **Start the gateway server** immediately
4. The request will timeout after 60s
5. You'll get a 202 with `request_id`
6. Use **GET /status/{request_id}** to poll

### Test 4: Breach Detection

To trigger a breach (for testing):

1. Create a threshold at a **high price**: `"thold_price": 150000.00`
2. Wait for it to complete - you'll get the hash
3. Immediately run **POST /check** with that hash
4. Since current BTC price (~$103k) is below $150k, it will breach!
5. You'll get `"event_type": "breach"` with the secret revealed

---

## Current Configuration

- **Gateway Server**: http://localhost:8081
- **Workflow ID**: `00035da0ef9df06335edb5c99686855121bd0c993b6938cfca03c7d3e55a813c`
- **Network**: Mutinynet (Bitcoin testnet)
- **Current BTC Price**: ~$103,315
- **Block Timeout**: 60 seconds
- **Authorized Address**: `0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82`

---

## Postman Collection Export

You can also create a collection with these requests:

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
      "name": "2. CHECK Threshold",
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
          "raw": "{\n  \"domain\": \"postman-test.ducat.xyz\",\n  \"thold_hash\": \"YOUR_HASH_HERE\"\n}"
        },
        "url": {
          "raw": "http://localhost:8081/check",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8081",
          "path": ["check"]
        }
      }
    },
    {
      "name": "3. GET Status",
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
      "name": "4. Health Check",
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
cd /Users/lucasrodriguez/Desktop/Ducat/cre-hmac/tools
./gateway-server

# Terminal 2: Test with curl (or use Postman)
curl -X POST http://localhost:8081/create \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "curl-test.ducat.xyz",
    "thold_price": 102000.00
  }'

# This will block... watch Terminal 1 for logs...
# After ~20s, you'll get the result with thold_hash

# Now check it
curl -X POST http://localhost:8081/check \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "curl-test.ducat.xyz",
    "thold_hash": "PUT_HASH_FROM_ABOVE_HERE"
  }'
```

Happy testing! 🎯
