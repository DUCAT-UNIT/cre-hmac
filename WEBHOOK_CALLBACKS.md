# Webhook Callbacks

The DUCAT Oracle workflow now supports **webhook callbacks** to automatically notify your server when operations complete, eliminating the need to manually check the CRE console.

## How It Works

When you trigger a workflow (CREATE or CHECK), you can provide an optional `callback_url`. After the workflow completes and publishes to Nostr, it will POST the result to your webhook.

## Callback Types

### 1. **CREATE** - New Threshold Created
Sent when a new threshold commitment is successfully created.

```json
{
  "event_type": "create",
  "event_id": "263d59e582c1d4debe0f5b8dd89a1082e4872f390f617175fef297ce8f071a79",
  "pubkey": "6b5008a293291c14effeb0e8b7c56a80ecb5ca7b801768e17ec93092be6c0621",
  "created_at": 1762876311,
  "kind": 30078,
  "tags": [
    ["d", "240c124e4a188281668b4899b6456c101c568de8"],
    ["domain", "test2.ducat.xyz"],
    ["event_type", "active"],
    ["thold_price", "95000.00000000"]
  ],
  "content": "{...full PriceEvent JSON...}",
  "sig": "f3a545df05289bd476aa6a2447f990034d9124ce6cd1c7b0aa748fec233ad894...",
  "nostr_event": {...full event...}
}
```

### 2. **CHECK (No Breach)** - Threshold Still Safe
Sent when CHECK confirms the threshold hasn't been breached yet.

```json
{
  "event_type": "check_no_breach",
  "event_id": "263d59e582c1d4debe0f5b8dd89a1082e4872f390f617175fef297ce8f071a79",
  ...same structure as CREATE...
}
```

### 3. **BREACH** - Secret Revealed!
Sent when CHECK detects a threshold breach and reveals the secret.

```json
{
  "event_type": "breach",
  "event_id": "...",
  "content": "{...PriceEvent with thold_key revealed...}",
  ...
}
```

The `content` field will contain the complete `PriceEvent` with:
- `event_price`: Current price that breached threshold
- `event_stamp`: Breach timestamp
- `thold_key`: **THE REVEALED SECRET** 🔓

## Usage

### With trigger-http Tool

```bash
# CREATE with webhook
./trigger-http \
  --workflow-id 0084e4d5376fa916e50fc3e3b9997890402d6b880f8e682f7cc3d3708ce50fc7 \
  --domain "example.com" \
  --op create \
  --thold-price "95000.00" \
  --callback-url "https://your-server.com/webhook/ducat"

# CHECK with webhook
./trigger-http \
  --workflow-id 0084e4d5376fa916e50fc3e3b9997890402d6b880f8e682f7cc3d3708ce50fc7 \
  --domain "example.com" \
  --op check \
  --thold-hash "240c124e4a188281668b4899b6456c101c568de8" \
  --callback-url "https://your-server.com/webhook/ducat"
```

### Raw JSON-RPC Request

```json
{
  "jsonrpc": "2.0",
  "id": "unique-id",
  "method": "workflows.execute",
  "params": {
    "input": {
      "domain": "example.com",
      "thold_price": 95000.00,
      "callback_url": "https://your-server.com/webhook/ducat"
    },
    "workflow": {
      "workflowID": "0084e4d5376fa916e50fc3e3b9997890402d6b880f8e682f7cc3d3708ce50fc7"
    }
  }
}
```

## Webhook Server Example

Here's a simple Go webhook server to receive callbacks:

```go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type WebhookPayload struct {
	EventType   string                 `json:"event_type"`
	EventID     string                 `json:"event_id"`
	PubKey      string                 `json:"pubkey"`
	CreatedAt   int64                  `json:"created_at"`
	Content     string                 `json:"content"`
	NostrEvent  map[string]interface{} `json:"nostr_event"`
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("Received %s event: %s\n", payload.EventType, payload.EventID)

	switch payload.EventType {
	case "create":
		log.Printf("New threshold created!")
		// Handle new commitment
	case "check_no_breach":
		log.Printf("Threshold still safe")
		// Continue monitoring
	case "breach":
		log.Printf("🚨 THRESHOLD BREACHED! Secret revealed!")
		// Parse content to get thold_key
		// Execute conditional logic (release funds, etc.)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	http.HandleFunc("/webhook/ducat", handleWebhook)
	log.Println("Webhook server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Security Considerations

1. **HTTPS Only**: Always use HTTPS for webhook URLs in production
2. **Signature Verification**: Verify the Nostr event signature to ensure authenticity:
   ```go
   // The event.sig is a Schnorr signature that proves the event
   // came from the DUCAT oracle with pubkey: event.pubkey
   ```
3. **Idempotency**: Use `event_id` to deduplicate callbacks (DON consensus may send multiple)
4. **Timeouts**: Your webhook endpoint should respond within 10 seconds
5. **Retry Logic**: The workflow won't retry failed webhooks - use a queue if processing is slow

## Benefits

✅ **No Polling**: Instant notifications when events occur
✅ **Automated Workflows**: Trigger actions immediately on breach
✅ **Efficient**: Don't waste resources checking CRE console
✅ **Reliable**: Uses DON consensus for delivery
✅ **Flexible**: Any HTTP endpoint can receive callbacks

## Testing

Test your webhook endpoint with a local server:

```bash
# Run webhook server
go run your-webhook-server.go

# In another terminal, use ngrok for public URL
ngrok http 8080

# Use the ngrok HTTPS URL as callback
./trigger-http \
  --workflow-id 0084e4d5376fa916e50fc3e3b9997890402d6b880f8e682f7cc3d3708ce50fc7 \
  --domain "test.com" \
  --op create \
  --thold-price "95000.00" \
  --callback-url "https://abc123.ngrok.io/webhook/ducat"
```

## Deployment

Remember to **redeploy** the workflow after adding webhook support:

```bash
cd hmac
GOOS=wasip1 GOARCH=wasm go build -o binary.wasm .
cd ..
cre workflow deploy ./hmac --target production-testnet --yes
```

Then your workflow will support callback URLs! 🎉
