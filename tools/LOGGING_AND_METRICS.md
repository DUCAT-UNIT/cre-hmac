# Logging and Metrics Guide

## Overview

The DUCAT Gateway Server now includes production-grade structured logging and Prometheus metrics for comprehensive observability.

## Structured Logging

### Technology
- **Library**: [Uber Zap](https://github.com/uber-go/zap) - High-performance structured logging
- **Format**: JSON (production) or colorized console (development)
- **Levels**: debug, info, warn, error, fatal

### Configuration

Set via environment variables:

```bash
# Log level (default: info)
LOG_LEVEL=debug|info|warn|error

# Log format (default: console)
LOG_FORMAT=json|console
```

### Example Log Output

**Console Format** (development):
```
2025-11-17T02:00:00.000Z  INFO  Gateway server initialized
    authorized_key=0x5b3ebc...
    callback_url=https://example.ngrok.app/webhook/ducat
    max_pending=1000
    block_timeout=1m0s

2025-11-17T02:00:01.123Z  INFO  CREATE request initiated
    domain=req-1234567890
    threshold_price=95000.00
    tracking_key=req-1234567890
    pending_count=1
```

**JSON Format** (production):
```json
{
  "level": "info",
  "ts": "2025-11-17T02:00:00.000Z",
  "msg": "Gateway server initialized",
  "authorized_key": "0x5b3ebc...",
  "callback_url": "https://example.ngrok.app/webhook/ducat",
  "max_pending": 1000,
  "block_timeout": "1m0s"
}
```

### Key Log Events

| Event | Level | Description |
|-------|-------|-------------|
| Gateway initialization | INFO | Server startup with configuration |
| CREATE request initiated | INFO | New threshold commitment request |
| CREATE request completed | INFO | Successful commitment with hash |
| CREATE request timeout | WARN | Request timed out after BLOCK_TIMEOUT |
| Webhook received and matched | INFO | Webhook successfully matched to pending request |
| Webhook unmatched | DEBUG | Webhook received but no pending request found |
| Duplicate webhook | DEBUG | Same webhook received multiple times |
| Max pending reached | WARN | Server at capacity, rejecting requests |
| Cleanup completed | INFO | Old requests removed from memory |
| Stale pending request | WARN | Request never completed/timed out (unusual) |
| Workflow trigger failed | ERROR | Failed to trigger CRE workflow |

## Prometheus Metrics

### Metrics Endpoint

Metrics are exposed at `/metrics` in Prometheus format:

```bash
curl http://localhost:8080/metrics
```

### Available Metrics

#### Request Metrics

**`gateway_http_requests_total{endpoint, method, status}`**
- Type: Counter
- Description: Total HTTP requests by endpoint, method, and status code
- Labels:
  - `endpoint`: create, webhook, health, metrics
  - `method`: GET, POST
  - `status`: 200, 202, 400, 500, 503, etc.

```promql
# Example queries
rate(gateway_http_requests_total{endpoint="create"}[5m])
gateway_http_requests_total{status="503"}  # Capacity rejections
```

**`gateway_http_request_duration_seconds{endpoint, method}`**
- Type: Histogram
- Description: HTTP request latency in seconds
- Buckets: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10

```promql
# Example queries
histogram_quantile(0.95, rate(gateway_http_request_duration_seconds_bucket[5m]))
avg(gateway_http_request_duration_seconds_sum) by (endpoint)
```

#### Application Metrics

**`gateway_pending_requests`**
- Type: Gauge
- Description: Current number of pending requests
- Use: Monitor memory usage and capacity

```promql
# Alert when approaching capacity
gateway_pending_requests / 1000 > 0.9
```

**`gateway_webhooks_received_total{event_type, matched}`**
- Type: Counter
- Description: Total webhooks received from CRE
- Labels:
  - `event_type`: create, check_no_breach, breach
  - `matched`: matched, no_match, duplicate

```promql
# Webhook match rate
rate(gateway_webhooks_received_total{matched="matched"}[5m]) /
rate(gateway_webhooks_received_total[5m])
```

**`gateway_workflow_triggers_total{operation, status}`**
- Type: Counter
- Description: Total CRE workflow triggers
- Labels:
  - `operation`: create, check
  - `status`: success, error

```promql
# Workflow error rate
rate(gateway_workflow_triggers_total{status="error"}[5m])
```

**`gateway_request_timeouts_total{endpoint}`**
- Type: Counter
- Description: Total request timeouts
- Labels:
  - `endpoint`: create, check

```promql
# Timeout rate
rate(gateway_request_timeouts_total[5m])
```

**`gateway_requests_cleaned_up_total`**
- Type: Counter
- Description: Total old requests cleaned up from memory

```promql
# Cleanup activity
rate(gateway_requests_cleaned_up_total[1h])
```

### Grafana Dashboard

Example Prometheus queries for Grafana dashboard:

```promql
# Request Rate
rate(gateway_http_requests_total{endpoint="create"}[5m])

# Success Rate
sum(rate(gateway_http_requests_total{status=~"2.."}[5m])) /
sum(rate(gateway_http_requests_total[5m]))

# P95 Latency
histogram_quantile(0.95,
  rate(gateway_http_request_duration_seconds_bucket[5m]))

# Pending Requests Over Time
gateway_pending_requests

# Webhook Match Rate
sum(rate(gateway_webhooks_received_total{matched="matched"}[5m])) /
sum(rate(gateway_webhooks_received_total[5m]))

# Error Rate
rate(gateway_http_requests_total{status=~"5.."}[5m])
```

## Alerting Rules

### Recommended Prometheus Alerts

```yaml
groups:
  - name: gateway_alerts
    rules:
      # High error rate
      - alert: GatewayHighErrorRate
        expr: rate(gateway_http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 2m
        annotations:
          summary: "Gateway error rate above 5%"

      # Approaching capacity
      - alert: GatewayNearCapacity
        expr: gateway_pending_requests / 1000 > 0.8
        for: 5m
        annotations:
          summary: "Gateway at 80% capacity"

      # High timeout rate
      - alert: GatewayHighTimeouts
        expr: rate(gateway_request_timeouts_total[5m]) > 0.1
        for: 2m
        annotations:
          summary: "Gateway timeout rate above 10%"

      # Webhook mismatch rate
      - alert: GatewayWebhookMismatch
        expr: |
          sum(rate(gateway_webhooks_received_total{matched="no_match"}[5m])) /
          sum(rate(gateway_webhooks_received_total[5m])) > 0.1
        for: 5m
        annotations:
          summary: "High webhook mismatch rate (>10%)"

      # Workflow trigger failures
      - alert: GatewayWorkflowFailures
        expr: rate(gateway_workflow_triggers_total{status="error"}[5m]) > 0
        for: 1m
        annotations:
          summary: "CRE workflow trigger failures detected"
```

## Monitoring Setup

### Quick Start with Docker

1. **Prometheus Configuration** (`prometheus.yml`):

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'gateway'
    static_configs:
      - targets: ['gateway:8080']
```

2. **Docker Compose**:

```yaml
version: '3'
services:
  gateway:
    build: .
    ports:
      - "8080:8080"
    environment:
      - LOG_FORMAT=json
      - LOG_LEVEL=info

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

3. **Start monitoring stack**:

```bash
docker-compose up -d
```

4. **Access**:
   - Gateway: http://localhost:8080
   - Metrics: http://localhost:8080/metrics
   - Prometheus: http://localhost:9090
   - Grafana: http://localhost:3000

## Log Aggregation

### With Elasticsearch/Logstash

Configure your log shipper to parse JSON logs:

```json
{
  "level": "info",
  "ts": "2025-11-17T02:00:00.000Z",
  "msg": "CREATE request initiated",
  "domain": "req-1234567890",
  "threshold_price": 95000.00
}
```

### With Datadog

Add Datadog log collection:

```yaml
logs:
  - type: file
    path: /var/log/gateway/*.log
    service: gateway
    source: zap
    sourcecategory: application
```

## Performance Impact

- **Logging overhead**: ~2-5μs per log statement (zap is highly optimized)
- **Metrics overhead**: ~500ns per counter increment
- **Memory**: ~1KB per pending request tracked
- **HTTP overhead**: Metrics middleware adds <1ms per request

## Best Practices

1. **Production**: Use `LOG_FORMAT=json` and `LOG_LEVEL=info`
2. **Development**: Use `LOG_FORMAT=console` and `LOG_LEVEL=debug`
3. **Staging**: Use `LOG_FORMAT=json` and `LOG_LEVEL=debug`

4. **Monitor**:
   - Pending requests gauge (watch for capacity issues)
   - Timeout rate (may need to increase BLOCK_TIMEOUT)
   - Webhook match rate (indicates request tracking health)
   - Error rate (indicates system health)

5. **Alert on**:
   - Error rate > 5%
   - Pending requests > 80% capacity
   - Webhook mismatch rate > 10%
   - Any workflow trigger failures

## Troubleshooting

### High Memory Usage
Check `gateway_pending_requests` - if consistently high, increase cleanup frequency:
```bash
CLEANUP_INTERVAL_SECONDS=60  # Clean up every minute instead of 2
```

### Missing Logs
Verify log level is appropriate:
```bash
LOG_LEVEL=debug  # Temporarily enable debug logs
```

### Webhook Mismatches
Check metrics:
```promql
gateway_webhooks_received_total{matched="no_match"}
```
Could indicate timing issues or request ID mismatches.

### High Latency
Check P95 latency metric:
```promql
histogram_quantile(0.95, rate(gateway_http_request_duration_seconds_bucket[5m]))
```
Most latency is from waiting for webhooks (controlled by BLOCK_TIMEOUT).
