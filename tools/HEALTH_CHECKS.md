# Health Check Documentation

## Overview

The gateway server provides two types of health checks following Kubernetes best practices:

1. **Liveness Probe** (`/health`) - Is the server running?
2. **Readiness Probe** (`/readiness`) - Is the server ready to accept traffic?

## Endpoints

### GET /health - Liveness Probe

**Purpose**: Verify the server process is alive and responding.

**When to use**: Container orchestration (Kubernetes, Docker) to detect if the process needs to be restarted.

**Response**: Always returns 200 OK if the server is running.

**Example**:
```bash
curl http://localhost:8080/health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-11-17T02:15:30Z",
  "uptime": "1h23m45s"
}
```

**Kubernetes Configuration**:
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30
  timeoutSeconds: 5
  failureThreshold: 3
```

---

### GET /readiness - Readiness Probe

**Purpose**: Verify the server can handle requests (all dependencies are healthy).

**When to use**:
- Load balancer health checks
- Kubernetes readiness checks
- Circuit breaker decisions
- Pre-deployment validation

**Status Codes**:
- `200 OK` - Healthy or degraded (can still serve traffic)
- `503 Service Unavailable` - Unhealthy (cannot serve traffic)

**Example**:
```bash
curl http://localhost:8080/readiness
```

**Healthy Response** (200 OK):
```json
{
  "status": "healthy",
  "timestamp": "2025-11-17T02:15:30Z",
  "version": "1.0.0",
  "uptime": "1h23m45s",
  "dependencies": {
    "cre_gateway": {
      "status": "up",
      "latency": "145ms",
      "message": "Reachable",
      "last_checked": "2025-11-17T02:15:30Z"
    },
    "capacity": {
      "status": "up",
      "message": "Capacity available",
      "last_checked": "2025-11-17T02:15:30Z"
    },
    "authentication": {
      "status": "up",
      "message": "Private key loaded",
      "last_checked": "2025-11-17T02:15:30Z"
    }
  },
  "metrics": {
    "pending_requests": 15,
    "max_pending": 1000,
    "capacity_used_percent": 1.5
  }
}
```

**Degraded Response** (200 OK - still accepting traffic):
```json
{
  "status": "degraded",
  "timestamp": "2025-11-17T02:16:00Z",
  "version": "1.0.0",
  "uptime": "1h24m15s",
  "dependencies": {
    "cre_gateway": {
      "status": "degraded",
      "latency": "2.5s",
      "message": "Slow response time",
      "last_checked": "2025-11-17T02:16:00Z"
    },
    "capacity": {
      "status": "degraded",
      "message": "Near capacity limit",
      "last_checked": "2025-11-17T02:16:00Z"
    },
    "authentication": {
      "status": "up",
      "message": "Private key loaded",
      "last_checked": "2025-11-17T02:16:00Z"
    }
  },
  "metrics": {
    "pending_requests": 920,
    "max_pending": 1000,
    "capacity_used_percent": 92.0
  }
}
```

**Unhealthy Response** (503 Service Unavailable):
```json
{
  "status": "unhealthy",
  "timestamp": "2025-11-17T02:17:00Z",
  "version": "1.0.0",
  "uptime": "1h25m15s",
  "dependencies": {
    "cre_gateway": {
      "status": "down",
      "message": "Unreachable: connection timeout",
      "last_checked": "2025-11-17T02:17:00Z"
    },
    "capacity": {
      "status": "down",
      "message": "At capacity limit",
      "last_checked": "2025-11-17T02:17:00Z"
    },
    "authentication": {
      "status": "up",
      "message": "Private key loaded",
      "last_checked": "2025-11-17T02:17:00Z"
    }
  },
  "metrics": {
    "pending_requests": 1000,
    "max_pending": 1000,
    "capacity_used_percent": 100.0
  }
}
```

**Kubernetes Configuration**:
```yaml
readinessProbe:
  httpGet:
    path: /readiness
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 5
  successThreshold: 1
  failureThreshold: 3
```

---

## Dependency Checks

The readiness probe validates these dependencies:

### 1. CRE Gateway (`cre_gateway`)

**What it checks**: Can we reach the CRE gateway?

**Method**: HEAD request to `GATEWAY_URL` with 5-second timeout

**Status determination**:
- `up` - Responds within 2 seconds
- `degraded` - Responds in 2-5 seconds (slow)
- `down` - Timeout or connection error

**Why it matters**: If we can't reach CRE, we can't trigger workflows.

---

### 2. Capacity (`capacity`)

**What it checks**: Do we have room for more pending requests?

**Method**: Check `len(pendingRequests)` vs `MAX_PENDING`

**Status determination**:
- `up` - < 90% capacity
- `degraded` - >= 90% capacity
- `down` - >= 100% capacity (at limit)

**Why it matters**: Prevents accepting requests when at capacity.

---

### 3. Authentication (`authentication`)

**What it checks**: Is the private key loaded and available?

**Method**: Verify `privateKey != nil`

**Status determination**:
- `up` - Private key loaded
- `down` - Private key missing

**Why it matters**: Without private key, cannot sign JWT tokens for CRE.

---

## Health Check Metrics

Prometheus metrics track health check behavior:

### `gateway_health_checks_total{type, status}`
- Type: Counter
- Labels:
  - `type`: liveness, readiness
  - `status`: healthy, degraded, unhealthy

**Example queries**:
```promql
# Readiness check failure rate
rate(gateway_health_checks_total{type="readiness",status!="healthy"}[5m])

# Total health checks
sum(gateway_health_checks_total)
```

### `gateway_dependency_status{dependency}`
- Type: Gauge
- Labels: `dependency` (cre_gateway, capacity, authentication)
- Values: 1.0 (up), 0.5 (degraded), 0.0 (down)

**Example queries**:
```promql
# CRE gateway availability
gateway_dependency_status{dependency="cre_gateway"}

# Alert if any dependency is down
gateway_dependency_status < 0.5
```

---

## Load Balancer Integration

### AWS ALB/ELB

```yaml
HealthCheck:
  Target: HTTP:8080/readiness
  Interval: 30
  Timeout: 5
  HealthyThreshold: 2
  UnhealthyThreshold: 3
```

### GCP Load Balancer

```yaml
healthCheck:
  type: HTTP
  port: 8080
  requestPath: /readiness
  checkIntervalSec: 10
  timeoutSec: 5
  healthyThreshold: 2
  unhealthyThreshold: 3
```

### HAProxy

```
backend gateway_servers
    option httpchk GET /readiness
    http-check expect status 200
    server gateway1 10.0.0.1:8080 check
    server gateway2 10.0.0.2:8080 check
```

---

## Alerting Rules

### Prometheus Alerts

```yaml
groups:
  - name: health_alerts
    rules:
      # CRE Gateway unreachable
      - alert: CREGatewayDown
        expr: gateway_dependency_status{dependency="cre_gateway"} == 0
        for: 2m
        annotations:
          summary: "CRE Gateway is unreachable"
          description: "Cannot connect to CRE gateway for {{ $value }} minutes"

      # Near capacity
      - alert: GatewayNearCapacity
        expr: gateway_dependency_status{dependency="capacity"} == 0.5
        for: 5m
        annotations:
          summary: "Gateway near capacity (>90%)"

      # At capacity
      - alert: GatewayAtCapacity
        expr: gateway_dependency_status{dependency="capacity"} == 0
        for: 1m
        annotations:
          summary: "Gateway at capacity limit"
          severity: critical

      # Readiness check failures
      - alert: GatewayNotReady
        expr: rate(gateway_health_checks_total{type="readiness",status="unhealthy"}[5m]) > 0
        for: 2m
        annotations:
          summary: "Gateway failing readiness checks"
```

---

## Testing

### Manual Testing

```bash
# Run the test script
./test_health_checks.sh

# Or manually:
curl -v http://localhost:8080/health
curl -v http://localhost:8080/readiness | jq .
```

### Automated Testing

```bash
# Check if server is ready
if curl -sf http://localhost:8080/readiness > /dev/null; then
    echo "Server is ready"
else
    echo "Server is not ready"
    exit 1
fi
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Wait for server ready
  run: |
    for i in {1..30}; do
      if curl -sf http://localhost:8080/readiness; then
        echo "Server ready"
        exit 0
      fi
      echo "Waiting for server... ($i/30)"
      sleep 2
    done
    echo "Server did not become ready"
    exit 1
```

---

## Troubleshooting

### Readiness probe failing

1. **Check logs**:
   ```bash
   # Look for "Readiness check failed" warnings
   LOG_LEVEL=debug ./gateway-server
   ```

2. **Check specific dependency**:
   ```bash
   curl http://localhost:8080/readiness | jq '.dependencies'
   ```

3. **Common issues**:
   - `cre_gateway: down` - Check firewall, network connectivity to CRE
   - `capacity: down` - Too many pending requests, increase `MAX_PENDING_REQUESTS`
   - `authentication: down` - `DUCAT_PRIVATE_KEY` env var not set

### CRE Gateway check slow

If `cre_gateway` shows `degraded` status:
- Check network latency to CRE gateway
- Verify no DNS issues
- Check if CRE gateway is overloaded

### High capacity usage

If `capacity` shows `degraded`:
- Increase `MAX_PENDING_REQUESTS`
- Investigate why requests aren't completing (check webhook delivery)
- Scale horizontally (add more gateway instances)

---

## Best Practices

1. **Separate liveness and readiness**: Don't use `/health` for load balancer checks
2. **Set appropriate thresholds**: Readiness should fail fast, liveness should be patient
3. **Monitor degraded state**: Don't ignore warnings, investigate capacity issues early
4. **Test during deployment**: Verify health checks before going live
5. **Alert on patterns**: Not every degraded state is critical, but sustained degradation is

---

## Comparison: Liveness vs Readiness

| Aspect | Liveness (`/health`) | Readiness (`/readiness`) |
|--------|---------------------|-------------------------|
| **Purpose** | Is process alive? | Can it serve traffic? |
| **Checks** | None (just responds) | Dependencies, capacity |
| **Failure action** | Restart container | Remove from load balancer |
| **Response time** | ~1ms | ~50-150ms (includes CRE check) |
| **When to use** | Kubernetes liveness | Load balancers, readiness |
| **Frequency** | Every 30s | Every 10s |

---

## Example Scenarios

### Scenario 1: Startup
- Liveness: ✓ healthy (server started)
- Readiness: ✗ unhealthy (CRE check pending)
- Action: Not added to load balancer yet

### Scenario 2: Normal Operation
- Liveness: ✓ healthy
- Readiness: ✓ healthy
- Action: Serving traffic normally

### Scenario 3: High Load
- Liveness: ✓ healthy
- Readiness: ⚠ degraded (90% capacity)
- Action: Still serving traffic, alerts sent

### Scenario 4: At Capacity
- Liveness: ✓ healthy
- Readiness: ✗ unhealthy (100% capacity)
- Action: Removed from load balancer, no new requests

### Scenario 5: CRE Gateway Down
- Liveness: ✓ healthy
- Readiness: ⚠ degraded (can't reach CRE)
- Action: Still in rotation, but workflows will fail
