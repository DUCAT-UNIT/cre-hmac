# Docker Deployment Guide

## Quick Start

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- `.env` file with required configuration

### 1. Build the Image

```bash
docker build -t ducat-gateway:latest .
```

### 2. Run with Docker Compose

```bash
# Start the gateway
docker-compose up -d

# View logs
docker-compose logs -f gateway

# Stop the gateway
docker-compose down
```

---

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Required
CRE_WORKFLOW_ID=your_workflow_id
DUCAT_AUTHORIZED_KEY=0xyour_address
DUCAT_PRIVATE_KEY=your_private_key
GATEWAY_CALLBACK_URL=https://your-public-url/webhook/ducat

# Optional
LOG_LEVEL=info
LOG_FORMAT=json
MAX_PENDING_REQUESTS=1000
GATEWAY_DB_PATH=/data/gateway.db  # SQLite database for price cache
```

---

## Deployment Options

### Option 1: Simple Deployment (Gateway Only)

```bash
docker-compose up -d
```

**Access**:
- Gateway: http://localhost:8080
- Health: http://localhost:8080/health
- Readiness: http://localhost:8080/readiness
- Metrics: http://localhost:8080/metrics

---

### Option 2: Full Monitoring Stack

Includes: Gateway + Prometheus + Grafana + Alertmanager + cAdvisor

```bash
docker-compose -f docker-compose.monitoring.yml up -d
```

**Access**:
- Gateway: http://localhost:8080
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)
- Alertmanager: http://localhost:9093
- cAdvisor: http://localhost:8081

**Grafana Setup**:
1. Login at http://localhost:3000 (admin/admin)
2. Prometheus datasource is auto-configured
3. Import dashboards from `monitoring/grafana/dashboards/`

---

## Docker Commands

### Build

```bash
# Build image
docker build -t ducat-gateway:latest .

# Build with specific tag
docker build -t ducat-gateway:v1.0.0 .

# Build without cache
docker build --no-cache -t ducat-gateway:latest .
```

### Run

```bash
# Run detached with persistent SQLite
docker run -d \
  --name ducat-gateway \
  -p 8080:8080 \
  -v ducat-data:/data \
  -e GATEWAY_DB_PATH=/data/gateway.db \
  --env-file .env \
  ducat-gateway:latest

# Run with custom port
docker run -d \
  -p 9000:8080 \
  -v ducat-data:/data \
  --env-file .env \
  ducat-gateway:latest

# Run in foreground (see logs)
docker run --rm \
  -p 8080:8080 \
  -v ducat-data:/data \
  --env-file .env \
  ducat-gateway:latest
```

### Logs

```bash
# View logs
docker logs ducat-gateway

# Follow logs
docker logs -f ducat-gateway

# Last 100 lines
docker logs --tail 100 ducat-gateway

# With docker-compose
docker-compose logs -f gateway
```

### Stop/Remove

```bash
# Stop container
docker stop ducat-gateway

# Remove container
docker rm ducat-gateway

# Stop and remove with docker-compose
docker-compose down

# Remove volumes too
docker-compose down -v
```

---

## Image Details

### Multi-Stage Build

The Dockerfile uses a multi-stage build for minimal image size:

1. **Builder stage** (golang:1.23-alpine)
   - Downloads dependencies
   - Compiles binary with static linking

2. **Runtime stage** (alpine:3.19)
   - Minimal base image (~7MB)
   - Only runtime dependencies (ca-certificates, curl)
   - Non-root user (gateway:gateway)
   - Health check included

**Image size**: ~20MB (vs ~1GB+ with full Go image)

### Security Features

- ✅ Non-root user (UID 1000)
- ✅ Minimal attack surface (Alpine + static binary)
- ✅ No shell in final image
- ✅ Read-only filesystem compatible
- ✅ CA certificates for HTTPS
- ✅ Health check built-in

---

## Health Checks

### Docker Health Check

Built into the image:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1
```

### Check Status

```bash
# View health status
docker ps
docker inspect --format='{{.State.Health.Status}}' ducat-gateway

# View health check logs
docker inspect --format='{{json .State.Health}}' ducat-gateway | jq
```

**States**:
- `starting` - Initial startup period
- `healthy` - Health check passing
- `unhealthy` - Health check failing

---

## Kubernetes Deployment

### Basic Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ducat-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ducat-gateway
  template:
    metadata:
      labels:
        app: ducat-gateway
    spec:
      containers:
      - name: gateway
        image: ducat-gateway:latest
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: CRE_WORKFLOW_ID
          valueFrom:
            secretKeyRef:
              name: ducat-secrets
              key: workflow-id
        - name: DUCAT_PRIVATE_KEY
          valueFrom:
            secretKeyRef:
              name: ducat-secrets
              key: private-key
        - name: DUCAT_AUTHORIZED_KEY
          valueFrom:
            secretKeyRef:
              name: ducat-secrets
              key: authorized-key
        - name: GATEWAY_CALLBACK_URL
          value: "https://gateway.example.com/webhook/ducat"
        - name: GATEWAY_DB_PATH
          value: "/data/gateway.db"
        - name: LOG_FORMAT
          value: "json"
        - name: LOG_LEVEL
          value: "info"

        volumeMounts:
        - name: data
          mountPath: /data

      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: ducat-gateway-pvc

        # Resource limits
        resources:
          requests:
            memory: "256Mi"
            cpu: "500m"
          limits:
            memory: "512Mi"
            cpu: "1000m"

        # Probes
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3

        readinessProbe:
          httpGet:
            path: /readiness
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 3

---
apiVersion: v1
kind: Service
metadata:
  name: ducat-gateway
spec:
  selector:
    app: ducat-gateway
  ports:
  - port: 80
    targetPort: 8080
    name: http
  type: LoadBalancer
```

### Create Secrets

```bash
kubectl create secret generic ducat-secrets \
  --from-literal=workflow-id=your_workflow_id \
  --from-literal=private-key=your_private_key \
  --from-literal=authorized-key=0xyour_address
```

---

## Production Recommendations

### 1. Resource Limits

Set appropriate limits based on load:

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "500m"
  limits:
    memory: "512Mi"
    cpu: "1000m"
```

### 2. Horizontal Scaling

**Current limitation**: In-memory state prevents horizontal scaling.

For multi-instance deployment:
- Implement Redis-backed state (see roadmap)
- Use sticky sessions temporarily
- Or run single instance with vertical scaling

### 3. Logging

JSON logging for production:

```yaml
environment:
  - LOG_FORMAT=json
  - LOG_LEVEL=info
```

Ship logs to aggregation service:
- ELK Stack
- Datadog
- CloudWatch
- Loki

### 4. Monitoring

Enable full monitoring stack:

```bash
docker-compose -f docker-compose.monitoring.yml up -d
```

Set up alerts in Alertmanager for:
- Gateway down
- High error rate
- Capacity warnings
- CRE gateway unreachable

### 5. Security

**Secrets management**:
```bash
# Use Docker secrets
docker secret create ducat_private_key ./private_key.txt

# Or Kubernetes secrets
kubectl create secret generic ducat-secrets --from-file=./secrets/
```

**Network security**:
```yaml
# Restrict access
networks:
  gateway_net:
    driver: bridge
    internal: true  # No external access
```

---

## Troubleshooting

### Container won't start

```bash
# Check logs
docker logs ducat-gateway

# Common issues:
# - Missing environment variables
# - Invalid private key
# - Port already in use
```

### Health check failing

```bash
# Check health status
docker inspect --format='{{json .State.Health}}' ducat-gateway | jq

# Test manually
docker exec ducat-gateway curl -f http://localhost:8080/health
```

### Out of memory

```bash
# Check memory usage
docker stats ducat-gateway

# Increase memory limit
docker run -m 1g ducat-gateway:latest
```

### Permission denied

```bash
# Check user
docker exec ducat-gateway id

# Should show: uid=1000(gateway) gid=1000(gateway)
```

---

## Performance Tuning

### 1. Increase capacity

```yaml
environment:
  - MAX_PENDING_REQUESTS=5000
```

### 2. Adjust timeouts

```yaml
environment:
  - BLOCK_TIMEOUT_SECONDS=30  # Shorter timeout
```

### 3. Resource allocation

```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 1G
```

### 4. Cleanup frequency

```yaml
environment:
  - CLEANUP_INTERVAL_SECONDS=60  # More frequent cleanup
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Build and Push Docker Image

on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Login to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: |
            your-org/ducat-gateway:latest
            your-org/ducat-gateway:${{ github.sha }}
```

---

## Maintenance

### Update image

```bash
# Pull latest
docker pull ducat-gateway:latest

# Restart with new image
docker-compose up -d --force-recreate
```

### Backup configuration

```bash
# Backup .env file
cp .env .env.backup

# Backup Prometheus data
docker run --rm -v ducat_prometheus-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/prometheus-backup.tar.gz /data
```

### Clean up

```bash
# Remove unused images
docker image prune -a

# Remove volumes
docker volume prune

# Full cleanup
docker system prune -a --volumes
```

---

## Support

For issues or questions:
1. Check logs: `docker logs ducat-gateway`
2. Verify configuration: `docker exec ducat-gateway env`
3. Test health endpoints manually
4. Check Prometheus metrics at `/metrics`
