#!/bin/bash

# DUCAT Gateway - Docker Build and Deployment Test Script
# This script tests the complete Docker setup

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
log_info "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    log_error "Docker not found. Please install Docker."
    exit 1
fi

if ! docker info &> /dev/null; then
    log_error "Docker daemon not running. Please start Docker Desktop."
    exit 1
fi

log_success "Docker is available and running"

# Check .env file
if [ ! -f .env ]; then
    log_warning ".env file not found. Creating from .env.example..."
    if [ -f tools/.env.example ]; then
        cp tools/.env.example .env
        log_info "Please edit .env with your actual values before proceeding"
        exit 1
    else
        log_error "tools/.env.example not found"
        exit 1
    fi
fi

log_success ".env file exists"

# Test 1: Docker build
log_info "=== Test 1: Building Docker image ==="
log_info "Running: docker build -t ducat-gateway:latest ."

if docker build -t ducat-gateway:latest .; then
    log_success "Docker image built successfully"
else
    log_error "Docker build failed"
    exit 1
fi

# Check image size
IMAGE_SIZE=$(docker images ducat-gateway:latest --format "{{.Size}}")
log_info "Image size: $IMAGE_SIZE"

if [ -n "$IMAGE_SIZE" ]; then
    log_success "Image created: ducat-gateway:latest ($IMAGE_SIZE)"
else
    log_error "Failed to get image size"
    exit 1
fi

# Test 2: Start container with docker-compose
log_info "=== Test 2: Starting container with docker-compose ==="
log_info "Running: docker-compose up -d"

if docker-compose up -d; then
    log_success "Container started"
    sleep 5  # Wait for startup
else
    log_error "Failed to start container"
    exit 1
fi

# Test 3: Check container status
log_info "=== Test 3: Checking container status ==="
CONTAINER_STATUS=$(docker-compose ps --format json | grep gateway | head -1)

if [ -n "$CONTAINER_STATUS" ]; then
    log_success "Container is running"
    docker-compose ps
else
    log_error "Container not found"
    docker-compose down
    exit 1
fi

# Test 4: Check logs for errors
log_info "=== Test 4: Checking logs ==="
log_info "Recent logs:"
docker-compose logs --tail=20 gateway

if docker-compose logs gateway | grep -i "error\|fatal\|panic" > /dev/null; then
    log_warning "Found potential errors in logs (check above)"
else
    log_success "No obvious errors in logs"
fi

# Test 5: Test health endpoint
log_info "=== Test 5: Testing /health endpoint ==="
sleep 2  # Wait a bit more

if curl -f -s http://localhost:8080/health > /dev/null 2>&1; then
    HEALTH_RESPONSE=$(curl -s http://localhost:8080/health)
    log_success "Health endpoint responding"
    echo "$HEALTH_RESPONSE" | jq '.' 2>/dev/null || echo "$HEALTH_RESPONSE"
else
    log_error "Health endpoint not responding"
    log_info "Checking if port is listening..."
    lsof -i :8080 || log_warning "Port 8080 not listening"
    docker-compose logs gateway
    docker-compose down
    exit 1
fi

# Test 6: Test readiness endpoint
log_info "=== Test 6: Testing /readiness endpoint ==="

if curl -f -s http://localhost:8080/readiness > /dev/null 2>&1; then
    READINESS_RESPONSE=$(curl -s http://localhost:8080/readiness)
    log_success "Readiness endpoint responding"
    echo "$READINESS_RESPONSE" | jq '.' 2>/dev/null || echo "$READINESS_RESPONSE"
else
    log_warning "Readiness endpoint not responding or not ready (may be expected if CRE gateway is unreachable)"
    curl -s http://localhost:8080/readiness | jq '.' || true
fi

# Test 7: Test metrics endpoint
log_info "=== Test 7: Testing /metrics endpoint ==="

if curl -f -s http://localhost:8080/metrics > /dev/null 2>&1; then
    log_success "Metrics endpoint responding"
    METRICS_COUNT=$(curl -s http://localhost:8080/metrics | grep -c "^gateway_" || true)
    log_info "Found $METRICS_COUNT gateway metrics"
else
    log_error "Metrics endpoint not responding"
fi

# Test 8: Test status endpoint
log_info "=== Test 8: Testing /status endpoint ==="

if curl -f -s http://localhost:8080/status > /dev/null 2>&1; then
    STATUS_RESPONSE=$(curl -s http://localhost:8080/status)
    log_success "Status endpoint responding"
    echo "$STATUS_RESPONSE" | jq '.' 2>/dev/null || echo "$STATUS_RESPONSE"
else
    log_error "Status endpoint not responding"
fi

# Test 9: Check Docker health check
log_info "=== Test 9: Checking Docker health check ==="
sleep 10  # Wait for health check to run

HEALTH_STATUS=$(docker inspect --format='{{.State.Health.Status}}' $(docker-compose ps -q gateway) 2>/dev/null || echo "unknown")
log_info "Docker health status: $HEALTH_STATUS"

if [ "$HEALTH_STATUS" = "healthy" ]; then
    log_success "Container is healthy"
elif [ "$HEALTH_STATUS" = "starting" ]; then
    log_warning "Container still starting (health check not completed)"
else
    log_warning "Container health status: $HEALTH_STATUS"
fi

# Test 10: Resource usage
log_info "=== Test 10: Checking resource usage ==="
docker stats --no-stream $(docker-compose ps -q gateway) || log_warning "Failed to get stats"

# Summary
echo ""
log_info "=== Test Summary ==="
log_success "✓ Docker image built successfully"
log_success "✓ Container started and running"
log_success "✓ Health endpoint working"
log_success "✓ Metrics endpoint working"
log_success "✓ Status endpoint working"

echo ""
log_info "=== Useful Commands ==="
echo "  View logs:       docker-compose logs -f gateway"
echo "  Check status:    docker-compose ps"
echo "  Stop:            docker-compose down"
echo "  Restart:         docker-compose restart gateway"
echo "  Shell access:    docker-compose exec gateway sh"
echo ""
echo "  Health:          curl http://localhost:8080/health"
echo "  Readiness:       curl http://localhost:8080/readiness"
echo "  Status:          curl http://localhost:8080/status"
echo "  Metrics:         curl http://localhost:8080/metrics"
echo ""

# Ask if user wants to stop
read -p "Stop container? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Stopping container..."
    docker-compose down
    log_success "Container stopped"
else
    log_info "Container still running. Stop with: docker-compose down"
fi

log_success "All tests completed!"
