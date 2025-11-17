#!/bin/bash

# Test script for health check endpoints

echo "========================================="
echo "Testing Gateway Server Health Checks"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

BASE_URL="${1:-http://localhost:8080}"

echo "Base URL: $BASE_URL"
echo ""

# Test 1: Liveness probe
echo -e "${YELLOW}Test 1: Liveness Probe (GET /health)${NC}"
echo "-------------------------------------"
response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$BASE_URL/health")
http_code=$(echo "$response" | grep "HTTP_STATUS" | cut -d: -f2)
body=$(echo "$response" | sed '/HTTP_STATUS/d')

if [ "$http_code" = "200" ]; then
    echo -e "${GREEN}✓ Status: $http_code (OK)${NC}"
else
    echo -e "${RED}✗ Status: $http_code (FAILED)${NC}"
fi

echo "Response:"
echo "$body" | jq '.' 2>/dev/null || echo "$body"
echo ""

# Test 2: Readiness probe
echo -e "${YELLOW}Test 2: Readiness Probe (GET /readiness)${NC}"
echo "-------------------------------------"
response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$BASE_URL/readiness")
http_code=$(echo "$response" | grep "HTTP_STATUS" | cut -d: -f2)
body=$(echo "$response" | sed '/HTTP_STATUS/d')

if [ "$http_code" = "200" ]; then
    echo -e "${GREEN}✓ Status: $http_code (Ready)${NC}"
elif [ "$http_code" = "503" ]; then
    echo -e "${RED}✗ Status: $http_code (Not Ready)${NC}"
else
    echo -e "${YELLOW}⚠ Status: $http_code${NC}"
fi

echo "Response:"
echo "$body" | jq '.' 2>/dev/null || echo "$body"
echo ""

# Test 3: Check specific dependencies
echo -e "${YELLOW}Test 3: Dependency Status Details${NC}"
echo "-------------------------------------"
dependencies=$(echo "$body" | jq -r '.dependencies | keys[]' 2>/dev/null)

if [ -n "$dependencies" ]; then
    for dep in $dependencies; do
        status=$(echo "$body" | jq -r ".dependencies.$dep.status" 2>/dev/null)
        message=$(echo "$body" | jq -r ".dependencies.$dep.message" 2>/dev/null)
        latency=$(echo "$body" | jq -r ".dependencies.$dep.latency // empty" 2>/dev/null)

        case "$status" in
            "up")
                color=$GREEN
                symbol="✓"
                ;;
            "degraded")
                color=$YELLOW
                symbol="⚠"
                ;;
            "down")
                color=$RED
                symbol="✗"
                ;;
            *)
                color=$NC
                symbol="?"
                ;;
        esac

        echo -e "${color}${symbol} ${dep}: ${status}${NC}"
        [ -n "$message" ] && echo "  Message: $message"
        [ -n "$latency" ] && echo "  Latency: $latency"
    done
else
    echo "No dependency information available"
fi
echo ""

# Test 4: Capacity metrics
echo -e "${YELLOW}Test 4: Capacity Metrics${NC}"
echo "-------------------------------------"
pending=$(echo "$body" | jq -r '.metrics.pending_requests' 2>/dev/null)
max_pending=$(echo "$body" | jq -r '.metrics.max_pending' 2>/dev/null)
capacity_used=$(echo "$body" | jq -r '.metrics.capacity_used_percent' 2>/dev/null)

if [ -n "$pending" ] && [ -n "$max_pending" ]; then
    echo "Pending Requests: $pending / $max_pending"
    echo "Capacity Used: ${capacity_used}%"

    if (( $(echo "$capacity_used >= 90" | bc -l) )); then
        echo -e "${RED}⚠ WARNING: Capacity near limit!${NC}"
    elif (( $(echo "$capacity_used >= 70" | bc -l) )); then
        echo -e "${YELLOW}⚠ Capacity at 70%${NC}"
    else
        echo -e "${GREEN}✓ Capacity OK${NC}"
    fi
else
    echo "No capacity information available"
fi
echo ""

# Test 5: Prometheus metrics
echo -e "${YELLOW}Test 5: Prometheus Metrics Sample${NC}"
echo "-------------------------------------"
metrics=$(curl -s "$BASE_URL/metrics" 2>/dev/null)

if [ -n "$metrics" ]; then
    echo "Health check metrics:"
    echo "$metrics" | grep "gateway_health_checks_total" || echo "  (no health check metrics yet)"
    echo ""
    echo "Dependency status metrics:"
    echo "$metrics" | grep "gateway_dependency_status" || echo "  (no dependency metrics yet)"
    echo ""
    echo "Full metrics available at: $BASE_URL/metrics"
else
    echo -e "${RED}✗ Could not fetch metrics${NC}"
fi
echo ""

echo "========================================="
echo "Health Check Tests Complete"
echo "========================================="
