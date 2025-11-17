#!/bin/bash
# Test script for blocking gateway server

GATEWAY_URL="http://localhost:8081"

echo "🧪 Testing DUCAT Blocking Gateway"
echo "=================================="
echo ""

# Test 1: CREATE operation
echo "📝 Test 1: CREATE operation (blocks until webhook arrives)"
echo "Request:"
cat <<EOF | tee /tmp/create_request.json
{
  "domain": "sync-test.ducat.xyz",
  "thold_price": 101000.00
}
EOF

echo ""
echo "Sending POST /create..."
START_TIME=$(date +%s)

curl -X POST "$GATEWAY_URL/create" \
  -H "Content-Type: application/json" \
  -d @/tmp/create_request.json \
  -w "\n\nHTTP Status: %{http_code}\nTotal Time: %{time_total}s\n" \
  | jq '.'

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "✅ Request completed in ${DURATION}s"
echo ""
echo "=================================="
echo ""

# Test 2: CHECK operation
echo "🔍 Test 2: CHECK operation (use the hash from Test 1)"
echo ""
read -p "Enter thold_hash from above: " THOLD_HASH

if [ -z "$THOLD_HASH" ]; then
  echo "Skipping CHECK test"
  exit 0
fi

cat <<EOF | tee /tmp/check_request.json
{
  "domain": "sync-test.ducat.xyz",
  "thold_hash": "$THOLD_HASH"
}
EOF

echo ""
echo "Sending POST /check..."
START_TIME=$(date +%s)

curl -X POST "$GATEWAY_URL/check" \
  -H "Content-Type: application/json" \
  -d @/tmp/check_request.json \
  -w "\n\nHTTP Status: %{http_code}\nTotal Time: %{time_total}s\n" \
  | jq '.'

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "✅ Request completed in ${DURATION}s"
