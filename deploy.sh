#!/usr/bin/env bash
# deploy.sh — Linux/Ubuntu One-Click Automated Deployment Script
set -e

TARGET="${1:-all}"
SERVER_URL="${2:-http://localhost:8000}"

echo "=========================================================="
echo "       JOCKY FORENSIC FRAMEWORK — AUTOMATED DEPLOYMENT    "
echo "=========================================================="

# 1. Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 is not installed."
    exit 1
fi

# 2. Dependencies
echo "[1/3] Verifying and installing dependencies..."
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet -r requirements.txt

# 3. CI Tests
echo "[2/3] Executing CI validation test suite..."
python3 tests/test_pipeline.py
echo "  ✓ All CI validation tests passed successfully."

# 4. Deploy
echo "[3/3] Deploying services (Target: $TARGET)..."

if [ "$TARGET" = "all" ] || [ "$TARGET" = "server" ]; then
    echo "  -> Starting JOCKY Central Management Server on port 8000..."
    nohup python3 backend/server.py > server.log 2>&1 &
    echo "  Server started (PID: $!). Log: server.log"
fi

if [ "$TARGET" = "all" ] || [ "$TARGET" = "agent" ]; then
    echo "  -> Starting JOCKY Target Agent on port 5000..."
    export JOCKY_SERVER_URL="$SERVER_URL"
    nohup python3 agent/agent.py > agent.log 2>&1 &
    echo "  Agent started (PID: $!). Log: agent.log"
fi

echo ""
echo "=========================================================="
echo "  [DEPLOYMENT SUCCESSFUL] All services running!"
echo "  • Management Console : http://localhost:8000"
echo "  • Target Agent       : http://localhost:5000"
echo "  • Frontend Dashboard : frontend/index.html"
echo "=========================================================="
