#!/bin/bash
set -e

# Test mode: can be "enabled" (KEYSINUSE_ENABLED=1), "disabled" (=0), or "unset" (default)
TEST_MODE="${1:-all}"

run_test_case() {
    local test_name=$1
    local env_var_value=$2
    
    echo ""
    echo "=========================================="
    echo "Test Case: $test_name"
    echo "=========================================="
    echo ""
    
    # Step 1: Build and install
    echo "=== Step 1: Configuring and building provider ==="
cd /home/jasjivsingh/SymCrypt-OpenSSL/build
SYMCRYPT_DIR="/home/jasjivsingh/SymCrypt"
cmake .. -DKEYSINUSE_ENABLED=1 -DSYMCRYPT_ROOT_DIR=$SYMCRYPT_DIR -DSYMCRYPT_LIBRARY=$SYMCRYPT_DIR/bin/module/generic/libsymcrypt.so 2>&1 | tail -5
make -j$(nproc) 2>&1 | tail -20
echo ""

echo "=== Step 2: Installing provider ==="
sudo install --mode 0644 ./SymCryptProvider/symcryptprovider.so /usr/lib/x86_64-linux-gnu/ossl-modules/
echo "✓ Provider installed"
echo ""

# Step 2: Clean logs
echo "=== Step 3: Cleaning old logs ==="
sudo rm -rf /var/log/keysinuse/
sudo rm -rf /var/log/journal/
sudo mkdir -p /var/log/keysinuse
sudo chmod 1733 /var/log/keysinuse
echo "✓ Logs cleared"
echo ""
echo "Verifying log directory is empty:"
sudo ls -la /var/log/keysinuse/
echo ""

# Step 3: Stop nginx gracefully
echo "=== Step 4: Stopping nginx gracefully ==="
if sudo systemctl is-active --quiet nginx; then
    sudo systemctl stop nginx
    # Wait for nginx to stop (max 5 seconds)
    for i in {1..10}; do
        if ! sudo systemctl is-active --quiet nginx; then
            echo "✓ nginx stopped"
            break
        fi
        sleep 0.5
        echo -n "."
    done
    
    # Force kill if still running
    if sudo systemctl is-active --quiet nginx; then
        echo ""
        echo "⚠ nginx didn't stop gracefully, force killing..."
        sudo systemctl kill nginx
        sleep 1
    fi
else
    echo "✓ nginx already stopped"
fi
echo ""

# Step 4: Configure nginx environment and start
echo "=== Step 5: Configuring and starting nginx ==="

# Create systemd override directory if it doesn't exist
sudo mkdir -p /etc/systemd/system/nginx.service.d/

# Configure environment variable for nginx
if [ "$env_var_value" == "unset" ]; then
    # Remove the override file for unset case
    sudo rm -f /etc/systemd/system/nginx.service.d/keysinuse.conf
    echo "✓ Removed KEYSINUSE_ENABLED override (unset)"
else
    # Create override file with the environment variable
    # We need to override ExecStart completely to pass environment variables
    # because nginx doesn't preserve them by default
    sudo bash -c "cat > /etc/systemd/system/nginx.service.d/keysinuse.conf << EOF
[Service]
Environment=\"KEYSINUSE_ENABLED=$env_var_value\"
# Clear the original ExecStart
ExecStart=
# Add it back with explicit environment variable
ExecStart=/bin/bash -c 'export KEYSINUSE_ENABLED=$env_var_value && exec /usr/sbin/nginx -g \"daemon on; master_process on;\"'
EOF"
    echo "✓ Set KEYSINUSE_ENABLED=$env_var_value in nginx service"
fi

# Reload systemd to pick up changes
sudo systemctl daemon-reload

sudo systemctl start nginx
sleep 2

if sudo systemctl is-active --quiet nginx; then
    echo "✓ nginx started successfully"
else
    echo "✗ nginx failed to start!"
    sudo systemctl status nginx --no-pager | tail -20
    exit 1
fi
echo ""

# Step 5: Check for debug messages
echo "=== Step 6: Checking KeysInUse initialization ==="

# Check if environment variable is set in nginx processes
MASTER_PID=$(pgrep -f "nginx: master" | head -1)
WORKER_PID=$(pgrep -f "nginx: worker" | head -1)

if [ -n "$MASTER_PID" ]; then
    echo "Checking environment variables:"
    echo "  Master PID: $MASTER_PID"
    MASTER_ENV=$(sudo cat /proc/$MASTER_PID/environ | tr '\0' '\n' | grep "KEYSINUSE_ENABLED" || echo "")
    if [ -n "$MASTER_ENV" ]; then
        echo "  Master env: $MASTER_ENV"
    else
        echo "  Master env: KEYSINUSE_ENABLED not set"
    fi
    
    if [ -n "$WORKER_PID" ]; then
        echo "  Worker PID: $WORKER_PID"
        WORKER_ENV=$(sudo cat /proc/$WORKER_PID/environ | tr '\0' '\n' | grep "KEYSINUSE_ENABLED" || echo "")
        if [ -n "$WORKER_ENV" ]; then
            echo "  Worker env: $WORKER_ENV"
        else
            echo "  Worker env: KEYSINUSE_ENABLED not set"
        fi
    fi
fi
echo ""

DEBUG_MSGS=$(sudo journalctl -u nginx --since "2 minutes ago" --no-pager || true)
if [ -n "$DEBUG_MSGS" ]; then
    echo "✓ KeysInUse debug messages found:"
    echo "$DEBUG_MSGS" | head -10
else
    echo "✗ No KeysInUse debug messages found"
fi
echo ""

# Step 6: Make HTTPS requests
echo "=== Step 7: Making HTTPS requests ==="
REQUEST_COUNT=2
for i in $(seq 1 $REQUEST_COUNT); do
    curl -k https://localhost:44330 >/dev/null 2>&1 && echo -n "." || echo -n "x"
done
echo " ($REQUEST_COUNT requests sent)"
echo ""

# Step 7: Wait for logging
echo "=== Step 8: Waiting for logging thread (5 seconds) ==="
sleep 5
echo "✓ Wait complete"
echo ""

# Step 8: Check logs
echo "=== Step 9: Checking KeysInUse logs ==="

# Always check log directory status
echo "Log directory status:"
if [ -d /var/log/keysinuse ]; then
    echo "  Directory exists: /var/log/keysinuse"
    LOG_COUNT=$(sudo find /var/log/keysinuse/ -name "*.log" -type f 2>/dev/null | wc -l)
    echo "  Log files found: $LOG_COUNT"
    
    if [ $LOG_COUNT -gt 0 ]; then
        echo ""
        echo "Log directory contents:"
        sudo ls -lh /var/log/keysinuse/
    fi
else
    echo "  Directory does not exist: /var/log/keysinuse"
fi
echo ""

# Verify expectations based on test case
if [ "$env_var_value" == "0" ]; then
    # For disabled case, we expect NO logs
    NOTICE_LOGS=$(sudo find /var/log/keysinuse/ -name "keysinuse_not_*.log" -type f 2>/dev/null || true)
    if [ -z "$NOTICE_LOGS" ]; then
        echo "✅ TEST PASSED: No KeysInUse logs found (as expected when disabled)"
    else
        echo "❌ TEST FAILED: KeysInUse logs found when it should be disabled!"
    fi
else
    # For enabled cases, we expect logs
    NOTICE_LOGS=$(sudo find /var/log/keysinuse/ -name "keysinuse_not_*.log" -type f 2>/dev/null || true)
    if [ -n "$NOTICE_LOGS" ]; then
        echo "✅ TEST PASSED: KeysInUse logs found (as expected when enabled)"
    else
        echo "❌ TEST FAILED: No KeysInUse logs found when it should be enabled!"
    fi
fi
echo ""

# Always print all log files for all test cases
echo "=== All KeysInUse Log Files ==="
ALL_LOGS=$(sudo find /var/log/keysinuse/ -name "*.log" -type f 2>/dev/null || true)
if [ -n "$ALL_LOGS" ]; then
    for logfile in $ALL_LOGS; do
        BASENAME=$(basename $logfile)
        FILE_SIZE=$(sudo stat -f "%z" "$logfile" 2>/dev/null || sudo stat -c "%s" "$logfile" 2>/dev/null || echo "unknown")
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📄 File: $BASENAME (Size: $FILE_SIZE bytes)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        sudo cat $logfile
        echo ""
    done
else
    echo "  (no log files found)"
fi
echo ""

    echo ""
    echo "=========================================="
    echo "Test Case: $test_name - Complete"
    echo "=========================================="
    
    return 0
}

# Main test execution
echo "=========================================="
echo "KeysInUse + nginx Test Script"
echo "=========================================="
echo ""

if [ "$TEST_MODE" == "all" ]; then
    echo "Running all test cases..."
    echo ""
    
    # Test 1: KEYSINUSE_ENABLED unset (default behavior - should be enabled)
    unset KEYSINUSE_ENABLED
    run_test_case "Default (KEYSINUSE_ENABLED unset)" "unset"
    TEST1_RESULT=$?
    
    # Test 2: KEYSINUSE_ENABLED=1 (explicitly enabled)
    export KEYSINUSE_ENABLED=1
    run_test_case "Explicitly Enabled (KEYSINUSE_ENABLED=1)" "1"
    TEST2_RESULT=$?
    
    # Test 3: KEYSINUSE_ENABLED=0 (disabled - breakglass)
    export KEYSINUSE_ENABLED=0
    run_test_case "Disabled (KEYSINUSE_ENABLED=0)" "0"
    TEST3_RESULT=$?
    
    echo ""
    echo "=========================================="
    echo "All Tests Complete"
    echo "=========================================="
    echo ""
    echo "Summary:"
    echo "  Test 1 (Unset):    $([ $TEST1_RESULT -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
    echo "  Test 2 (Enabled):  $([ $TEST2_RESULT -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
    echo "  Test 3 (Disabled): $([ $TEST3_RESULT -eq 0 ] && echo '✓ PASSED' || echo '✗ FAILED')"
    echo ""
    
    if [ $TEST1_RESULT -eq 0 ] && [ $TEST2_RESULT -eq 0 ] && [ $TEST3_RESULT -eq 0 ]; then
        echo "🎉 All tests PASSED!"
        exit 0
    else
        echo "❌ Some tests FAILED"
        exit 1
    fi
elif [ "$TEST_MODE" == "enabled" ]; then
    export KEYSINUSE_ENABLED=1
    run_test_case "Explicitly Enabled (KEYSINUSE_ENABLED=1)" "1"
elif [ "$TEST_MODE" == "disabled" ]; then
    export KEYSINUSE_ENABLED=0
    run_test_case "Disabled (KEYSINUSE_ENABLED=0)" "0"
elif [ "$TEST_MODE" == "unset" ]; then
    unset KEYSINUSE_ENABLED
    run_test_case "Default (KEYSINUSE_ENABLED unset)" "unset"
else
    echo "Usage: $0 [all|enabled|disabled|unset]"
    echo ""
    echo "  all      - Run all test cases (default)"
    echo "  enabled  - Test with KEYSINUSE_ENABLED=1"
    echo "  disabled - Test with KEYSINUSE_ENABLED=0 (breakglass)"
    echo "  unset    - Test with KEYSINUSE_ENABLED unset (default)"
    exit 1
fi
