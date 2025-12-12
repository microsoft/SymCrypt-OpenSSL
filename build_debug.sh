#!/bin/bash
# Build SymCrypt OpenSSL Provider with Debug Symbols
# This script builds the provider with full DWARF debug information for GDB

set -e

echo "=========================================="
echo "Building with Debug Symbols"
echo "=========================================="
echo ""

cd "$(dirname "$0")"

# Option 1: Use the build directory with Debug type
echo "=== Building in Debug mode ==="
mkdir -p build
cd build

# Configure with Debug build type
# This adds -g flag automatically and disables optimization
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Build
echo ""
echo "=== Compiling ==="
make -j$(nproc)

# Verify debug symbols
echo ""
echo "=== Verifying Debug Symbols ==="
PROVIDER_PATH="./SymCryptProvider/symcryptprovider.so"

if [ -f "$PROVIDER_PATH" ]; then
    echo "Provider built at: $PROVIDER_PATH"
    echo ""
    
    # Check file type
    file "$PROVIDER_PATH"
    echo ""
    
    # Check for debug sections
    echo "Debug sections:"
    if objdump -h "$PROVIDER_PATH" | grep -E "\.debug"; then
        objdump -h "$PROVIDER_PATH" | grep -E "\.debug" | awk '{print "  ✅ " $2 " (size: " $3 ")"}'
        echo ""
        echo "🎉 SUCCESS! Provider has full debug symbols (DWARF)"
    else
        echo "  ⚠️  No debug sections found"
        echo ""
        echo "Checking basic symbols..."
        if file "$PROVIDER_PATH" | grep -q "not stripped"; then
            echo "  ℹ️  Provider has basic symbols but no debug info"
        else
            echo "  ❌ Provider is stripped"
        fi
    fi
    
    echo ""
    echo "=== Installing Provider ==="
    sudo install --mode 0644 "$PROVIDER_PATH" /usr/lib/x86_64-linux-gnu/ossl-modules/
    echo "✅ Installed to: /usr/lib/x86_64-linux-gnu/ossl-modules/symcryptprovider.so"
    
    echo ""
    echo "=== Ready for Debugging ==="
    echo "Now you can:"
    echo "  1. sudo systemctl restart nginx"
    echo "  2. ./debug_nginx_provider.sh attach"
else
    echo "❌ Provider not found at: $PROVIDER_PATH"
    exit 1
fi

echo ""
echo "=========================================="
echo "Build Complete"
echo "=========================================="
