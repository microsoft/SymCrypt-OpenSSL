#!/bin/bash
# Debug nginx with SymCrypt OpenSSL provider using GDB
# Usage: ./debug_nginx_provider.sh [attach|start|worker|rebuild]

MODE="${1:-attach}"

# Check if provider has debug symbols
check_debug_symbols() {
    PROVIDER_PATH="/home/jasjivsingh/SymCrypt-OpenSSL/build/SymCryptProvider/symcryptprovider.so"
    
    if [ ! -f "$PROVIDER_PATH" ]; then
        echo "⚠️  Provider not found at: $PROVIDER_PATH"
        echo "Run: ./debug_nginx_provider.sh rebuild"
        return 1
    fi
    
    # Check for debug symbols
    if objdump -h "$PROVIDER_PATH" 2>/dev/null | grep -q "\.debug_info"; then
        echo "✅ Provider has full debug symbols (DWARF)"
        return 0
    elif file "$PROVIDER_PATH" | grep -q "not stripped"; then
        echo "⚠️  Provider has basic symbols but NO debug info"
        echo "   - Can set breakpoints by function name"
        echo "   - Cannot step through source or see variables"
        echo ""
        echo "💡 For full debugging, rebuild with debug symbols:"
        echo "   ./debug_nginx_provider.sh rebuild"
        return 2
    else
        echo "❌ Provider is stripped (no symbols)"
        echo "   Run: ./debug_nginx_provider.sh rebuild"
        return 1
    fi
}

# Rebuild with debug symbols
rebuild_with_debug() {
    echo "=========================================="
    echo "Rebuilding with Debug Symbols"
    echo "=========================================="
    echo ""
    
    cd /home/jasjivsingh/SymCrypt-OpenSSL
    
    # Create build directory if needed
    mkdir -p build
    cd build
    
    echo "=== Step 1: Configuring with Debug build type ==="
    cmake -DCMAKE_BUILD_TYPE=Debug ..
    
    echo ""
    echo "=== Step 2: Building with debug symbols ==="
    make -j$(nproc)
    
    echo ""
    echo "=== Step 3: Installing provider ==="
    sudo install --mode 0644 ./SymCryptProvider/symcryptprovider.so /usr/lib/x86_64-linux-gnu/ossl-modules/
    
    echo ""
    echo "=== Verifying debug symbols ==="
    if objdump -h ./SymCryptProvider/symcryptprovider.so | grep -q "\.debug_info"; then
        echo "✅ Success! Provider now has full debug symbols"
        echo ""
        echo "Debug sections found:"
        objdump -h ./SymCryptProvider/symcryptprovider.so | grep "\.debug" | awk '{print "   - " $2}'
    else
        echo "⚠️  Warning: Debug symbols may not be complete"
    fi
    
    echo ""
    echo "=== Ready for debugging ==="
    echo "Run: ./debug_nginx_provider.sh attach"
    return 0
}

# Show GDB symbol loading info
show_gdb_symbol_tips() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📚 GDB Symbol Loading Tips"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "In GDB, use these commands to verify symbols:"
    echo ""
    echo "  info sharedlibrary"
    echo "    └─ Shows all loaded libraries and symbol status"
    echo ""
    echo "  info sharedlibrary symcrypt"
    echo "    └─ Check if symcryptprovider.so symbols loaded"
    echo ""
    echo "  maint info symtabs"
    echo "    └─ List all symbol tables with debug info"
    echo ""
    echo "  set debug-file-directory /home/jasjivsingh/SymCrypt-OpenSSL/build"
    echo "    └─ Set path to debug symbols"
    echo ""
    echo "  directory /home/jasjivsingh/SymCrypt-OpenSSL"
    echo "    └─ Add source code directory"
    echo ""
    echo "If symbols not loaded automatically:"
    echo "  sharedlibrary symcryptprovider"
    echo "    └─ Manually load provider symbols"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

case "$MODE" in
    rebuild)
        rebuild_with_debug
        exit $?
        ;;
        
    attach)
        echo "=== Attaching GDB to nginx worker process ==="
        echo ""
        check_debug_symbols
        SYMBOL_STATUS=$?
        echo ""
        
        WORKER_PID=$(pgrep -f "nginx: worker" | head -1)
        
        if [ -z "$WORKER_PID" ]; then
            echo "❌ Error: No nginx worker process found"
            echo "Start nginx first: sudo systemctl start nginx"
            exit 1
        fi
        
        echo "Found nginx worker PID: $WORKER_PID"
        echo ""
        
        # Check which libraries the worker has loaded
        echo "Libraries loaded by worker:"
        sudo lsof -p "$WORKER_PID" 2>/dev/null | grep -E "symcrypt|ossl-modules" | head -3
        echo ""
        
        show_gdb_symbol_tips
        echo ""
        echo "Suggested GDB commands to try first:"
        echo "  info sharedlibrary symcrypt"
        echo "  directory /home/jasjivsingh/SymCrypt-OpenSSL/SymCryptProvider/src"
        echo "  break scossl_provider_init"
        echo "  break scossl_cipher_encrypt"
        echo "  continue"
        echo ""
        echo "Press Enter to launch GDB..."
        read
        
        # Create GDB init commands
        cat > /tmp/gdb_init_attach.txt <<'EOF'
# Set source directories
directory /home/jasjivsingh/SymCrypt-OpenSSL/SymCryptProvider/src
directory /home/jasjivsingh/SymCrypt-OpenSSL/ScosslCommon/src
directory /home/jasjivsingh/SymCrypt-OpenSSL/KeysInUse

# Try to load symbols
sharedlibrary symcryptprovider
sharedlibrary keysinuse

# Show loaded libraries
echo \n=== Loaded Libraries ===\n
info sharedlibrary symcrypt
info sharedlibrary keysinuse

# Show available functions (if symbols loaded)
echo \n=== Available Functions ===\n
info functions scossl_

echo \n=== Ready to Debug ===\n
echo Type 'break <function>' to set breakpoints\n
echo Type 'continue' to resume execution\n
EOF
        
        sudo gdb -p "$WORKER_PID" -x /tmp/gdb_init_attach.txt
        rm -f /tmp/gdb_init_attach.txt
        ;;
        
    start)
        echo "=== Starting nginx under GDB ==="
        echo ""
        check_debug_symbols
        echo ""
        
        sudo systemctl stop nginx 2>/dev/null || true
        sleep 1
        
        show_gdb_symbol_tips
        echo ""
        echo "GDB will start nginx in single-process mode for easier debugging"
        echo ""
        
        # Create GDB init commands
        cat > /tmp/gdb_init_start.txt <<'EOF'
# Set source directories
directory /home/jasjivsingh/SymCrypt-OpenSSL/SymCryptProvider/src
directory /home/jasjivsingh/SymCrypt-OpenSSL/ScosslCommon/src
directory /home/jasjivsingh/SymCrypt-OpenSSL/KeysInUse

# Enable pending breakpoints for shared libraries
set breakpoint pending on

# Set some common breakpoints
break scossl_provider_init
break scossl_provider_query

echo \n=== Breakpoints Set ===\n
info breakpoints

echo \n=== Starting nginx in single-process mode ===\n
echo Type 'run -g "daemon off; master_process off;"' to start\n
echo Or just type 'run' for normal mode with fork following\n
EOF
        
        sudo gdb -x /tmp/gdb_init_start.txt /usr/sbin/nginx
        rm -f /tmp/gdb_init_start.txt
        ;;
        
    worker)
        echo "=== Debugging worker with fork following ==="
        echo ""
        check_debug_symbols
        echo ""
        
        sudo systemctl stop nginx 2>/dev/null || true
        sleep 1
        
        cat > /tmp/gdb_commands.txt <<'EOF'
# Set source directories
directory /home/jasjivsingh/SymCrypt-OpenSSL/SymCryptProvider/src
directory /home/jasjivsingh/SymCrypt-OpenSSL/ScosslCommon/src
directory /home/jasjivsingh/SymCrypt-OpenSSL/KeysInUse

# Follow child (worker) processes
set follow-fork-mode child
set detach-on-fork off

# Enable pending breakpoints
set breakpoint pending on

# Set breakpoints
break scossl_provider_init
break scossl_provider_query

echo \n=== Breakpoints set, starting nginx ===\n
run -c /etc/nginx/nginx.conf
EOF
        
        echo "Running GDB with automatic fork following..."
        echo ""
        sudo gdb -x /tmp/gdb_commands.txt /usr/sbin/nginx
        rm /tmp/gdb_commands.txt
        ;;
        
    *)
        echo "Usage: $0 [rebuild|attach|start|worker]"
        echo ""
        echo "Modes:"
        echo "  rebuild - Rebuild provider with full debug symbols (do this first!)"
        echo "  attach  - Attach to running nginx worker (default)"
        echo "  start   - Start nginx under GDB in single-process mode"
        echo "  worker  - Start nginx and follow fork to debug worker"
        echo ""
        echo "Recommended workflow:"
        echo "  1. ./debug_nginx_provider.sh rebuild    # Build with debug symbols"
        echo "  2. sudo systemctl start nginx            # Start nginx normally"
        echo "  3. ./debug_nginx_provider.sh attach      # Attach GDB to worker"
        echo ""
        exit 1
        ;;
esac
