# Debug Symbols Guide for SymCrypt OpenSSL Provider

## Understanding Debug Symbols

### Symbol Types

1. **No Symbols (Stripped)**
   - Binary has no function names or debug info
   - `file` output: "stripped"
   - GDB can't show function names or source code

2. **Basic Symbols**
   - Has function names in `.symtab` section
   - `file` output: "not stripped"
   - GDB can set breakpoints by function name
   - ❌ No source code viewing
   - ❌ No variable inspection
   - ❌ No line-by-line stepping

3. **Debug Symbols (DWARF)**
   - Has `.debug_*` sections
   - Includes source file/line mapping
   - ✅ Full source code viewing in GDB
   - ✅ Variable inspection
   - ✅ Line-by-line stepping
   - ✅ Type information

## How to Add Debug Symbols

### Method 1: Use CMAKE_BUILD_TYPE (Recommended)

```bash
# Clean rebuild with debug symbols
cd /home/jasjivsingh/SymCrypt-OpenSSL
./build_debug.sh
```

Or manually:
```bash
cd /home/jasjivsingh/SymCrypt-OpenSSL/build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

**Build Types:**
- `Debug`: `-g3 -O0` (no optimization, max debug info)
- `RelWithDebInfo`: `-g -O2` (optimized + debug symbols)
- `Release`: `-O3` (optimized, no debug by default)

### Method 2: Add Debug Flags Manually

```bash
cd /home/jasjivsingh/SymCrypt-OpenSSL/build
cmake -DCMAKE_C_FLAGS="-g3" -DCMAKE_CXX_FLAGS="-g3" ..
make -j$(nproc)
```

### Method 3: Modify CMakeLists.txt

Already done! The file now has:
```cmake
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -O0 -DDEBUG")
```

## Debug Flag Options

| Flag | Description |
|------|-------------|
| `-g` | Include basic debug information |
| `-g3` | Include macro definitions and extra debug info |
| `-ggdb` | Generate debug info for GDB specifically |
| `-O0` | No optimization (easier to debug) |
| `-O2` | Optimize (harder to debug, variables optimized away) |
| `-fno-omit-frame-pointer` | Keep frame pointer (better backtraces) |

## Verify Debug Symbols

### Check if symbols exist:
```bash
file symcryptprovider.so
# Should say: "not stripped"
```

### Check for debug sections:
```bash
objdump -h symcryptprovider.so | grep debug
# Should show: .debug_info, .debug_line, .debug_str, etc.
```

### Check symbol table:
```bash
nm -D symcryptprovider.so | grep scossl_provider_init
# Should show: function symbols
```

### Detailed debug info:
```bash
readelf -w symcryptprovider.so | head -100
# Shows DWARF debug information
```

## Using Debug Symbols in GDB

### Load Symbols
```gdb
# GDB should auto-load symbols when attaching
# If not, manually load:
sharedlibrary symcryptprovider

# Check if loaded:
info sharedlibrary symcrypt
```

### Set Source Directories
```gdb
# Tell GDB where source files are:
directory /home/jasjivsingh/SymCrypt-OpenSSL/SymCryptProvider/src
directory /home/jasjivsingh/SymCrypt-OpenSSL/ScosslCommon/src
```

### Verify Symbols Loaded
```gdb
# List functions:
info functions scossl_

# Show source for a function:
list scossl_provider_init

# Check debug info:
maint info symtabs
```

## Troubleshooting Symbol Loading

### Problem: GDB says "No debugging symbols found"

**Solution 1:** Check if debug symbols exist
```bash
objdump -h /usr/lib/x86_64-linux-gnu/ossl-modules/symcryptprovider.so | grep debug
```

**Solution 2:** Rebuild with debug symbols
```bash
./build_debug.sh
```

**Solution 3:** Point GDB to build directory
```gdb
set debug-file-directory /home/jasjivsingh/SymCrypt-OpenSSL/build
```

### Problem: "No source file named ..."

**Solution:** Add source directories
```gdb
directory /home/jasjivsingh/SymCrypt-OpenSSL/SymCryptProvider/src
```

### Problem: Variables show "<optimized out>"

**Cause:** Code was compiled with optimization (`-O2`, `-O3`)

**Solution:** Use Debug build type (`-O0`)
```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

## Best Practices

### For Development/Debugging
```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
# Pros: Full debug info, no optimization
# Cons: Slower execution
```

### For Production Debugging
```bash
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
# Pros: Optimized + debug symbols
# Cons: Some variables optimized away
```

### For Production Release
```bash
cmake -DCMAKE_BUILD_TYPE=Release ..
# Then optionally strip:
strip --strip-debug symcryptprovider.so
```

## Quick Reference

| Task | Command |
|------|---------|
| Build with debug | `./build_debug.sh` |
| Check for debug symbols | `objdump -h *.so \| grep debug` |
| Check if stripped | `file *.so` |
| List symbols | `nm -D *.so` |
| Debug with GDB | `./debug_nginx_provider.sh attach` |

## File Sizes Comparison

Typical sizes for the provider:
- **Stripped Release**: ~500KB
- **Release with symbols**: ~1MB
- **Debug**: ~2-3MB (includes debug sections)

The debug sections add overhead but provide invaluable debugging capability.
