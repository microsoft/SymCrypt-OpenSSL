# KeysInUse Environment Variable Design

## Overview

The `KEYSINUSE_ENABLED` environment variable provides a breakglass mechanism to disable KeysInUse at runtime without requiring code changes or recompilation.

## Environment Variable

- **Name**: `KEYSINUSE_ENABLED`
- **Values**:
  - `0` - Disables KeysInUse
  - `1` or any other value - KeysInUse enabled (default)
  - Unset - KeysInUse enabled (default)

## Usage

```bash
# Disable KeysInUse before starting service
export KEYSINUSE_ENABLED=0
systemctl start nginx

# Or via systemd override
echo '[Service]
Environment="KEYSINUSE_ENABLED=0"' > /etc/systemd/system/nginx.service.d/keysinuse.conf
systemctl daemon-reload
systemctl restart nginx
```

## Implementation Details

### Where the Environment Variable is Checked

The environment variable is checked in **two places**:

1. **`keysinuse_init_internal()`** - Parent process initialization
2. **`keysinuse_atfork_reinit()`** - Child process fork handler

### Design Rationale

#### Why Check in Both Places?

While testing (`test_fork_env.c`) demonstrates that child processes inherit the parent's environment at fork time (making the fork handler check technically redundant in typical scenarios), we check in both places for the following reasons:

1. **Consistency**: Both initialization paths explicitly check the environment variable
2. **Defensive Programming**: Protects against future code changes or edge cases
3. **Code Clarity**: Makes it explicit that the env var is respected in both contexts
4. **Minimal Cost**: One `getenv()` + `strcmp()` per fork is negligible overhead
5. **Flexibility**: Future enhancements or custom fork handling are already covered

#### What the Test Program Proves

The `test_fork_env.c` program demonstrates:

- **Test Case 1**: Child inherits parent's env var value
- **Test Case 3**: Parent changes after fork don't affect child
- **Test Case 4**: Child changes don't affect parent
- **Test Case 5**: Both checks (inherited state + env var) always yield same result

**Conclusion**: In normal scenarios, the fork handler check is redundant because:
- Child inherits parent's `keysinuse_enabled` variable state
- Child inherits parent's environment (same `KEYSINUSE_ENABLED` value)
- Both checks always yield the same result

However, we keep both checks for **consistency and defensive programming**.

## Behavior

### Scenario 1: Variable Set Before Service Starts

```bash
export KEYSINUSE_ENABLED=0
systemctl start nginx
```

**Result**: 
- Parent checks env → disabled
- Parent forks workers
- Child inherits disabled state
- Child checks env → disabled (redundant but consistent)
- **KeysInUse disabled in all processes** ✓

### Scenario 2: Variable Changed While Service Running

```bash
systemctl start nginx  # KeysInUse enabled
export KEYSINUSE_ENABLED=0  # Too late! Only affects new processes
systemctl reload nginx
```

**Result**:
- Parent already initialized with KeysInUse enabled
- Parent's environment unchanged (process already running)
- Child inherits parent's enabled state
- Child inherits parent's environment (no "0" value)
- **KeysInUse remains enabled** ✓

**To disable**: Must restart the entire service:
```bash
export KEYSINUSE_ENABLED=0
systemctl restart nginx
```

### Scenario 3: Systemd Override

```bash
echo '[Service]
Environment="KEYSINUSE_ENABLED=0"' > /etc/systemd/system/nginx.service.d/keysinuse.conf
systemctl daemon-reload
systemctl restart nginx
```

**Result**:
- Systemd sets env var before starting nginx
- Same as Scenario 1
- **KeysInUse disabled in all processes** ✓

## Implementation

### Helper Function

```c
// Check if KeysInUse has been disabled via KEYSINUSE_ENABLED environment variable.
static void keysinuse_check_env_disabled()
{
    const char *env_enabled = getenv("KEYSINUSE_ENABLED");
    if (env_enabled != NULL && strcmp(env_enabled, "0") == 0)
    {
        keysinuse_enabled = FALSE;
    }
}
```

### Parent Process Initialization

```c
static void keysinuse_init_internal()
{
    // ...
    
    // Check if KeysInUse has been disabled via environment variable
    keysinuse_check_env_disabled();
    
    if (!keysinuse_enabled)
    {
        return;  // Early exit, don't initialize
    }
    
    // ... rest of initialization
}
```

### Fork Handler

```c
static void keysinuse_atfork_reinit()
{
    // ...
    
    // Check if KeysInUse has been disabled via environment variable.
    // This check is performed for consistency and to ensure the environment
    // variable is respected in the child process initialization path.
    keysinuse_check_env_disabled();
    
    // ... rest of fork handler
}
```

## Testing

### Unit Test

Run `test_fork_env.c` to verify environment variable behavior across fork:

```bash
cd /home/jasjivsingh/SymCrypt-OpenSSL
gcc -o test_fork_env test_fork_env.c
./test_fork_env
```

### Integration Test

Run `test_keysinuse_nginx.sh` to test all three scenarios:

```bash
# Test all cases
./test_keysinuse_nginx.sh all

# Test individual cases
./test_keysinuse_nginx.sh enabled   # KEYSINUSE_ENABLED=1
./test_keysinuse_nginx.sh disabled  # KEYSINUSE_ENABLED=0
./test_keysinuse_nginx.sh unset     # KEYSINUSE_ENABLED unset
```

## Security Considerations

1. **No Privilege Escalation**: Environment variable is read-only, cannot be changed at runtime
2. **Clear Audit Trail**: Setting env var requires systemd config changes (auditable)
3. **Fail-Safe**: If KeysInUse causes issues, can be disabled without code changes
4. **Documented**: Clear documentation of breakglass procedure

## Future Enhancements

Potential improvements:
- Support for `KEYSINUSE_ENABLED=1` to explicitly enable (currently same as unset)
- Support for additional configuration via environment variables
- Runtime signal to enable/disable (more complex, requires careful synchronization)
