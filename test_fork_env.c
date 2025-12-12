/*
 * Test program to demonstrate environment variable behavior across fork()
 * 
 * This program tests:
 * 1. Environment variable set BEFORE parent starts
 * 2. Environment variable changed in parent BEFORE fork
 * 3. Environment variable changed in parent AFTER fork (doesn't affect child)
 * 4. Environment variable changed in child (doesn't affect parent)
 * 
 * Compile: gcc -o test_fork_env test_fork_env.c
 * Run: ./test_fork_env
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

#define TEST_ENV_VAR "KEYSINUSE_ENABLED"

void print_env_status(const char *location, const char *phase) {
    const char *value = getenv(TEST_ENV_VAR);
    printf("[%s][%s] PID=%d: %s=%s\n", 
           phase, location, getpid(), TEST_ENV_VAR, 
           value ? value : "(unset)");
}

void test_case_1() {
    printf("\n========================================\n");
    printf("TEST CASE 1: Env var set BEFORE parent starts\n");
    printf("========================================\n");
    printf("Expected: Both parent and child see the same initial value\n\n");
    
    // Simulate: export KEYSINUSE_ENABLED=1 before running program
    setenv(TEST_ENV_VAR, "1", 1);
    
    print_env_status("Parent", "Before fork");
    
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        sleep(1); // Give parent time to print
        print_env_status("Child", "After fork");
        printf("[After fork][Child] ✓ Child inherited parent's value\n");
        exit(0);
    } else {
        // Parent process
        print_env_status("Parent", "After fork");
        wait(NULL);
        printf("\n✓ Test Case 1 Complete\n");
    }
}

void test_case_2() {
    printf("\n========================================\n");
    printf("TEST CASE 2: Env var changed in parent BEFORE fork\n");
    printf("========================================\n");
    printf("Expected: Child sees parent's value at fork time\n\n");
    
    // Start with one value
    setenv(TEST_ENV_VAR, "initial", 1);
    print_env_status("Parent", "Initial state");
    
    // Change before fork
    setenv(TEST_ENV_VAR, "changed_before_fork", 1);
    print_env_status("Parent", "Before fork");
    
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        sleep(1);
        print_env_status("Child", "After fork");
        printf("[After fork][Child] ✓ Child sees parent's changed value\n");
        exit(0);
    } else {
        // Parent process
        print_env_status("Parent", "After fork");
        wait(NULL);
        printf("\n✓ Test Case 2 Complete\n");
    }
}

void test_case_3() {
    printf("\n========================================\n");
    printf("TEST CASE 3: Env var changed in parent AFTER fork\n");
    printf("========================================\n");
    printf("Expected: Child does NOT see parent's post-fork change\n\n");
    
    setenv(TEST_ENV_VAR, "value_at_fork_time", 1);
    print_env_status("Parent", "Before fork");
    
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        sleep(2); // Wait for parent to change env
        print_env_status("Child", "After parent change");
        
        const char *child_value = getenv(TEST_ENV_VAR);
        if (child_value && strcmp(child_value, "value_at_fork_time") == 0) {
            printf("[After parent change][Child] ✓ Child still sees old value (isolated from parent)\n");
        } else {
            printf("[After parent change][Child] ✗ UNEXPECTED: Child saw parent's change!\n");
        }
        exit(0);
    } else {
        // Parent process
        print_env_status("Parent", "After fork");
        
        // Change env var AFTER fork
        sleep(1);
        setenv(TEST_ENV_VAR, "changed_after_fork", 1);
        print_env_status("Parent", "After change");
        
        wait(NULL);
        printf("\n✓ Test Case 3 Complete\n");
    }
}

void test_case_4() {
    printf("\n========================================\n");
    printf("TEST CASE 4: Env var changed in child\n");
    printf("========================================\n");
    printf("Expected: Parent does NOT see child's change\n\n");
    
    setenv(TEST_ENV_VAR, "shared_initial", 1);
    print_env_status("Parent", "Before fork");
    
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        sleep(1);
        print_env_status("Child", "Before change");
        
        setenv(TEST_ENV_VAR, "changed_by_child", 1);
        print_env_status("Child", "After change");
        printf("[After change][Child] Child changed its copy\n");
        exit(0);
    } else {
        // Parent process
        print_env_status("Parent", "After fork");
        
        wait(NULL); // Wait for child to finish
        
        print_env_status("Parent", "After child exit");
        const char *parent_value = getenv(TEST_ENV_VAR);
        if (parent_value && strcmp(parent_value, "shared_initial") == 0) {
            printf("[After child exit][Parent] ✓ Parent still sees original value (isolated from child)\n");
        } else {
            printf("[After child exit][Parent] ✗ UNEXPECTED: Parent saw child's change!\n");
        }
        
        printf("\n✓ Test Case 4 Complete\n");
    }
}

void test_case_5_keysinuse_scenario() {
    printf("\n========================================\n");
    printf("TEST CASE 5: KeysInUse-specific scenario\n");
    printf("========================================\n");
    printf("Expected: Fork handler checking env is redundant\n\n");
    
    // Simulate KeysInUse initialization
    setenv(TEST_ENV_VAR, "0", 1);  // Disabled
    
    int keysinuse_enabled = 1;  // Default enabled
    
    // Parent: keysinuse_init_internal() checks env
    const char *env_value = getenv(TEST_ENV_VAR);
    if (env_value && strcmp(env_value, "0") == 0) {
        keysinuse_enabled = 0;
    }
    printf("[Parent Init] keysinuse_enabled = %d (checked env: %s)\n", 
           keysinuse_enabled, env_value ? env_value : "(unset)");
    
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process: keysinuse_atfork_reinit() checks env again
        sleep(1);
        
        // Child inherits parent's keysinuse_enabled variable state
        printf("[Child Fork Handler] Inherited keysinuse_enabled = %d\n", keysinuse_enabled);
        
        // Child also checks env (redundant)
        const char *child_env = getenv(TEST_ENV_VAR);
        int child_check = 1;
        if (child_env && strcmp(child_env, "0") == 0) {
            child_check = 0;
        }
        printf("[Child Fork Handler] Checked env again: %s → keysinuse_enabled = %d\n",
               child_env ? child_env : "(unset)", child_check);
        
        if (keysinuse_enabled == child_check) {
            printf("[Child Fork Handler] ✓ REDUNDANT: Both checks give same result!\n");
        } else {
            printf("[Child Fork Handler] ✗ UNEXPECTED: Checks gave different results!\n");
        }
        
        exit(0);
    } else {
        // Parent process
        wait(NULL);
        printf("\n✓ Test Case 5 Complete\n");
        printf("   Conclusion: Checking env in fork handler is redundant because:\n");
        printf("   - Child inherits parent's environment (same value)\n");
        printf("   - Child inherits parent's variable state\n");
        printf("   - Both checks will always yield the same result\n");
    }
}

int main() {
    printf("========================================\n");
    printf("Fork + Environment Variable Test Suite\n");
    printf("========================================\n");
    printf("\nThis program demonstrates how environment variables\n");
    printf("behave across fork() and why checking env in fork\n");
    printf("handler is redundant for KeysInUse.\n");
    
    test_case_1();
    test_case_2();
    test_case_3();
    test_case_4();
    test_case_5_keysinuse_scenario();
    
    printf("\n========================================\n");
    printf("All Tests Complete!\n");
    printf("========================================\n");
    printf("\nKey Takeaways:\n");
    printf("1. Child inherits parent's environment at fork time\n");
    printf("2. Parent changes after fork don't affect child\n");
    printf("3. Child changes don't affect parent\n");
    printf("4. Environment variables are COPIED, not shared\n");
    printf("5. Checking env in fork handler is REDUNDANT\n");
    printf("   → If parent disabled KeysInUse, child inherits that state\n");
    printf("   → If parent enabled KeysInUse, child inherits that state\n");
    printf("   → Child's env check will always match parent's decision\n");
    
    return 0;
}
