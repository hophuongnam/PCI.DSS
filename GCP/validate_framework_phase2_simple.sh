#!/usr/bin/env bash

# Phase 2: Integration Stability Validation (Simplified)
# Part of T06_S02 Complete Framework Validation

set -euo pipefail

# Setup colors and basic variables
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    local level="$1"
    local message="$2"
    local color=""
    local prefix=""
    
    case "$level" in
        "INFO") prefix="[INFO]"; color="$BLUE" ;;
        "PASS") prefix="[PASS]"; color="$GREEN" ;;
        "WARN") prefix="[WARN]"; color="$YELLOW" ;;
        "FAIL") prefix="[FAIL]"; color="$RED" ;;
    esac
    
    echo -e "${color}${prefix}${NC} $message"
}

# Phase 2: Integration Stability Validation (Simplified)
validate_integration_stability() {
    print_status "INFO" "=== Phase 2: Integration Stability Validation ==="
    
    local error_count=0
    local lib_path="$(pwd)/lib"
    
    # 1. Individual Library Loading Test
    print_status "INFO" "1. Individual Library Loading Test"
    
    # Load gcp_common.sh first (required by others)
    if source "$lib_path/gcp_common.sh" 2>/dev/null; then
        print_status "PASS" "gcp_common.sh loaded successfully"
    else
        print_status "FAIL" "gcp_common.sh failed to load"
        ((error_count++))
        return 1
    fi
    
    # Test remaining libraries
    for lib in "gcp_permissions.sh" "gcp_html_report.sh" "gcp_scope_mgmt.sh"; do
        if timeout 5 bash -c "source '$lib_path/$lib'" 2>/dev/null; then
            print_status "PASS" "$lib loaded successfully"
        else
            print_status "FAIL" "$lib failed to load or timed out"
            ((error_count++))
        fi
    done
    
    # 2. Function Availability Test
    print_status "INFO" "2. Function Availability Test"
    
    # Load all libraries in fresh shell and test function availability
    local function_test_result
    function_test_result=$(timeout 10 bash -c "
        source '$lib_path/gcp_common.sh' 2>/dev/null || exit 1
        source '$lib_path/gcp_permissions.sh' 2>/dev/null || exit 1
        source '$lib_path/gcp_html_report.sh' 2>/dev/null || exit 1
        source '$lib_path/gcp_scope_mgmt.sh' 2>/dev/null || exit 1
        
        # Test key functions from each library
        declare -F setup_environment > /dev/null || exit 1
        declare -F print_status > /dev/null || exit 1
        declare -F register_required_permissions > /dev/null || exit 1
        declare -F initialize_report > /dev/null || exit 1
        declare -F setup_assessment_scope > /dev/null || exit 1
        
        echo 'All key functions available'
    " 2>/dev/null) || function_test_result="FAILED"
    
    if [[ "$function_test_result" == "All key functions available" ]]; then
        print_status "PASS" "All key functions available after loading all libraries"
    else
        print_status "FAIL" "Function availability test failed"
        ((error_count++))
    fi
    
    # 3. Basic Integration Test
    print_status "INFO" "3. Basic Integration Test"
    
    # Test that libraries can work together in basic workflow
    local integration_test_result
    integration_test_result=$(timeout 10 bash -c "
        source '$lib_path/gcp_common.sh' 2>/dev/null || exit 1
        source '$lib_path/gcp_permissions.sh' 2>/dev/null || exit 1
        source '$lib_path/gcp_html_report.sh' 2>/dev/null || exit 1
        source '$lib_path/gcp_scope_mgmt.sh' 2>/dev/null || exit 1
        
        # Test basic environment setup
        setup_environment 'test.log' 2>/dev/null || exit 1
        
        # Test that environment variables are set
        [[ -n \"\${WORK_DIR:-}\" ]] || exit 1
        [[ -n \"\${REPORT_DIR:-}\" ]] || exit 1
        [[ -n \"\${LOG_DIR:-}\" ]] || exit 1
        
        echo 'Basic integration successful'
    " 2>/dev/null) || integration_test_result="FAILED"
    
    if [[ "$integration_test_result" == "Basic integration successful" ]]; then
        print_status "PASS" "Basic integration test successful"
    else
        print_status "FAIL" "Basic integration test failed"
        ((error_count++))
    fi
    
    # 4. Library Dependency Test
    print_status "INFO" "4. Library Dependency Test"
    
    # Test that loading order matters (gcp_common must be first)
    local dependency_violations=0
    
    # Test loading gcp_permissions.sh without gcp_common.sh first
    if timeout 3 bash -c "source '$lib_path/gcp_permissions.sh'" 2>/dev/null; then
        print_status "WARN" "gcp_permissions.sh loaded without gcp_common.sh (may indicate missing dependency check)"
    else
        print_status "PASS" "gcp_permissions.sh correctly requires gcp_common.sh to be loaded first"
    fi
    
    # 5. Error Handling Test
    print_status "INFO" "5. Error Handling Test"
    
    # Test that libraries can handle basic error conditions
    local error_handling_result
    error_handling_result=$(timeout 5 bash -c "
        source '$lib_path/gcp_common.sh' 2>/dev/null || exit 1
        
        # Test print_status with different levels
        print_status 'INFO' 'Test info message' >/dev/null 2>&1 || exit 1
        print_status 'PASS' 'Test pass message' >/dev/null 2>&1 || exit 1
        print_status 'WARN' 'Test warn message' >/dev/null 2>&1 || exit 1
        print_status 'FAIL' 'Test fail message' >/dev/null 2>&1 || exit 1
        
        echo 'Error handling test successful'
    " 2>/dev/null) || error_handling_result="FAILED"
    
    if [[ "$error_handling_result" == "Error handling test successful" ]]; then
        print_status "PASS" "Error handling test successful"
    else
        print_status "FAIL" "Error handling test failed"
        ((error_count++))
    fi
    
    # Summary
    print_status "INFO" "=== Phase 2 Summary ==="
    if [[ $error_count -eq 0 ]]; then
        print_status "PASS" "Integration Stability Validation: PASSED"
        return 0
    else
        print_status "FAIL" "Integration Stability Validation: FAILED ($error_count errors)"
        return 1
    fi
}

# Run Phase 2 validation
validate_integration_stability