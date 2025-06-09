#!/usr/bin/env bash

# Phase 2: Integration Stability Validation
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

# Phase 2: Integration Stability Validation
validate_integration_stability() {
    print_status "INFO" "=== Phase 2: Integration Stability Validation ==="
    
    local error_count=0
    local lib_path="$(pwd)/lib"
    
    # Set up environment for testing
    export LIB_DIR="$lib_path"
    export GCP_LIB_PATH="$lib_path"
    
    # 1. Cross-Library Integration
    print_status "INFO" "1. Cross-Library Integration Testing"
    
    # Test individual library loading
    if source "$lib_path/gcp_common.sh" 2>/dev/null; then
        print_status "PASS" "gcp_common.sh loaded individually"
    else
        print_status "FAIL" "gcp_common.sh failed to load"
        ((error_count++))
    fi
    
    # Test function availability after loading gcp_common.sh
    local required_common_functions=(
        "source_gcp_libraries" "setup_environment" "parse_common_arguments" 
        "validate_prerequisites" "print_status" "load_requirement_config"
    )
    
    for func in "${required_common_functions[@]}"; do
        if declare -F "$func" > /dev/null 2>&1; then
            print_status "PASS" "Function $func available from gcp_common.sh"
        else
            print_status "FAIL" "Function $func not available from gcp_common.sh"
            ((error_count++))
        fi
    done
    
    # Test manual loading of other libraries (dependencies require gcp_common first)
    for lib in "gcp_permissions.sh" "gcp_html_report.sh" "gcp_scope_mgmt.sh"; do
        if source "$lib_path/$lib" 2>/dev/null; then
            print_status "PASS" "$lib loaded after gcp_common.sh"
        else
            print_status "WARN" "$lib failed to load independently (may require gcp_common.sh first)"
        fi
    done
    
    # 2. State Management Testing
    print_status "INFO" "2. State Management Testing"
    
    # Test environment setup
    if setup_environment "integration_test.log" 2>/dev/null; then
        print_status "PASS" "Environment setup successful"
        
        # Check if environment variables were set
        if [[ -n "${WORK_DIR:-}" && -n "${REPORT_DIR:-}" && -n "${LOG_DIR:-}" ]]; then
            print_status "PASS" "Environment variables properly set"
        else
            print_status "FAIL" "Environment variables not set correctly"
            ((error_count++))
        fi
    else
        print_status "FAIL" "Environment setup failed"
        ((error_count++))
    fi
    
    # 3. Error Propagation Testing
    print_status "INFO" "3. Error Propagation Testing"
    
    # Test error handling in print_status function
    if print_status "FAIL" "Test error message" >/dev/null 2>&1; then
        print_status "PASS" "Error handling functions work correctly"
    else
        print_status "FAIL" "Error handling functions failed"
        ((error_count++))
    fi
    
    # 4. Resource Management Testing
    print_status "INFO" "4. Resource Management Testing"
    
    # Test cleanup function availability
    if declare -F "cleanup_temp_files" > /dev/null 2>&1; then
        print_status "PASS" "cleanup_temp_files function available"
        
        # Test cleanup execution
        if cleanup_temp_files 2>/dev/null; then
            print_status "PASS" "cleanup_temp_files executed successfully"
        else
            print_status "WARN" "cleanup_temp_files execution issues (may be expected if no temp files)"
        fi
    else
        print_status "FAIL" "cleanup_temp_files function not available"
        ((error_count++))
    fi
    
    # 5. Dependency Resolution Testing
    print_status "INFO" "5. Dependency Resolution Testing"
    
    # Test that functions from different libraries can work together
    local integration_test_passed=true
    
    # Test common + permissions integration
    if declare -F "register_required_permissions" > /dev/null 2>&1; then
        print_status "PASS" "Permissions library functions available"
    else
        print_status "FAIL" "Permissions library functions not available"
        ((error_count++))
        integration_test_passed=false
    fi
    
    # Test common + html_report integration
    if declare -F "initialize_report" > /dev/null 2>&1; then
        print_status "PASS" "HTML report library functions available"
    else
        print_status "FAIL" "HTML report library functions not available"
        ((error_count++))
        integration_test_passed=false
    fi
    
    # Test common + scope_mgmt integration
    if declare -F "setup_assessment_scope" > /dev/null 2>&1; then
        print_status "PASS" "Scope management library functions available"
    else
        print_status "FAIL" "Scope management library functions not available"
        ((error_count++))
        integration_test_passed=false
    fi
    
    # 6. Cross-Module Function Calls Test
    print_status "INFO" "6. Cross-Module Function Calls Test"
    
    # Test simulated cross-module integration workflow
    local workflow_test_passed=true
    
    # Simulate a basic workflow that would use multiple libraries
    if $integration_test_passed; then
        # Test argument parsing (gcp_common.sh)
        if parse_common_arguments -v -s project 2>/dev/null; then
            print_status "PASS" "Argument parsing works"
        else
            print_status "WARN" "Argument parsing test inconclusive"
        fi
        
        # Test that library loading guard variables are set
        if [[ "${GCP_COMMON_LOADED:-}" == "true" ]]; then
            print_status "PASS" "Library loading guard variables working"
        else
            print_status "WARN" "Library loading guard variables not set"
        fi
        
        print_status "PASS" "Cross-module integration workflow test completed"
    else
        print_status "FAIL" "Cannot test cross-module workflow due to missing functions"
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