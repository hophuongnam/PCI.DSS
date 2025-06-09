#!/usr/bin/env bash

# Phase 1: Framework Completeness Assessment
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

# Phase 1: Framework Completeness Assessment
validate_framework_completeness() {
    print_status "INFO" "=== Phase 1: Framework Completeness Assessment ==="
    
    local error_count=0
    local lib_path="$(pwd)/lib"
    
    # 1. Library Implementation Verification
    print_status "INFO" "1. Library Implementation Verification"
    
    local required_libs=(
        "gcp_common.sh"
        "gcp_html_report.sh"
        "gcp_permissions.sh"
        "gcp_scope_mgmt.sh"
    )
    
    for lib in "${required_libs[@]}"; do
        if [[ -f "$lib_path/$lib" ]]; then
            local line_count=$(wc -l < "$lib_path/$lib")
            print_status "PASS" "Library $lib exists ($line_count lines)"
        else
            print_status "FAIL" "Library $lib not found"
            ((error_count++))
        fi
    done
    
    # 2. Function Inventory Audit
    print_status "INFO" "2. Function Inventory Audit"
    
    # Test function availability from each library
    local total_functions=0
    
    # gcp_common.sh functions (expected: 11)
    local common_functions=$(grep -c "^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*()[[:space:]]*{" "$lib_path/gcp_common.sh")
    total_functions=$((total_functions + common_functions))
    print_status "PASS" "gcp_common.sh: $common_functions functions"
    
    # gcp_permissions.sh functions (expected: 5)
    local permissions_functions=$(grep -c "^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*()[[:space:]]*{" "$lib_path/gcp_permissions.sh")
    total_functions=$((total_functions + permissions_functions))
    print_status "PASS" "gcp_permissions.sh: $permissions_functions functions"
    
    # gcp_html_report.sh functions (expected: 5-11)
    local html_functions=$(grep -c "^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*()[[:space:]]*{" "$lib_path/gcp_html_report.sh")
    total_functions=$((total_functions + html_functions))
    print_status "PASS" "gcp_html_report.sh: $html_functions functions"
    
    # gcp_scope_mgmt.sh functions (expected: 5)
    local scope_functions=$(grep -c "^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*()[[:space:]]*{" "$lib_path/gcp_scope_mgmt.sh")
    total_functions=$((total_functions + scope_functions))
    print_status "PASS" "gcp_scope_mgmt.sh: $scope_functions functions"
    
    print_status "INFO" "Total functions discovered: $total_functions (required: 21)"
    
    if [[ $total_functions -ge 21 ]]; then
        print_status "PASS" "Function inventory meets requirements"
    else
        print_status "FAIL" "Function inventory below requirements"
        ((error_count++))
    fi
    
    # 3. API Consistency Check (basic syntax validation)
    print_status "INFO" "3. API Consistency Check"
    
    for lib in "${required_libs[@]}"; do
        if bash -n "$lib_path/$lib" 2>/dev/null; then
            print_status "PASS" "$lib: Syntax validation passed"
        else
            print_status "FAIL" "$lib: Syntax validation failed"
            ((error_count++))
        fi
    done
    
    # 4. Documentation Completeness
    print_status "INFO" "4. Documentation Completeness"
    
    local doc_files=(
        "README_GCP_SCOPE.md"
        "README_HTML_REPORT.md"
        "README_PERMISSIONS.md"
        "README_SCOPE_MGMT.md"
        "README_COMPLETE_API.md"
    )
    
    for doc in "${doc_files[@]}"; do
        if [[ -f "$lib_path/$doc" ]]; then
            print_status "PASS" "Documentation $doc exists"
        else
            print_status "WARN" "Documentation $doc missing"
        fi
    done
    
    # 5. Architecture Compliance Check
    print_status "INFO" "5. Architecture Compliance Check"
    
    declare -A expected_lines=(
        ["gcp_common.sh"]=200
        ["gcp_html_report.sh"]=300  
        ["gcp_permissions.sh"]=150
        ["gcp_scope_mgmt.sh"]=150
    )
    
    local total_actual=0
    local total_expected=800
    
    for library in "${!expected_lines[@]}"; do
        local actual_lines=$(wc -l < "$lib_path/$library" 2>/dev/null || echo 0)
        local expected=${expected_lines[$library]}
        local percentage=$((actual_lines * 100 / expected))
        total_actual=$((total_actual + actual_lines))
        
        if [[ $percentage -le 110 && $percentage -ge 90 ]]; then
            print_status "PASS" "$library: $actual_lines lines (${percentage}% of target $expected)"
        elif [[ $percentage -gt 110 ]]; then
            print_status "WARN" "$library: $actual_lines lines (${percentage}% of target $expected) - OVERSIZED"
        else
            print_status "WARN" "$library: $actual_lines lines (${percentage}% of target $expected) - UNDERSIZED"
        fi
    done
    
    local total_percentage=$((total_actual * 100 / total_expected))
    print_status "INFO" "Total framework size: $total_actual lines (${total_percentage}% of target $total_expected)"
    
    # Summary
    print_status "INFO" "=== Phase 1 Summary ==="
    if [[ $error_count -eq 0 ]]; then
        print_status "PASS" "Framework Completeness Assessment: PASSED"
        return 0
    else
        print_status "FAIL" "Framework Completeness Assessment: FAILED ($error_count errors)"
        return 1
    fi
}

# Run Phase 1 validation
validate_framework_completeness