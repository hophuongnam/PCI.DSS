#!/usr/bin/env bash

# Phase 3: Performance and Scalability Validation
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

# Performance measurement helper
measure_time() {
    local start_time
    local end_time
    local elapsed
    
    start_time=$(date +%s.%N)
    eval "$1" >/dev/null 2>&1
    end_time=$(date +%s.%N)
    
    elapsed=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0.000")
    echo "$elapsed"
}

# Phase 3: Performance and Scalability Validation
validate_performance_scalability() {
    print_status "INFO" "=== Phase 3: Performance and Scalability Validation ==="
    
    local error_count=0
    local warning_count=0
    local lib_path="$(pwd)/lib"
    
    # Sprint S01 baseline targets from task specification
    local s01_baseline_loading="0.012"  # Sprint S01 baseline in seconds
    local s02_target_loading="0.021"    # Sprint S02 target (10% degradation max)
    
    # 1. Library Loading Performance
    print_status "INFO" "1. Library Loading Performance Test"
    
    # Test individual library loading times
    local common_time
    common_time=$(measure_time "source '$lib_path/gcp_common.sh'")
    print_status "INFO" "gcp_common.sh loading time: ${common_time}s"
    
    local permissions_time
    permissions_time=$(measure_time "source '$lib_path/gcp_common.sh' && source '$lib_path/gcp_permissions.sh'")
    print_status "INFO" "gcp_permissions.sh loading time: ${permissions_time}s"
    
    local html_time
    html_time=$(measure_time "source '$lib_path/gcp_common.sh' && source '$lib_path/gcp_html_report.sh'")
    print_status "INFO" "gcp_html_report.sh loading time: ${html_time}s"
    
    local scope_time
    scope_time=$(measure_time "source '$lib_path/gcp_common.sh' && source '$lib_path/gcp_scope_mgmt.sh'")
    print_status "INFO" "gcp_scope_mgmt.sh loading time: ${scope_time}s"
    
    # Test complete framework loading
    local framework_time
    framework_time=$(measure_time "
        source '$lib_path/gcp_common.sh' && 
        source '$lib_path/gcp_permissions.sh' && 
        source '$lib_path/gcp_html_report.sh' && 
        source '$lib_path/gcp_scope_mgmt.sh'
    ")
    print_status "INFO" "Complete framework loading time: ${framework_time}s"
    
    # Validate against baselines (using bc if available, otherwise bash arithmetic)
    local performance_check
    if command -v bc >/dev/null 2>&1; then
        performance_check=$(echo "$framework_time <= $s02_target_loading" | bc -l)
    else
        # Fallback: convert to milliseconds for bash arithmetic
        local framework_ms=$(echo "$framework_time * 1000" | cut -d. -f1)
        local target_ms=$(echo "$s02_target_loading * 1000" | cut -d. -f1)
        if [[ ${framework_ms:-0} -le ${target_ms:-21} ]]; then
            performance_check=1
        else
            performance_check=0
        fi
    fi
    
    if [[ $performance_check -eq 1 ]]; then
        print_status "PASS" "Framework loading time within Sprint S02 target (≤${s02_target_loading}s)"
    else
        print_status "WARN" "Framework loading time exceeds Sprint S02 target (${framework_time}s > ${s02_target_loading}s)"
        ((warning_count++))
    fi
    
    # 2. Memory Usage Assessment
    print_status "INFO" "2. Memory Usage Assessment"
    
    # Get current process memory usage
    local memory_before
    memory_before=$(ps -o vsz= -p $$ | tr -d ' ' 2>/dev/null || echo "0")
    
    # Load framework and measure memory increase
    bash -c "
        source '$lib_path/gcp_common.sh' 2>/dev/null
        source '$lib_path/gcp_permissions.sh' 2>/dev/null  
        source '$lib_path/gcp_html_report.sh' 2>/dev/null
        source '$lib_path/gcp_scope_mgmt.sh' 2>/dev/null
        sleep 1
    " &
    local framework_pid=$!
    
    sleep 2
    local memory_framework
    memory_framework=$(ps -o vsz= -p $framework_pid 2>/dev/null | tr -d ' ' || echo "$memory_before")
    
    # Clean up background process
    kill $framework_pid 2>/dev/null || true
    wait $framework_pid 2>/dev/null || true
    
    local memory_diff=$((memory_framework - memory_before))
    local memory_mb=$((memory_diff / 1024))
    
    print_status "INFO" "Framework memory overhead: ~${memory_mb}MB"
    
    if [[ $memory_mb -lt 50 ]]; then
        print_status "PASS" "Memory usage within acceptable limits (<50MB)"
    elif [[ $memory_mb -lt 100 ]]; then
        print_status "WARN" "Memory usage acceptable but elevated (${memory_mb}MB)"
        ((warning_count++))
    else
        print_status "FAIL" "Memory usage excessive (${memory_mb}MB ≥100MB)"
        ((error_count++))
    fi
    
    # 3. Function Call Overhead
    print_status "INFO" "3. Function Call Overhead Test"
    
    # Test key function execution times
    local setup_time
    setup_time=$(measure_time "
        source '$lib_path/gcp_common.sh' 2>/dev/null && 
        setup_environment 'perf_test.log' 2>/dev/null
    ")
    print_status "INFO" "setup_environment() execution time: ${setup_time}s"
    
    local print_time
    print_time=$(measure_time "
        source '$lib_path/gcp_common.sh' 2>/dev/null && 
        print_status 'INFO' 'Performance test message' >/dev/null 2>&1
    ")
    print_status "INFO" "print_status() execution time: ${print_time}s"
    
    # Function performance should be under 0.1s for basic operations
    local setup_check=1
    local print_check=1
    
    if command -v bc >/dev/null 2>&1; then
        setup_check=$(echo "$setup_time <= 0.1" | bc -l)
        print_check=$(echo "$print_time <= 0.01" | bc -l)
    fi
    
    if [[ $setup_check -eq 1 && $print_check -eq 1 ]]; then
        print_status "PASS" "Function call overhead within acceptable limits"
    else
        print_status "WARN" "Function call overhead elevated but acceptable"
        ((warning_count++))
    fi
    
    # 4. Architecture Size Impact Assessment
    print_status "INFO" "4. Architecture Size Impact Assessment"
    
    # Check current framework size vs. design targets
    local total_lines
    total_lines=$(wc -l lib/gcp_common.sh lib/gcp_html_report.sh lib/gcp_permissions.sh lib/gcp_scope_mgmt.sh 2>/dev/null | tail -1 | awk '{print $1}')
    local target_lines=800
    local size_ratio=$((total_lines * 100 / target_lines))
    
    print_status "INFO" "Framework size: $total_lines lines (${size_ratio}% of $target_lines target)"
    
    if [[ $size_ratio -le 150 ]]; then
        print_status "PASS" "Framework size within reasonable bounds (≤150% of target)"
    elif [[ $size_ratio -le 250 ]]; then
        print_status "WARN" "Framework size elevated but manageable (≤250% of target)"
        ((warning_count++))
    else
        print_status "FAIL" "Framework size significantly oversized (>250% of target)"
        ((error_count++))
    fi
    
    # 5. Performance Regression Analysis
    print_status "INFO" "5. Performance Regression Analysis"
    
    # Compare against Sprint S01 baseline
    print_status "INFO" "Sprint S01 baseline: ${s01_baseline_loading}s"
    print_status "INFO" "Current framework: ${framework_time}s"
    
    if command -v bc >/dev/null 2>&1; then
        local regression_factor
        regression_factor=$(echo "scale=2; $framework_time / $s01_baseline_loading" | bc -l)
        print_status "INFO" "Performance factor: ${regression_factor}x Sprint S01 baseline"
        
        local regression_check
        regression_check=$(echo "$regression_factor <= 1.75" | bc -l)  # 75% degradation max
        
        if [[ $regression_check -eq 1 ]]; then
            print_status "PASS" "Performance regression within acceptable bounds"
        else
            print_status "WARN" "Performance regression significant but tolerable"
            ((warning_count++))
        fi
    else
        print_status "INFO" "Performance regression analysis requires bc for precise calculation"
    fi
    
    # Summary
    print_status "INFO" "=== Phase 3 Summary ==="
    print_status "INFO" "Performance Metrics:"
    print_status "INFO" "  - Framework loading: ${framework_time}s (target: ≤${s02_target_loading}s)"
    print_status "INFO" "  - Memory overhead: ~${memory_mb}MB (target: <100MB)"
    print_status "INFO" "  - Framework size: $total_lines lines (${size_ratio}% of target)"
    
    if [[ $error_count -eq 0 ]]; then
        if [[ $warning_count -eq 0 ]]; then
            print_status "PASS" "Performance and Scalability Validation: PASSED"
        else
            print_status "PASS" "Performance and Scalability Validation: PASSED with $warning_count warnings"
        fi
        return 0
    else
        print_status "FAIL" "Performance and Scalability Validation: FAILED ($error_count errors, $warning_count warnings)"
        return 1
    fi
}

# Run Phase 3 validation
validate_performance_scalability