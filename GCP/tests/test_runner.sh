#!/bin/bash
# Comprehensive Test Runner for GCP PCI DSS Testing Framework
# This script executes all test types with coverage reporting and quality gates

set -euo pipefail

# Script directory and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test_config.bash"

# Default configuration
RUN_UNIT_TESTS=true
RUN_INTEGRATION_TESTS=true
RUN_VALIDATION_TESTS=true
GENERATE_COVERAGE=true
VERBOSE=false
PARALLEL_EXECUTION=false
QUALITY_GATE_ENABLED=true

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Usage information
usage() {
    cat << EOF
GCP PCI DSS Testing Framework - Test Runner

Usage: $0 [OPTIONS]

Options:
    -u, --unit-only         Run only unit tests
    -i, --integration-only  Run only integration tests
    -v, --validation-only   Run only validation tests
    -c, --no-coverage      Disable coverage generation
    -p, --parallel         Run tests in parallel
    --verbose              Verbose output
    --no-quality-gate      Disable quality gate checks
    -h, --help             Show this help message

Examples:
    $0                     # Run all tests with coverage
    $0 --unit-only         # Run only unit tests
    $0 --parallel          # Run tests in parallel
    $0 --no-coverage       # Run tests without coverage
EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--unit-only)
                RUN_UNIT_TESTS=true
                RUN_INTEGRATION_TESTS=false
                RUN_VALIDATION_TESTS=false
                shift
                ;;
            -i|--integration-only)
                RUN_UNIT_TESTS=false
                RUN_INTEGRATION_TESTS=true
                RUN_VALIDATION_TESTS=false
                shift
                ;;
            -v|--validation-only)
                RUN_UNIT_TESTS=false
                RUN_INTEGRATION_TESTS=false
                RUN_VALIDATION_TESTS=true
                shift
                ;;
            -c|--no-coverage)
                GENERATE_COVERAGE=false
                export COVERAGE_ENABLED=false
                shift
                ;;
            -p|--parallel)
                PARALLEL_EXECUTION=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                export TEST_VERBOSE=true
                shift
                ;;
            --no-quality-gate)
                QUALITY_GATE_ENABLED=false
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test execution functions
run_unit_tests() {
    log_info "Running unit tests..."
    
    local unit_test_files=()
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    # Find all unit test files
    if [[ -d "$UNIT_TEST_DIR" ]]; then
        mapfile -t unit_test_files < <(find "$UNIT_TEST_DIR" -name "*.bats" -type f)
    fi
    
    if [[ ${#unit_test_files[@]} -eq 0 ]]; then
        log_warning "No unit test files found in $UNIT_TEST_DIR"
        return 0
    fi
    
    log_info "Found ${#unit_test_files[@]} unit test files"
    
    # Execute unit tests
    for test_file in "${unit_test_files[@]}"; do
        local test_name="$(basename "$test_file" .bats)"
        log_info "Running unit test: $test_name"
        
        if $GENERATE_COVERAGE; then
            # Run with coverage if enabled
            local coverage_output="$COVERAGE_DIR/unit_$test_name"
            mkdir -p "$coverage_output"
            
            if command -v kcov >/dev/null 2>&1; then
                # Use kcov for coverage
                if kcov --include-path="$SHARED_LIB_DIR" "$coverage_output" bats "$test_file"; then
                    ((passed_tests++))
                    log_success "Unit test passed: $test_name"
                else
                    ((failed_tests++))
                    log_error "Unit test failed: $test_name"
                fi
            else
                # Run without kcov if not available
                if bats "$test_file"; then
                    ((passed_tests++))
                    log_success "Unit test passed: $test_name"
                else
                    ((failed_tests++))
                    log_error "Unit test failed: $test_name"
                fi
            fi
        else
            # Run without coverage
            if bats "$test_file"; then
                ((passed_tests++))
                log_success "Unit test passed: $test_name"
            else
                ((failed_tests++))
                log_error "Unit test failed: $test_name"
            fi
        fi
        
        ((total_tests++))
    done
    
    # Generate coverage report for unit tests
    if $GENERATE_COVERAGE && command -v kcov >/dev/null 2>&1; then
        generate_unit_test_coverage_report
    fi
    
    # Store results for summary
    export UNIT_TOTAL_TESTS=$total_tests
    export UNIT_PASSED_TESTS=$passed_tests
    export UNIT_FAILED_TESTS=$failed_tests
    
    local pass_rate=$(echo "scale=2; $passed_tests * 100 / $total_tests" | bc -l 2>/dev/null || echo "0")
    print_test_execution_summary "Unit Tests" "$total_tests" "$passed_tests" "$failed_tests" "${UNIT_COVERAGE_PERCENTAGE:-N/A}"
    
    return $failed_tests
}

run_integration_tests() {
    log_info "Running integration tests..."
    
    local integration_test_files=()
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    # Find all integration test files
    if [[ -d "$INTEGRATION_TEST_DIR" ]]; then
        mapfile -t integration_test_files < <(find "$INTEGRATION_TEST_DIR" -name "*.bats" -type f)
    fi
    
    if [[ ${#integration_test_files[@]} -eq 0 ]]; then
        log_warning "No integration test files found in $INTEGRATION_TEST_DIR"
        return 0
    fi
    
    log_info "Found ${#integration_test_files[@]} integration test files"
    
    # Execute integration tests
    for test_file in "${integration_test_files[@]}"; do
        local test_name="$(basename "$test_file" .bats)"
        log_info "Running integration test: $test_name"
        
        if bats "$test_file"; then
            ((passed_tests++))
            log_success "Integration test passed: $test_name"
        else
            ((failed_tests++))
            log_error "Integration test failed: $test_name"
        fi
        
        ((total_tests++))
    done
    
    # Store results for summary
    export INTEGRATION_TOTAL_TESTS=$total_tests
    export INTEGRATION_PASSED_TESTS=$passed_tests
    export INTEGRATION_FAILED_TESTS=$failed_tests
    
    print_test_execution_summary "Integration Tests" "$total_tests" "$passed_tests" "$failed_tests"
    
    return $failed_tests
}

run_validation_tests() {
    log_info "Running validation tests..."
    
    local validation_test_files=()
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    # Find all validation test files
    if [[ -d "$VALIDATION_TEST_DIR" ]]; then
        mapfile -t validation_test_files < <(find "$VALIDATION_TEST_DIR" -name "*.bats" -type f)
    fi
    
    if [[ ${#validation_test_files[@]} -eq 0 ]]; then
        log_warning "No validation test files found in $VALIDATION_TEST_DIR"
        return 0
    fi
    
    log_info "Found ${#validation_test_files[@]} validation test files"
    
    # Execute validation tests
    for test_file in "${validation_test_files[@]}"; do
        local test_name="$(basename "$test_file" .bats)"
        log_info "Running validation test: $test_name"
        
        if bats "$test_file"; then
            ((passed_tests++))
            log_success "Validation test passed: $test_name"
        else
            ((failed_tests++))
            log_error "Validation test failed: $test_name"
        fi
        
        ((total_tests++))
    done
    
    # Store results for summary
    export VALIDATION_TOTAL_TESTS=$total_tests
    export VALIDATION_PASSED_TESTS=$passed_tests
    export VALIDATION_FAILED_TESTS=$failed_tests
    
    print_test_execution_summary "Validation Tests" "$total_tests" "$passed_tests" "$failed_tests"
    
    return $failed_tests
}

# Coverage report generation
generate_unit_test_coverage_report() {
    log_info "Generating unit test coverage report..."
    
    # Combine coverage results if multiple test files were run
    local combined_coverage_dir="$COVERAGE_DIR/combined_unit_tests"
    mkdir -p "$combined_coverage_dir"
    
    # This would combine kcov results from all unit tests
    # For now, we'll create a summary report
    
    if [[ -n "${FUNCTION_COVERAGE_PERCENTAGE:-}" && -n "${LINE_COVERAGE_PERCENTAGE:-}" ]]; then
        generate_coverage_report "unit_tests"
        export UNIT_COVERAGE_PERCENTAGE="$LINE_COVERAGE_PERCENTAGE"
    fi
}

# Performance benchmarking
run_performance_benchmarks() {
    if [[ "$BENCHMARK_ENABLED" != "true" ]]; then
        return 0
    fi
    
    log_info "Running performance benchmarks..."
    
    # Benchmark shared libraries vs original scripts
    for script in "${REQUIREMENT_SCRIPTS[@]}"; do
        local original_script="$ORIGINAL_SCRIPTS_DIR/$script"
        if [[ -f "$original_script" ]]; then
            log_info "Benchmarking: $script"
            benchmark_execution "$original_script" "Original $script" "$BENCHMARK_ITERATIONS"
            
            # Store benchmark result
            local benchmark_file="$TEST_OUTPUT_DIR/benchmark_$script.txt"
            echo "Script: $script" > "$benchmark_file"
            echo "Average Time: ${BENCHMARK_TIME}s" >> "$benchmark_file"
            echo "Iterations: $BENCHMARK_ITERATIONS" >> "$benchmark_file"
            echo "Timestamp: $(date)" >> "$benchmark_file"
        fi
    done
}

# Quality gate checks
run_quality_gates() {
    if [[ "$QUALITY_GATE_ENABLED" != "true" ]]; then
        log_info "Quality gates disabled, skipping checks"
        return 0
    fi
    
    log_info "Running quality gate checks..."
    
    local overall_quality_gate_passed=true
    
    # Unit test quality gate
    if [[ "${UNIT_TOTAL_TESTS:-0}" -gt 0 ]]; then
        local unit_pass_rate=$(echo "scale=2; ${UNIT_PASSED_TESTS:-0} * 100 / ${UNIT_TOTAL_TESTS:-1}" | bc -l 2>/dev/null || echo "0")
        if ! quality_gate_check "unit" "$unit_pass_rate" "${UNIT_COVERAGE_PERCENTAGE:-N/A}"; then
            overall_quality_gate_passed=false
        fi
    fi
    
    # Integration test quality gate
    if [[ "${INTEGRATION_TOTAL_TESTS:-0}" -gt 0 ]]; then
        local integration_pass_rate=$(echo "scale=2; ${INTEGRATION_PASSED_TESTS:-0} * 100 / ${INTEGRATION_TOTAL_TESTS:-1}" | bc -l 2>/dev/null || echo "0")
        if ! quality_gate_check "integration" "$integration_pass_rate" "N/A"; then
            overall_quality_gate_passed=false
        fi
    fi
    
    # Validation test quality gate
    if [[ "${VALIDATION_TOTAL_TESTS:-0}" -gt 0 ]]; then
        local validation_pass_rate=$(echo "scale=2; ${VALIDATION_PASSED_TESTS:-0} * 100 / ${VALIDATION_TOTAL_TESTS:-1}" | bc -l 2>/dev/null || echo "0")
        if ! quality_gate_check "validation" "$validation_pass_rate" "N/A"; then
            overall_quality_gate_passed=false
        fi
    fi
    
    if $overall_quality_gate_passed; then
        log_success "All quality gates passed!"
        return 0
    else
        log_error "One or more quality gates failed!"
        return 1
    fi
}

# Generate final test report
generate_final_report() {
    log_info "Generating final test report..."
    
    local report_file="$TEST_REPORTS_DIR/test_execution_report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>GCP PCI DSS Testing Framework - Execution Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin: 15px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; }
        .warning { background-color: #fff3cd; }
        .error { background-color: #f8d7da; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>GCP PCI DSS Testing Framework - Execution Report</h1>
        <p>Generated on: $(date)</p>
        <p>Test Framework Version: $TEST_FRAMEWORK_VERSION</p>
    </div>
    
    <div class="section">
        <h2>Test Summary</h2>
        <table>
            <tr><th>Test Type</th><th>Total</th><th>Passed</th><th>Failed</th><th>Pass Rate</th></tr>
            <tr><td>Unit Tests</td><td>${UNIT_TOTAL_TESTS:-0}</td><td>${UNIT_PASSED_TESTS:-0}</td><td>${UNIT_FAILED_TESTS:-0}</td><td>$(echo "scale=1; ${UNIT_PASSED_TESTS:-0} * 100 / ${UNIT_TOTAL_TESTS:-1}" | bc -l 2>/dev/null || echo "0")%</td></tr>
            <tr><td>Integration Tests</td><td>${INTEGRATION_TOTAL_TESTS:-0}</td><td>${INTEGRATION_PASSED_TESTS:-0}</td><td>${INTEGRATION_FAILED_TESTS:-0}</td><td>$(echo "scale=1; ${INTEGRATION_PASSED_TESTS:-0} * 100 / ${INTEGRATION_TOTAL_TESTS:-1}" | bc -l 2>/dev/null || echo "0")%</td></tr>
            <tr><td>Validation Tests</td><td>${VALIDATION_TOTAL_TESTS:-0}</td><td>${VALIDATION_PASSED_TESTS:-0}</td><td>${VALIDATION_FAILED_TESTS:-0}</td><td>$(echo "scale=1; ${VALIDATION_PASSED_TESTS:-0} * 100 / ${VALIDATION_TOTAL_TESTS:-1}" | bc -l 2>/dev/null || echo "0")%</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Coverage Information</h2>
        <p>Unit Test Coverage: ${UNIT_COVERAGE_PERCENTAGE:-N/A}%</p>
        <p>Coverage Reports: Available in $COVERAGE_REPORT_DIR</p>
    </div>
    
    <div class="section">
        <h2>Quality Gates</h2>
        <p>Status: Quality gate checks $(if $QUALITY_GATE_ENABLED; then echo "enabled"; else echo "disabled"; fi)</p>
    </div>
</body>
</html>
EOF
    
    log_success "Final report generated: $report_file"
}

# Main execution function
main() {
    echo "=================================================================="
    echo "     GCP PCI DSS Testing Framework - Test Runner"
    echo "=================================================================="
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Print environment information
    if $VERBOSE; then
        print_test_environment_info
    fi
    
    # Global setup
    log_info "Performing global test setup..."
    global_test_setup
    
    # Track overall results
    local overall_exit_code=0
    
    # Run tests based on configuration
    if $RUN_UNIT_TESTS; then
        if ! run_unit_tests; then
            overall_exit_code=1
        fi
    fi
    
    if $RUN_INTEGRATION_TESTS; then
        if ! run_integration_tests; then
            overall_exit_code=1
        fi
    fi
    
    if $RUN_VALIDATION_TESTS; then
        if ! run_validation_tests; then
            overall_exit_code=1
        fi
    fi
    
    # Run performance benchmarks
    run_performance_benchmarks
    
    # Run quality gate checks
    if ! run_quality_gates; then
        overall_exit_code=1
    fi
    
    # Generate final report
    generate_final_report
    
    # Global teardown
    log_info "Performing global test teardown..."
    global_test_teardown
    
    # Final status
    echo "=================================================================="
    if [[ $overall_exit_code -eq 0 ]]; then
        log_success "All tests completed successfully!"
    else
        log_error "Some tests failed or quality gates not met!"
    fi
    echo "=================================================================="
    
    exit $overall_exit_code
}

# Run main function with all arguments
main "$@"