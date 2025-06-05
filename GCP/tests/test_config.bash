#!/bin/bash
# Test Configuration for GCP PCI DSS Testing Framework
# This file contains configuration settings and setup for all tests

# Test Framework Version
export TEST_FRAMEWORK_VERSION="1.0.0"

# Base Directories
export TEST_BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_ROOT="$(cd "$TEST_BASE_DIR/.." && pwd)"
export SHARED_LIB_DIR="$PROJECT_ROOT/lib"

# Shared Libraries
export COMMON_LIB="$SHARED_LIB_DIR/gcp_common.sh"
export PERMISSIONS_LIB="$SHARED_LIB_DIR/gcp_permissions.sh"

# Test Directories
export UNIT_TEST_DIR="$TEST_BASE_DIR/unit"
export INTEGRATION_TEST_DIR="$TEST_BASE_DIR/integration"
export VALIDATION_TEST_DIR="$TEST_BASE_DIR/validation"
export MOCK_DIR="$TEST_BASE_DIR/mocks"
export HELPERS_DIR="$TEST_BASE_DIR/helpers"

# Helper Scripts
export TEST_HELPERS="$HELPERS_DIR/test_helpers.bash"
export MOCK_HELPERS="$HELPERS_DIR/mock_helpers.bash"
export COVERAGE_HELPERS="$HELPERS_DIR/coverage_helpers.bash"

# Coverage Configuration
export COVERAGE_ENABLED="${COVERAGE_ENABLED:-true}"
export COVERAGE_DIR="$TEST_BASE_DIR/coverage"
export COVERAGE_REPORT_DIR="$COVERAGE_DIR/reports"

# Coverage Targets
export UNIT_TEST_FUNCTION_COVERAGE_TARGET=95
export UNIT_TEST_LINE_COVERAGE_TARGET=90
export INTEGRATION_TEST_COVERAGE_TARGET=85
export VALIDATION_TEST_COVERAGE_TARGET=100
export OVERALL_COVERAGE_TARGET=90

# Test Execution Configuration
export TEST_PARALLEL="${TEST_PARALLEL:-false}"
export TEST_VERBOSE="${TEST_VERBOSE:-false}"
export TEST_TIMEOUT="${TEST_TIMEOUT:-30}"

# Mock Configuration
export MOCK_ENABLED="${MOCK_ENABLED:-true}"
export MOCK_RESPONSE_DELAY="${MOCK_RESPONSE_DELAY:-normal}"

# Test Data Configuration
export TEST_PROJECT_ID="test-project-12345"
export TEST_PROJECT_NUMBER="123456789012"
export TEST_SERVICE_ACCOUNT="test-sa@test-project-12345.iam.gserviceaccount.com"

# GCP Original Scripts (for validation testing)
export ORIGINAL_SCRIPTS_DIR="$PROJECT_ROOT"
export REQUIREMENT_SCRIPTS=(
    "check_gcp_pci_requirement1.sh"
    "check_gcp_pci_requirement2.sh"
    "check_gcp_pci_requirement3.sh"
    "check_gcp_pci_requirement4.sh"
    "check_gcp_pci_requirement5.sh"
    "check_gcp_pci_requirement6.sh"
    "check_gcp_pci_requirement7.sh"
    "check_gcp_pci_requirement8.sh"
)

# Test Output Configuration
export TEST_OUTPUT_DIR="$TEST_BASE_DIR/output"
export TEST_REPORTS_DIR="$TEST_BASE_DIR/reports"
export TEST_LOGS_DIR="$TEST_BASE_DIR/logs"

# Ensure output directories exist
mkdir -p "$TEST_OUTPUT_DIR" "$TEST_REPORTS_DIR" "$TEST_LOGS_DIR"

# Performance Benchmarking Configuration
export BENCHMARK_ENABLED="${BENCHMARK_ENABLED:-true}"
export BENCHMARK_ITERATIONS="${BENCHMARK_ITERATIONS:-5}"
export BENCHMARK_TIMEOUT="${BENCHMARK_TIMEOUT:-60}"

# Test Quality Standards
export REQUIRED_TEST_PASS_RATE=100  # All tests must pass
export REQUIRED_FUNCTION_COVERAGE=95
export REQUIRED_LINE_COVERAGE=90
export REQUIRED_INTEGRATION_COVERAGE=85

# Load Helper Functions
load_test_helpers() {
    local helper_file="$1"
    if [[ -f "$helper_file" ]]; then
        source "$helper_file"
        echo "✓ Loaded $(basename "$helper_file")"
    else
        echo "⚠️  Helper file not found: $helper_file"
        return 1
    fi
}

# Global Test Setup Function
global_test_setup() {
    echo "=== Global Test Setup ==="
    
    # Load all helper functions
    load_test_helpers "$TEST_HELPERS"
    load_test_helpers "$MOCK_HELPERS"
    load_test_helpers "$COVERAGE_HELPERS"
    
    # Setup coverage environment
    if [[ "$COVERAGE_ENABLED" == "true" ]]; then
        setup_coverage_environment
    fi
    
    # Setup mock environment
    if [[ "$MOCK_ENABLED" == "true" ]]; then
        setup_mock_gcp_environment
        create_test_data_sets
    fi
    
    # Verify shared libraries exist
    verify_shared_libraries
    
    echo "✓ Global test setup completed"
}

# Global Test Teardown Function
global_test_teardown() {
    echo "=== Global Test Teardown ==="
    
    # Restore GCP environment
    if [[ "$MOCK_ENABLED" == "true" ]]; then
        restore_gcp_environment
    fi
    
    # Cleanup temporary files
    cleanup_test_environment
    
    echo "✓ Global test teardown completed"
}

# Verify Shared Libraries
verify_shared_libraries() {
    echo "Verifying shared libraries..."
    
    local all_libraries_ok=true
    
    for lib in "$COMMON_LIB" "$PERMISSIONS_LIB"; do
        if [[ -f "$lib" ]]; then
            if verify_library_loads "$lib"; then
                echo "✓ $(basename "$lib") verified"
            else
                echo "✗ $(basename "$lib") failed verification"
                all_libraries_ok=false
            fi
        else
            echo "✗ Library not found: $lib"
            all_libraries_ok=false
        fi
    done
    
    if ! $all_libraries_ok; then
        echo "❌ Shared library verification failed"
        return 1
    fi
    
    echo "✅ All shared libraries verified"
    return 0
}

# Test Environment Information
print_test_environment_info() {
    echo "=== Test Environment Information ==="
    echo "Framework Version: $TEST_FRAMEWORK_VERSION"
    echo "Project Root: $PROJECT_ROOT"
    echo "Test Base Dir: $TEST_BASE_DIR"
    echo "Shared Lib Dir: $SHARED_LIB_DIR"
    echo "Coverage Enabled: $COVERAGE_ENABLED"
    echo "Mock Enabled: $MOCK_ENABLED"
    echo "Test Project ID: $TEST_PROJECT_ID"
    echo "Bats Version: $(bats --version 2>/dev/null || echo 'Not available')"
    echo "Kcov Available: $(command -v kcov >/dev/null && echo 'Yes' || echo 'No')"
    echo "=== End Environment Info ==="
}

# Test Execution Summary
print_test_execution_summary() {
    local test_type="$1"
    local total_tests="$2"
    local passed_tests="$3"
    local failed_tests="$4"
    local coverage_percentage="${5:-N/A}"
    
    echo "=== Test Execution Summary: $test_type ==="
    echo "Total Tests: $total_tests"
    echo "Passed: $passed_tests"
    echo "Failed: $failed_tests"
    echo "Success Rate: $(echo "scale=2; $passed_tests * 100 / $total_tests" | bc -l 2>/dev/null || echo 'N/A')%"
    echo "Coverage: $coverage_percentage%"
    
    if [[ "$failed_tests" -eq 0 ]]; then
        echo "Status: ✅ ALL TESTS PASSED"
    else
        echo "Status: ❌ SOME TESTS FAILED"
    fi
    echo "=== End Summary ==="
}

# Quality Gate Check
quality_gate_check() {
    local test_type="$1"
    local pass_rate="$2"
    local coverage_rate="$3"
    
    local quality_gate_passed=true
    
    echo "=== Quality Gate Check: $test_type ==="
    
    # Check pass rate
    if (( $(echo "$pass_rate < $REQUIRED_TEST_PASS_RATE" | bc -l 2>/dev/null || echo 1) )); then
        echo "❌ Pass rate ($pass_rate%) below required ($REQUIRED_TEST_PASS_RATE%)"
        quality_gate_passed=false
    else
        echo "✅ Pass rate requirement met ($pass_rate%)"
    fi
    
    # Check coverage based on test type
    local required_coverage
    case "$test_type" in
        "unit")
            required_coverage="$REQUIRED_LINE_COVERAGE"
            ;;
        "integration")
            required_coverage="$REQUIRED_INTEGRATION_COVERAGE"
            ;;
        *)
            required_coverage="$OVERALL_COVERAGE_TARGET"
            ;;
    esac
    
    if [[ "$coverage_rate" != "N/A" ]] && (( $(echo "$coverage_rate < $required_coverage" | bc -l 2>/dev/null || echo 1) )); then
        echo "❌ Coverage ($coverage_rate%) below required ($required_coverage%)"
        quality_gate_passed=false
    else
        echo "✅ Coverage requirement met ($coverage_rate%)"
    fi
    
    if $quality_gate_passed; then
        echo "🎉 Quality gate PASSED"
        return 0
    else
        echo "🚫 Quality gate FAILED"
        return 1
    fi
}

# Export configuration functions
export -f load_test_helpers global_test_setup global_test_teardown
export -f verify_shared_libraries print_test_environment_info
export -f print_test_execution_summary quality_gate_check

echo "✓ Test configuration loaded"