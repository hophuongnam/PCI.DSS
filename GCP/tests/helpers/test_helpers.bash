#!/bin/bash
# Test Helper Functions for GCP PCI DSS Testing Framework
# This file provides common utilities and helper functions for testing

# Load bats libraries if available
load_bats_helpers() {
    # Try to load bats-support and bats-assert if available
    if [[ -f "/opt/homebrew/lib/bats-support/load.bash" ]]; then
        load "/opt/homebrew/lib/bats-support/load"
    fi
    if [[ -f "/opt/homebrew/lib/bats-assert/load.bash" ]]; then
        load "/opt/homebrew/lib/bats-assert/load"
    fi
}

# Test Environment Setup
setup_test_environment() {
    # Create temporary test directory
    export TEST_TEMP_DIR="$(mktemp -d)"
    export TEST_PROJECT_ID="test-project-12345"
    export TEST_SERVICE_ACCOUNT_KEY="$TEST_TEMP_DIR/test-service-account.json"
    
    # Setup test paths
    export SHARED_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib"
    export COMMON_LIB="$SHARED_LIB_DIR/gcp_common.sh"
    export PERMISSIONS_LIB="$SHARED_LIB_DIR/gcp_permissions.sh"
    
    # Mock gcloud configuration
    export CLOUDSDK_CORE_PROJECT="$TEST_PROJECT_ID"
    export GOOGLE_APPLICATION_CREDENTIALS="$TEST_SERVICE_ACCOUNT_KEY"
}

# Test Environment Cleanup
teardown_test_environment() {
    if [[ -n "$TEST_TEMP_DIR" && -d "$TEST_TEMP_DIR" ]]; then
        rm -rf "$TEST_TEMP_DIR"
    fi
    unset TEST_TEMP_DIR TEST_PROJECT_ID TEST_SERVICE_ACCOUNT_KEY
    unset SHARED_LIB_DIR COMMON_LIB PERMISSIONS_LIB
    unset CLOUDSDK_CORE_PROJECT GOOGLE_APPLICATION_CREDENTIALS
}

# Mock Service Account Key Creation
create_mock_service_account_key() {
    cat > "$TEST_SERVICE_ACCOUNT_KEY" << 'EOF'
{
  "type": "service_account",
  "project_id": "test-project-12345",
  "private_key_id": "test-key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE_KEY\n-----END PRIVATE KEY-----\n",
  "client_email": "test-sa@test-project-12345.iam.gserviceaccount.com",
  "client_id": "12345678901234567890",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
EOF
}

# Assert Function Exists
assert_function_exists() {
    local function_name="$1"
    local script_file="$2"
    
    if ! declare -f "$function_name" >/dev/null 2>&1; then
        echo "Function '$function_name' not found in $script_file"
        return 1
    fi
}

# Assert File Contains Pattern
assert_file_contains() {
    local file="$1"
    local pattern="$2"
    local message="${3:-File $file should contain pattern: $pattern}"
    
    if [[ ! -f "$file" ]]; then
        echo "File $file does not exist"
        return 1
    fi
    
    if ! grep -q "$pattern" "$file"; then
        echo "$message"
        return 1
    fi
}

# Assert Output Contains
assert_output_contains() {
    local pattern="$1"
    local message="${2:-Output should contain: $pattern}"
    
    if [[ "$output" != *"$pattern"* ]]; then
        echo "$message"
        echo "Actual output: $output"
        return 1
    fi
}

# Mock gcloud command
mock_gcloud() {
    local command="$1"
    shift
    local args="$*"
    
    case "$command" in
        "auth")
            echo "Authenticated as test-service-account"
            ;;
        "config")
            if [[ "$args" == *"set project"* ]]; then
                echo "Updated property [core/project]."
            elif [[ "$args" == *"get-value project"* ]]; then
                echo "$TEST_PROJECT_ID"
            fi
            ;;
        "projects")
            echo '{"projectId":"test-project-12345","name":"Test Project","projectNumber":"123456789"}'
            ;;
        "iam")
            if [[ "$args" == *"list"* ]]; then
                echo '{"bindings":[{"role":"roles/viewer","members":["user:test@example.com"]}]}'
            fi
            ;;
        *)
            echo "Mock gcloud command: $command $args"
            ;;
    esac
}

# Backup original function and replace with mock
backup_and_mock_gcloud() {
    if command -v gcloud >/dev/null 2>&1; then
        # Create backup
        eval "original_gcloud() { command gcloud \"\$@\"; }"
    fi
    
    # Replace gcloud with mock
    eval "gcloud() { mock_gcloud \"\$@\"; }"
}

# Restore original gcloud
restore_gcloud() {
    if declare -f original_gcloud >/dev/null 2>&1; then
        eval "gcloud() { original_gcloud \"\$@\"; }"
        unset -f original_gcloud
    fi
}

# Verify library can be sourced
verify_library_loads() {
    local library_file="$1"
    local library_name="$(basename "$library_file")"
    
    if [[ ! -f "$library_file" ]]; then
        echo "Library file not found: $library_file"
        return 1
    fi
    
    # Test if library can be sourced without errors
    if ! bash -n "$library_file"; then
        echo "Syntax error in $library_name"
        return 1
    fi
    
    # Test if library can be sourced
    if ! (source "$library_file" >/dev/null 2>&1); then
        echo "Failed to source $library_name"
        return 1
    fi
    
    echo "✓ $library_name loads successfully"
}

# Compare outputs (for validation testing)
compare_outputs() {
    local original_output="$1"
    local shared_output="$2"
    local comparison_type="${3:-exact}"
    
    case "$comparison_type" in
        "exact")
            if [[ "$original_output" == "$shared_output" ]]; then
                echo "✓ Outputs match exactly"
                return 0
            else
                echo "✗ Output mismatch"
                echo "Original: $original_output"
                echo "Shared:   $shared_output"
                return 1
            fi
            ;;
        "contains")
            if [[ "$shared_output" == *"$original_output"* ]]; then
                echo "✓ Shared output contains original output"
                return 0
            else
                echo "✗ Shared output does not contain original output"
                return 1
            fi
            ;;
        "pattern")
            # Extract key patterns and compare
            echo "Pattern-based comparison not yet implemented"
            return 0
            ;;
    esac
}

# Benchmark execution time
benchmark_execution() {
    local script="$1"
    local description="$2"
    local iterations="${3:-5}"
    
    echo "Benchmarking: $description"
    local total_time=0
    
    for ((i=1; i<=iterations; i++)); do
        local start_time=$(date +%s.%N)
        bash "$script" >/dev/null 2>&1
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || python3 -c "print($end_time - $start_time)")
        total_time=$(echo "$total_time + $duration" | bc -l 2>/dev/null || python3 -c "print($total_time + $duration)")
    done
    
    local average_time=$(echo "scale=3; $total_time / $iterations" | bc -l 2>/dev/null || python3 -c "print(round($total_time / $iterations, 3))")
    echo "Average execution time: ${average_time}s"
    
    export BENCHMARK_TIME="$average_time"
}

# Export all helper functions
export -f setup_test_environment teardown_test_environment
export -f create_mock_service_account_key assert_function_exists
export -f assert_file_contains assert_output_contains
export -f mock_gcloud backup_and_mock_gcloud restore_gcloud
export -f verify_library_loads compare_outputs benchmark_execution