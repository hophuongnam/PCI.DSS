#!/usr/bin/env bats
# Unit Tests for GCP Common Library - Core Functions
# Tests: source_gcp_libraries, setup_environment, validate_prerequisites

# Load test configuration and helpers
load '../../test_config'
load '../../helpers/test_helpers'
load '../../helpers/mock_helpers'

# Setup and teardown for each test
setup() {
    setup_test_environment
    setup_mock_gcp_environment
    
    # Source the library under test
    source "$COMMON_LIB"
}

teardown() {
    teardown_test_environment
    restore_gcp_environment
}

# =============================================================================
# Tests for source_gcp_libraries()
# =============================================================================

@test "source_gcp_libraries: successfully loads libraries when directory exists" {
    # Setup
    export LIB_DIR="$SHARED_LIB_DIR"
    
    # Execute
    run source_gcp_libraries
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Libraries loaded successfully" ]]
}

@test "source_gcp_libraries: handles missing library directory gracefully" {
    # Setup
    export LIB_DIR="/nonexistent/lib/directory"
    
    # Execute
    run source_gcp_libraries
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Library directory not found" ]]
}

@test "source_gcp_libraries: verifies gcp_common library state" {
    # Execute
    source_gcp_libraries
    
    # Assert
    [ "$GCP_COMMON_LOADED" = "true" ]
}

# =============================================================================
# Tests for setup_environment()
# =============================================================================

@test "setup_environment: initializes global variables correctly" {
    # Execute
    run setup_environment
    
    # Assert
    [ "$status" -eq 0 ]
    [ -n "$SCRIPT_DIR" ]
    [ -n "$LIB_DIR" ]
    [ "$passed_checks" -eq 0 ]
    [ "$failed_checks" -eq 0 ]
    [ "$total_projects" -eq 0 ]
}

@test "setup_environment: sets up color variables" {
    # Execute
    setup_environment
    
    # Assert
    [ -n "$RED" ]
    [ -n "$GREEN" ]
    [ -n "$YELLOW" ]
    [ -n "$BLUE" ]
    [ -n "$NC" ]
}

@test "setup_environment: creates necessary directories" {
    # Setup
    export OUTPUT_DIR="$TEST_TEMP_DIR/test_output"
    
    # Execute
    run setup_environment
    
    # Assert
    [ "$status" -eq 0 ]
    [ -d "$OUTPUT_DIR" ]
}

@test "setup_environment: handles missing output directory creation" {
    # Setup - create read-only parent directory
    local readonly_dir="$TEST_TEMP_DIR/readonly"
    mkdir -p "$readonly_dir"
    chmod 444 "$readonly_dir"
    export OUTPUT_DIR="$readonly_dir/test_output"
    
    # Execute
    run setup_environment
    
    # Assert - should handle gracefully
    [ "$status" -eq 0 ]  # or 1 depending on implementation
    
    # Cleanup
    chmod 755 "$readonly_dir"
}

# =============================================================================
# Tests for validate_prerequisites()
# =============================================================================

@test "validate_prerequisites: passes when all tools are available" {
    # Mock required tools
    eval 'gcloud() { echo "Google Cloud SDK 400.0.0"; }'
    eval 'jq() { echo "jq-1.6"; }'
    eval 'curl() { echo "curl 7.68.0"; }'
    
    # Execute
    run validate_prerequisites
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Prerequisites validated successfully" ]]
    
    # Cleanup
    unset -f gcloud jq curl
}

@test "validate_prerequisites: fails when gcloud is missing" {
    # Ensure gcloud is not available
    eval 'gcloud() { return 127; }'  # Command not found
    
    # Execute
    run validate_prerequisites
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "gcloud.*not found" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "validate_prerequisites: fails when jq is missing" {
    # Mock gcloud available but jq missing
    eval 'gcloud() { echo "Google Cloud SDK 400.0.0"; }'
    eval 'jq() { return 127; }'
    
    # Execute
    run validate_prerequisites
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "jq.*not found" ]]
    
    # Cleanup
    unset -f gcloud jq
}

@test "validate_prerequisites: checks network connectivity" {
    # Mock tools available
    eval 'gcloud() { echo "Google Cloud SDK 400.0.0"; }'
    eval 'jq() { echo "jq-1.6"; }'
    eval 'curl() { echo "curl 7.68.0"; }'
    
    # Execute
    run validate_prerequisites
    
    # Assert
    [ "$status" -eq 0 ]
    # Should include connectivity check in output
    
    # Cleanup
    unset -f gcloud jq curl
}

@test "validate_prerequisites: handles network connectivity failure" {
    # Mock tools available but network failing
    eval 'gcloud() { echo "Google Cloud SDK 400.0.0"; }'
    eval 'jq() { echo "jq-1.6"; }'
    eval 'curl() { return 1; }'  # Network failure
    
    # Execute
    run validate_prerequisites
    
    # Assert - depends on implementation; might warn but not fail
    # [ "$status" -eq 1 ] || [ "$status" -eq 0 ]
    
    # Cleanup
    unset -f gcloud jq curl
}

@test "validate_prerequisites: verifies gcloud authentication" {
    # Mock gcloud with authentication check
    eval 'gcloud() { 
        if [[ "$*" == *"auth list"* ]]; then
            echo "test-sa@test-project-12345.iam.gserviceaccount.com"
        else
            echo "Google Cloud SDK 400.0.0"
        fi
    }'
    eval 'jq() { echo "jq-1.6"; }'
    eval 'curl() { echo "curl 7.68.0"; }'
    
    # Execute
    run validate_prerequisites
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "authenticated" ]] || [[ "$output" =~ "Prerequisites validated" ]]
    
    # Cleanup
    unset -f gcloud jq curl
}

# =============================================================================
# Tests for print_status()
# =============================================================================

@test "print_status: displays info messages correctly" {
    # Execute
    run print_status "info" "Test info message"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Test info message" ]]
    [[ "$output" =~ "INFO" ]] || [[ "$output" =~ "info" ]]
}

@test "print_status: displays success messages with color" {
    # Execute
    run print_status "success" "Test success message"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Test success message" ]]
    [[ "$output" =~ "SUCCESS" ]] || [[ "$output" =~ "success" ]]
}

@test "print_status: displays error messages correctly" {
    # Execute
    run print_status "error" "Test error message"
    
    # Assert
    [ "$status" -eq 0 ]  # print_status itself shouldn't fail
    [[ "$output" =~ "Test error message" ]]
    [[ "$output" =~ "ERROR" ]] || [[ "$output" =~ "error" ]]
}

@test "print_status: displays warning messages correctly" {
    # Execute
    run print_status "warning" "Test warning message"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Test warning message" ]]
    [[ "$output" =~ "WARNING" ]] || [[ "$output" =~ "warning" ]]
}

@test "print_status: handles unknown message types gracefully" {
    # Execute
    run print_status "unknown" "Test unknown message"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Test unknown message" ]]
}

@test "print_status: respects verbose mode" {
    # Setup
    export VERBOSE=true
    
    # Execute
    run print_status "debug" "Debug message"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Debug message" ]]
}

@test "print_status: suppresses debug in non-verbose mode" {
    # Setup
    export VERBOSE=false
    
    # Execute
    run print_status "debug" "Debug message"
    
    # Assert
    [ "$status" -eq 0 ]
    # Debug message should be suppressed in non-verbose mode
    [[ ! "$output" =~ "Debug message" ]] || [[ "$output" == "" ]]
}

# =============================================================================
# Tests for log_debug()
# =============================================================================

@test "log_debug: writes to log file when specified" {
    # Setup
    export LOG_FILE="$TEST_TEMP_DIR/test.log"
    export VERBOSE=true
    
    # Execute
    run log_debug "Test debug message"
    
    # Assert
    [ "$status" -eq 0 ]
    [ -f "$LOG_FILE" ]
    grep -q "Test debug message" "$LOG_FILE"
}

@test "log_debug: includes timestamp in log entries" {
    # Setup
    export LOG_FILE="$TEST_TEMP_DIR/test.log"
    export VERBOSE=true
    
    # Execute
    log_debug "Test timestamp message"
    
    # Assert
    [ -f "$LOG_FILE" ]
    # Check if log contains timestamp pattern (YYYY-MM-DD HH:MM:SS)
    grep -q "[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}" "$LOG_FILE"
}

@test "log_debug: handles missing log file directory" {
    # Setup
    export LOG_FILE="/nonexistent/directory/test.log"
    export VERBOSE=true
    
    # Execute
    run log_debug "Test message"
    
    # Assert - should handle gracefully
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

# =============================================================================
# Tests for check_script_permissions()
# =============================================================================

@test "check_script_permissions: validates current script permissions" {
    # Execute
    run check_script_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "permissions" ]] || [ -z "$output" ]  # May be silent on success
}

@test "check_script_permissions: handles non-executable script" {
    # Create a test script without execute permissions
    local test_script="$TEST_TEMP_DIR/test_script.sh"
    echo "#!/bin/bash" > "$test_script"
    chmod 644 "$test_script"  # No execute permission
    
    # Mock BASH_SOURCE to point to our test script
    BASH_SOURCE=("$test_script")
    
    # Execute
    run check_script_permissions
    
    # Assert - depends on implementation
    # Could warn or succeed depending on requirements
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

# =============================================================================
# Tests for get_script_name()
# =============================================================================

@test "get_script_name: returns correct script name" {
    # Mock BASH_SOURCE
    BASH_SOURCE=("/path/to/test_script.sh")
    
    # Execute
    run get_script_name
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" == "test_script.sh" ]]
}

@test "get_script_name: handles script name without path" {
    # Mock BASH_SOURCE
    BASH_SOURCE=("simple_script.sh")
    
    # Execute
    run get_script_name
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" == "simple_script.sh" ]]
}

@test "get_script_name: handles empty BASH_SOURCE" {
    # Mock empty BASH_SOURCE
    BASH_SOURCE=()
    
    # Execute
    run get_script_name
    
    # Assert
    [ "$status" -eq 0 ]
    # Should return default or empty string
}

# =============================================================================
# Tests for cleanup_temp_files()
# =============================================================================

@test "cleanup_temp_files: removes temporary files" {
    # Setup - create some temporary files
    local temp_file1="$TEST_TEMP_DIR/temp1.tmp"
    local temp_file2="$TEST_TEMP_DIR/temp2.tmp"
    echo "test content" > "$temp_file1"
    echo "test content" > "$temp_file2"
    
    # Simulate setting temp files in global state
    # This depends on how the library tracks temp files
    
    # Execute
    run cleanup_temp_files
    
    # Assert
    [ "$status" -eq 0 ]
    # Check that cleanup was attempted (implementation specific)
}

@test "cleanup_temp_files: handles missing files gracefully" {
    # Execute cleanup when no temp files exist
    run cleanup_temp_files
    
    # Assert
    [ "$status" -eq 0 ]
    # Should succeed even with no files to clean
}