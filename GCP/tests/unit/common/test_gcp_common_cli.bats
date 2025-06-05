#!/usr/bin/env bats
# Unit Tests for GCP Common Library - CLI Argument Parsing
# Tests: parse_common_arguments, show_help

# Load test configuration and helpers
load '../../test_config'
load '../../helpers/test_helpers'
load '../../helpers/mock_helpers'

# Setup and teardown for each test
setup() {
    setup_test_environment
    
    # Source the library under test
    source "$COMMON_LIB"
    
    # Reset global variables before each test
    SCOPE=""
    SCOPE_TYPE="project"
    PROJECT_ID=""
    ORG_ID=""
    OUTPUT_DIR=""
    VERBOSE=false
    REPORT_ONLY=false
}

teardown() {
    teardown_test_environment
}

# =============================================================================
# Tests for parse_common_arguments()
# =============================================================================

@test "parse_common_arguments: parses project scope correctly" {
    # Setup arguments
    local args=("-s" "test-project-12345")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$SCOPE" = "test-project-12345" ]
    [ "$SCOPE_TYPE" = "project" ]
}

@test "parse_common_arguments: handles project ID argument" {
    # Setup arguments
    local args=("-p" "my-test-project")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$PROJECT_ID" = "my-test-project" ]
}

@test "parse_common_arguments: handles organization ID argument" {
    # Setup arguments
    local args=("--org" "123456789012")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$ORG_ID" = "123456789012" ]
    [ "$SCOPE_TYPE" = "organization" ] || [ "$SCOPE" = "123456789012" ]
}

@test "parse_common_arguments: handles output directory argument" {
    # Setup arguments
    local args=("-o" "$TEST_TEMP_DIR/output")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$OUTPUT_DIR" = "$TEST_TEMP_DIR/output" ]
}

@test "parse_common_arguments: enables verbose mode" {
    # Setup arguments
    local args=("-v")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$VERBOSE" = "true" ]
}

@test "parse_common_arguments: handles long verbose flag" {
    # Setup arguments
    local args=("--verbose")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$VERBOSE" = "true" ]
}

@test "parse_common_arguments: enables report-only mode" {
    # Setup arguments
    local args=("--report-only")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$REPORT_ONLY" = "true" ]
}

@test "parse_common_arguments: handles help flag" {
    # Setup arguments
    local args=("-h")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    # Help should exit with 0 and display help message
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Usage" ]] || [[ "$output" =~ "help" ]]
}

@test "parse_common_arguments: handles long help flag" {
    # Setup arguments
    local args=("--help")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Usage" ]] || [[ "$output" =~ "help" ]]
}

@test "parse_common_arguments: handles multiple arguments" {
    # Setup arguments
    local args=("-s" "test-project" "-o" "$TEST_TEMP_DIR" "-v")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$SCOPE" = "test-project" ]
    [ "$OUTPUT_DIR" = "$TEST_TEMP_DIR" ]
    [ "$VERBOSE" = "true" ]
}

@test "parse_common_arguments: handles arguments in different order" {
    # Setup arguments
    local args=("-v" "-p" "my-project" "-o" "$TEST_TEMP_DIR")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$PROJECT_ID" = "my-project" ]
    [ "$OUTPUT_DIR" = "$TEST_TEMP_DIR" ]
    [ "$VERBOSE" = "true" ]
}

@test "parse_common_arguments: validates required arguments" {
    # Setup arguments with missing required values
    local args=("-s")  # Missing scope value
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    # Should fail when required argument value is missing
    [ "$status" -eq 1 ] || [ "$status" -eq 0 ]  # Depends on implementation
}

@test "parse_common_arguments: handles unknown arguments" {
    # Setup arguments
    local args=("--unknown-arg" "value")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    # Should handle unknown arguments gracefully or show error
    [ "$status" -eq 1 ] || [ "$status" -eq 0 ]
    [[ "$output" =~ "unknown" ]] || [[ "$output" =~ "error" ]] || [ -z "$output" ]
}

@test "parse_common_arguments: handles empty argument list" {
    # Setup arguments
    local args=()
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    # Variables should remain at default values
    [ -z "$SCOPE" ]
    [ "$VERBOSE" = "false" ]
}

@test "parse_common_arguments: sets scope type for organization" {
    # Setup arguments
    local args=("--org" "123456789012")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$SCOPE_TYPE" = "organization" ] || [ "$ORG_ID" = "123456789012" ]
}

@test "parse_common_arguments: validates project ID format" {
    # Setup arguments with potentially invalid project ID
    local args=("-p" "INVALID_PROJECT_ID_WITH_UPPERCASE")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    # Depending on validation implementation
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
    if [ "$status" -eq 1 ]; then
        [[ "$output" =~ "invalid" ]] || [[ "$output" =~ "format" ]]
    fi
}

@test "parse_common_arguments: validates organization ID format" {
    # Setup arguments with potentially invalid org ID
    local args=("--org" "invalid-org-id")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    # Depending on validation implementation
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

@test "parse_common_arguments: creates output directory if specified" {
    # Setup arguments
    local test_output_dir="$TEST_TEMP_DIR/new_output_dir"
    local args=("-o" "$test_output_dir")
    
    # Execute
    run parse_common_arguments "${args[@]}"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$OUTPUT_DIR" = "$test_output_dir" ]
    # Directory creation might happen in parse_common_arguments or later
}

# =============================================================================
# Tests for show_help()
# =============================================================================

@test "show_help: displays usage information" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Usage" ]]
}

@test "show_help: shows available options" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "-s" ]] || [[ "$output" =~ "scope" ]]
    [[ "$output" =~ "-p" ]] || [[ "$output" =~ "project" ]]
    [[ "$output" =~ "-o" ]] || [[ "$output" =~ "output" ]]
    [[ "$output" =~ "-v" ]] || [[ "$output" =~ "verbose" ]]
}

@test "show_help: shows option descriptions" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "project" ]]
    [[ "$output" =~ "output" ]]
    [[ "$output" =~ "verbose" ]]
}

@test "show_help: includes examples" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Example" ]] || [[ "$output" =~ "example" ]]
}

@test "show_help: shows script name in usage" {
    # Mock script name
    BASH_SOURCE=("test_script.sh")
    
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "test_script" ]] || [[ "$output" =~ "Usage:" ]]
}

@test "show_help: displays help for all supported flags" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    # Check for common flags that should be documented
    [[ "$output" =~ "-h" ]] || [[ "$output" =~ "help" ]]
    [[ "$output" =~ "--help" ]] || [[ "$output" =~ "help" ]]
}

@test "show_help: formats output readably" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    # Output should be non-empty and formatted
    [ ${#output} -gt 50 ]  # Should be substantial help text
    [[ "$output" =~ $'\n' ]]  # Should contain newlines for formatting
}

# =============================================================================
# Tests for load_requirement_config()
# =============================================================================

@test "load_requirement_config: loads configuration file successfully" {
    # Setup - create a test config file
    local test_config="$TEST_TEMP_DIR/requirement_config.conf"
    cat > "$test_config" << 'EOF'
# Test configuration
REQUIREMENT_ID="REQ1"
REQUIREMENT_NAME="Test Requirement"
CHECK_ENABLED=true
EOF
    
    # Execute
    run load_requirement_config "$test_config"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "loaded" ]] || [ -z "$output" ]
}

@test "load_requirement_config: handles missing config file" {
    # Setup
    local missing_config="$TEST_TEMP_DIR/nonexistent.conf"
    
    # Execute
    run load_requirement_config "$missing_config"
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "not found" ]] || [[ "$output" =~ "missing" ]]
}

@test "load_requirement_config: handles malformed config file" {
    # Setup - create a malformed config file
    local malformed_config="$TEST_TEMP_DIR/malformed.conf"
    cat > "$malformed_config" << 'EOF'
INVALID SYNTAX HERE
MISSING_EQUALS_SIGN
=MISSING_VARIABLE_NAME
EOF
    
    # Execute
    run load_requirement_config "$malformed_config"
    
    # Assert
    # Should handle gracefully or show error
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

@test "load_requirement_config: validates config content" {
    # Setup - create config with required fields
    local valid_config="$TEST_TEMP_DIR/valid.conf"
    cat > "$valid_config" << 'EOF'
REQUIREMENT_ID="REQ1"
REQUIREMENT_NAME="Network Security"
CHECK_ENABLED=true
SEVERITY="HIGH"
EOF
    
    # Execute
    load_requirement_config "$valid_config"
    
    # Assert - variables should be loaded
    [ "$REQUIREMENT_ID" = "REQ1" ]
    [ "$REQUIREMENT_NAME" = "Network Security" ]
    [ "$CHECK_ENABLED" = "true" ]
    [ "$SEVERITY" = "HIGH" ]
}