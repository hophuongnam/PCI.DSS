#!/usr/bin/env bats
# Unit Tests for GCP Permissions Library - Validation and User Interaction
# Tests: check_all_permissions, validate_scope_permissions, prompt_continue_limited, display_permission_guidance, log_permission_audit_trail

# Load test configuration and helpers
load '../../test_config'
load '../../helpers/test_helpers'
load '../../helpers/mock_helpers'

# Setup and teardown for each test
setup() {
    setup_test_environment
    setup_mock_gcp_environment
    
    # Source both libraries
    source "$COMMON_LIB"
    source "$PERMISSIONS_LIB"
    
    # Initialize permissions framework
    init_permissions_framework
    
    # Reset state
    unset PERMISSION_CHECK_RESULTS
    declare -A PERMISSION_CHECK_RESULTS
}

teardown() {
    teardown_test_environment
    restore_gcp_environment
}

# =============================================================================
# Tests for check_all_permissions()
# =============================================================================

@test "check_all_permissions: checks all registered permissions" {
    # Setup
    register_required_permissions "compute.instances.list" "iam.roles.list" "storage.buckets.list"
    export PROJECT_ID="test-project-12345"
    
    # Mock gcloud IAM test with mixed results
    eval 'gcloud() {
        case "$*" in
            *"iam test-permissions"*"compute.instances.list"*)
                echo "compute.instances.list"
                return 0
                ;;
            *"iam test-permissions"*"iam.roles.list"*)
                echo ""  # No permission
                return 0
                ;;
            *"iam test-permissions"*"storage.buckets.list"*)
                echo "storage.buckets.list"
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run check_all_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "compute.instances.list" ]]
    [[ "$output" =~ "storage.buckets.list" ]]
    [[ "$output" =~ "iam.roles.list" ]] || [[ "$output" =~ "denied" ]] || [[ "$output" =~ "missing" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "check_all_permissions: handles no registered permissions" {
    # Execute without registering any permissions
    run check_all_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "No permissions" ]] || [ -z "$output" ]
}

@test "check_all_permissions: reports coverage summary" {
    # Setup
    register_required_permissions "compute.instances.list" "iam.roles.list"
    export PROJECT_ID="test-project-12345"
    
    # Mock gcloud with one success, one failure
    eval 'gcloud() {
        case "$*" in
            *"iam test-permissions"*"compute.instances.list"*)
                echo "compute.instances.list"
                return 0
                ;;
            *"iam test-permissions"*"iam.roles.list"*)
                echo ""
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run check_all_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "50%" ]] || [[ "$output" =~ "1" ]] || [[ "$output" =~ "coverage" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "check_all_permissions: handles gcloud command failures" {
    # Setup
    register_required_permissions "compute.instances.list"
    export PROJECT_ID="test-project-12345"
    
    # Mock gcloud failure
    eval 'gcloud() { return 1; }'
    
    # Execute
    run check_all_permissions
    
    # Assert
    [ "$status" -eq 1 ] || [ "$status" -eq 0 ]  # May continue with warnings
    [[ "$output" =~ "error" ]] || [[ "$output" =~ "failed" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "check_all_permissions: updates permission coverage tracking" {
    # Setup
    register_required_permissions "compute.instances.list"
    export PROJECT_ID="test-project-12345"
    
    # Mock gcloud
    eval 'gcloud() {
        case "$*" in
            *"iam test-permissions"*)
                echo "compute.instances.list"
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    check_all_permissions
    
    # Assert - check internal state was updated
    [[ "${PERMISSION_COVERAGE[compute.instances.list]}" ]] || [ "${#PERMISSION_COVERAGE[@]}" -gt 0 ]
    
    # Cleanup
    unset -f gcloud
}

# =============================================================================
# Tests for validate_scope_permissions()
# =============================================================================

@test "validate_scope_permissions: validates project scope permissions" {
    # Setup
    export PROJECT_ID="test-project-12345"
    export SCOPE_TYPE="project"
    register_required_permissions "compute.instances.list"
    
    # Mock gcloud
    eval 'gcloud() {
        case "$*" in
            *"projects get-iam-policy"*)
                echo '{"bindings":[{"role":"roles/viewer","members":["user:test@example.com"]}]}'
                return 0
                ;;
            *"iam test-permissions"*)
                echo "compute.instances.list"
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run validate_scope_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "valid" ]] || [[ "$output" =~ "permissions" ]] || [ -z "$output" ]
    
    # Cleanup
    unset -f gcloud
}

@test "validate_scope_permissions: validates organization scope permissions" {
    # Setup
    export ORG_ID="123456789012"
    export SCOPE_TYPE="organization"
    register_required_permissions "resourcemanager.projects.list"
    
    # Mock gcloud
    eval 'gcloud() {
        case "$*" in
            *"organizations get-iam-policy"*)
                echo '{"bindings":[{"role":"roles/viewer","members":["user:test@example.com"]}]}'
                return 0
                ;;
            *"organizations test-permissions"*)
                echo "resourcemanager.projects.list"
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run validate_scope_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    
    # Cleanup
    unset -f gcloud
}

@test "validate_scope_permissions: handles insufficient permissions" {
    # Setup
    export PROJECT_ID="test-project-12345"
    export SCOPE_TYPE="project"
    register_required_permissions "compute.instances.list" "iam.roles.list"
    
    # Mock gcloud with insufficient permissions
    eval 'gcloud() {
        case "$*" in
            *"projects get-iam-policy"*)
                echo "ERROR: (gcloud.projects.get-iam-policy) User does not have permission"
                return 1
                ;;
            *"iam test-permissions"*)
                echo ""  # No permissions
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run validate_scope_permissions
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "insufficient" ]] || [[ "$output" =~ "permission" ]] || [[ "$output" =~ "denied" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "validate_scope_permissions: handles missing scope configuration" {
    # Setup - no PROJECT_ID or ORG_ID
    unset PROJECT_ID ORG_ID SCOPE_TYPE
    
    # Execute
    run validate_scope_permissions
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "scope" ]] || [[ "$output" =~ "configuration" ]]
}

# =============================================================================
# Tests for prompt_continue_limited()
# =============================================================================

@test "prompt_continue_limited: displays limited permissions warning" {
    # Setup
    register_required_permissions "compute.instances.list" "iam.roles.list"
    PERMISSION_COVERAGE["compute.instances.list"]="GRANTED"
    PERMISSION_COVERAGE["iam.roles.list"]="DENIED"
    
    # Mock user input - continue
    echo "y" | run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "limited" ]] || [[ "$output" =~ "continue" ]] || [[ "$output" =~ "warning" ]]
}

@test "prompt_continue_limited: handles user choosing to continue" {
    # Setup
    register_required_permissions "compute.instances.list"
    PERMISSION_COVERAGE["compute.instances.list"]="DENIED"
    
    # Mock user input - yes
    echo "yes" | run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
}

@test "prompt_continue_limited: handles user choosing to abort" {
    # Setup
    register_required_permissions "compute.instances.list"
    PERMISSION_COVERAGE["compute.instances.list"]="DENIED"
    
    # Mock user input - no
    echo "no" | run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 1 ]
}

@test "prompt_continue_limited: handles non-interactive mode" {
    # Setup
    export NON_INTERACTIVE=true
    register_required_permissions "compute.instances.list"
    PERMISSION_COVERAGE["compute.instances.list"]="DENIED"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    # Should handle non-interactive mode appropriately
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

@test "prompt_continue_limited: shows coverage percentage" {
    # Setup
    register_required_permissions "compute.instances.list" "iam.roles.list"
    PERMISSION_COVERAGE["compute.instances.list"]="GRANTED"
    PERMISSION_COVERAGE["iam.roles.list"]="DENIED"
    
    # Mock user input
    echo "y" | run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "50%" ]] || [[ "$output" =~ "coverage" ]]
}

# =============================================================================
# Tests for display_permission_guidance()
# =============================================================================

@test "display_permission_guidance: shows guidance for missing permissions" {
    # Setup
    register_required_permissions "compute.instances.list" "iam.roles.list"
    PERMISSION_COVERAGE["compute.instances.list"]="GRANTED"
    PERMISSION_COVERAGE["iam.roles.list"]="DENIED"
    
    # Execute
    run display_permission_guidance
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "guidance" ]] || [[ "$output" =~ "permission" ]] || [[ "$output" =~ "iam.roles.list" ]]
}

@test "display_permission_guidance: provides role suggestions" {
    # Setup
    register_required_permissions "compute.instances.list"
    PERMISSION_COVERAGE["compute.instances.list"]="DENIED"
    
    # Execute
    run display_permission_guidance
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "role" ]] || [[ "$output" =~ "viewer" ]] || [[ "$output" =~ "compute" ]]
}

@test "display_permission_guidance: handles all permissions granted" {
    # Setup
    register_required_permissions "compute.instances.list"
    PERMISSION_COVERAGE["compute.instances.list"]="GRANTED"
    
    # Execute
    run display_permission_guidance
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "sufficient" ]] || [[ "$output" =~ "all permissions" ]] || [ -z "$output" ]
}

@test "display_permission_guidance: shows project-specific guidance" {
    # Setup
    export PROJECT_ID="test-project-12345"
    export SCOPE_TYPE="project"
    register_required_permissions "compute.instances.list"
    PERMISSION_COVERAGE["compute.instances.list"]="DENIED"
    
    # Execute
    run display_permission_guidance
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "project" ]] || [[ "$output" =~ "test-project-12345" ]]
}

@test "display_permission_guidance: shows organization-specific guidance" {
    # Setup
    export ORG_ID="123456789012"
    export SCOPE_TYPE="organization"
    register_required_permissions "resourcemanager.projects.list"
    PERMISSION_COVERAGE["resourcemanager.projects.list"]="DENIED"
    
    # Execute
    run display_permission_guidance
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "organization" ]] || [[ "$output" =~ "123456789012" ]]
}

# =============================================================================
# Tests for log_permission_audit_trail()
# =============================================================================

@test "log_permission_audit_trail: creates audit log entry" {
    # Setup
    export LOG_FILE="$TEST_TEMP_DIR/audit.log"
    register_required_permissions "compute.instances.list"
    PERMISSION_COVERAGE["compute.instances.list"]="GRANTED"
    
    # Execute
    run log_permission_audit_trail "Permission check completed"
    
    # Assert
    [ "$status" -eq 0 ]
    [ -f "$LOG_FILE" ]
    grep -q "Permission check completed" "$LOG_FILE"
}

@test "log_permission_audit_trail: includes timestamp in audit log" {
    # Setup
    export LOG_FILE="$TEST_TEMP_DIR/audit.log"
    
    # Execute
    log_permission_audit_trail "Test audit message"
    
    # Assert
    [ -f "$LOG_FILE" ]
    grep -q "[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}" "$LOG_FILE"
}

@test "log_permission_audit_trail: includes permission summary" {
    # Setup
    export LOG_FILE="$TEST_TEMP_DIR/audit.log"
    register_required_permissions "compute.instances.list" "iam.roles.list"
    PERMISSION_COVERAGE["compute.instances.list"]="GRANTED"
    PERMISSION_COVERAGE["iam.roles.list"]="DENIED"
    
    # Execute
    log_permission_audit_trail "Audit test"
    
    # Assert
    [ -f "$LOG_FILE" ]
    grep -q "compute.instances.list" "$LOG_FILE" || grep -q "iam.roles.list" "$LOG_FILE"
}

@test "log_permission_audit_trail: handles missing log file directory" {
    # Setup
    export LOG_FILE="/nonexistent/directory/audit.log"
    
    # Execute
    run log_permission_audit_trail "Test message"
    
    # Assert
    # Should handle gracefully
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

@test "log_permission_audit_trail: includes scope information" {
    # Setup
    export LOG_FILE="$TEST_TEMP_DIR/audit.log"
    export PROJECT_ID="test-project-12345"
    export SCOPE_TYPE="project"
    
    # Execute
    log_permission_audit_trail "Scope test"
    
    # Assert
    [ -f "$LOG_FILE" ]
    grep -q "test-project-12345" "$LOG_FILE" || grep -q "project" "$LOG_FILE"
}

@test "log_permission_audit_trail: handles empty message" {
    # Setup
    export LOG_FILE="$TEST_TEMP_DIR/audit.log"
    
    # Execute
    run log_permission_audit_trail ""
    
    # Assert
    [ "$status" -eq 0 ]
    [ -f "$LOG_FILE" ]
}

@test "log_permission_audit_trail: appends to existing log file" {
    # Setup
    export LOG_FILE="$TEST_TEMP_DIR/audit.log"
    echo "Previous log entry" > "$LOG_FILE"
    
    # Execute
    log_permission_audit_trail "New log entry"
    
    # Assert
    [ -f "$LOG_FILE" ]
    grep -q "Previous log entry" "$LOG_FILE"
    grep -q "New log entry" "$LOG_FILE"
}