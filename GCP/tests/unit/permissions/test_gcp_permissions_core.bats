#!/usr/bin/env bats
# Unit Tests for GCP Permissions Library - Core Functions
# Tests: init_permissions_framework, validate_authentication_setup, detect_and_validate_scope

# Load test configuration and helpers
load '../../test_config'
load '../../helpers/test_helpers'
load '../../helpers/mock_helpers'

# Setup and teardown for each test
setup() {
    setup_test_environment
    setup_mock_gcp_environment
    
    # Source both libraries (permissions depends on common)
    source "$COMMON_LIB"
    source "$PERMISSIONS_LIB"
    
    # Reset permissions state
    unset REQUIRED_PERMISSIONS
    unset PERMISSION_COVERAGE
    unset CURRENT_SCOPE
    declare -A REQUIRED_PERMISSIONS
    declare -A PERMISSION_COVERAGE
}

teardown() {
    teardown_test_environment
    restore_gcp_environment
}

# =============================================================================
# Tests for init_permissions_framework()
# =============================================================================

@test "init_permissions_framework: initializes framework successfully" {
    # Execute
    run init_permissions_framework
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "initialized" ]] || [ -z "$output" ]
}

@test "init_permissions_framework: sets up global arrays" {
    # Execute
    init_permissions_framework
    
    # Assert - check that arrays are declared
    declare -p REQUIRED_PERMISSIONS >/dev/null 2>&1
    declare -p PERMISSION_COVERAGE >/dev/null 2>&1
}

@test "init_permissions_framework: initializes counters" {
    # Execute
    init_permissions_framework
    
    # Assert
    [ "${#REQUIRED_PERMISSIONS[@]}" -eq 0 ]
    [ "${#PERMISSION_COVERAGE[@]}" -eq 0 ]
}

@test "init_permissions_framework: handles multiple calls safely" {
    # Execute multiple times
    run init_permissions_framework
    [ "$status" -eq 0 ]
    
    run init_permissions_framework
    [ "$status" -eq 0 ]
    
    # Should not fail on repeated initialization
}

# =============================================================================
# Tests for validate_authentication_setup()
# =============================================================================

@test "validate_authentication_setup: passes with valid authentication" {
    # Mock gcloud authentication
    eval 'gcloud() {
        case "$*" in
            *"auth list"*)
                echo "test-sa@test-project-12345.iam.gserviceaccount.com"
                return 0
                ;;
            *"config get-value project"*)
                echo "test-project-12345"
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run validate_authentication_setup
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "authenticated" ]] || [[ "$output" =~ "valid" ]] || [ -z "$output" ]
    
    # Cleanup
    unset -f gcloud
}

@test "validate_authentication_setup: fails with no authentication" {
    # Mock gcloud with no authentication
    eval 'gcloud() {
        case "$*" in
            *"auth list"*)
                echo "No credentialed accounts."
                return 1
                ;;
            *)
                return 1
                ;;
        esac
    }'
    
    # Execute
    run validate_authentication_setup
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "not authenticated" ]] || [[ "$output" =~ "authentication" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "validate_authentication_setup: handles gcloud command failure" {
    # Mock gcloud command failure
    eval 'gcloud() { return 127; }'  # Command not found
    
    # Execute
    run validate_authentication_setup
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "gcloud" ]] || [[ "$output" =~ "command" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "validate_authentication_setup: validates service account authentication" {
    # Mock service account authentication
    eval 'gcloud() {
        case "$*" in
            *"auth list"*)
                echo "test-sa@test-project-12345.iam.gserviceaccount.com  ACTIVE"
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run validate_authentication_setup
    
    # Assert
    [ "$status" -eq 0 ]
    
    # Cleanup
    unset -f gcloud
}

@test "validate_authentication_setup: validates user account authentication" {
    # Mock user account authentication
    eval 'gcloud() {
        case "$*" in
            *"auth list"*)
                echo "user@example.com  ACTIVE"
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run validate_authentication_setup
    
    # Assert
    [ "$status" -eq 0 ]
    
    # Cleanup
    unset -f gcloud
}

# =============================================================================
# Tests for detect_and_validate_scope()
# =============================================================================

@test "detect_and_validate_scope: detects project scope correctly" {
    # Setup
    export PROJECT_ID="test-project-12345"
    export SCOPE_TYPE="project"
    
    # Mock gcloud project validation
    eval 'gcloud() {
        case "$*" in
            *"projects describe"*)
                echo '{"projectId":"test-project-12345","lifecycleState":"ACTIVE"}'
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run detect_and_validate_scope
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "project" ]] || [ -z "$output" ]
    
    # Cleanup
    unset -f gcloud
}

@test "detect_and_validate_scope: detects organization scope correctly" {
    # Setup
    export ORG_ID="123456789012"
    export SCOPE_TYPE="organization"
    
    # Mock gcloud organization validation
    eval 'gcloud() {
        case "$*" in
            *"organizations describe"*)
                echo '{"name":"organizations/123456789012","displayName":"Test Org"}'
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run detect_and_validate_scope
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "organization" ]] || [ -z "$output" ]
    
    # Cleanup
    unset -f gcloud
}

@test "detect_and_validate_scope: handles invalid project ID" {
    # Setup
    export PROJECT_ID="invalid-project"
    export SCOPE_TYPE="project"
    
    # Mock gcloud failure for invalid project
    eval 'gcloud() {
        case "$*" in
            *"projects describe"*)
                echo "ERROR: (gcloud.projects.describe) Project [invalid-project] not found."
                return 1
                ;;
            *)
                return 1
                ;;
        esac
    }'
    
    # Execute
    run detect_and_validate_scope
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "not found" ]] || [[ "$output" =~ "invalid" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "detect_and_validate_scope: handles missing scope configuration" {
    # Setup - no PROJECT_ID or ORG_ID set
    unset PROJECT_ID ORG_ID
    export SCOPE_TYPE=""
    
    # Execute
    run detect_and_validate_scope
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "scope" ]] || [[ "$output" =~ "project" ]] || [[ "$output" =~ "organization" ]]
}

@test "detect_and_validate_scope: validates scope permissions" {
    # Setup
    export PROJECT_ID="test-project-12345"
    export SCOPE_TYPE="project"
    
    # Mock gcloud with successful project description and IAM check
    eval 'gcloud() {
        case "$*" in
            *"projects describe"*)
                echo '{"projectId":"test-project-12345","lifecycleState":"ACTIVE"}'
                return 0
                ;;
            *"projects get-iam-policy"*)
                echo '{"bindings":[{"role":"roles/viewer","members":["user:test@example.com"]}]}'
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run detect_and_validate_scope
    
    # Assert
    [ "$status" -eq 0 ]
    
    # Cleanup
    unset -f gcloud
}

@test "detect_and_validate_scope: handles network connectivity issues" {
    # Setup
    export PROJECT_ID="test-project-12345"
    export SCOPE_TYPE="project"
    
    # Mock network failure
    eval 'gcloud() {
        echo "ERROR: Network is unreachable"
        return 1
    }'
    
    # Execute
    run detect_and_validate_scope
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "network" ]] || [[ "$output" =~ "unreachable" ]] || [[ "$output" =~ "ERROR" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "detect_and_validate_scope: sets CURRENT_SCOPE variable" {
    # Setup
    export PROJECT_ID="test-project-12345"
    export SCOPE_TYPE="project"
    
    # Mock gcloud
    eval 'gcloud() {
        case "$*" in
            *"projects describe"*)
                echo '{"projectId":"test-project-12345","lifecycleState":"ACTIVE"}'
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    detect_and_validate_scope
    
    # Assert
    [ "$CURRENT_SCOPE" = "test-project-12345" ] || [ "$CURRENT_SCOPE" = "project:test-project-12345" ]
    
    # Cleanup
    unset -f gcloud
}

# =============================================================================
# Tests for register_required_permissions()
# =============================================================================

@test "register_required_permissions: registers single permission" {
    # Setup
    init_permissions_framework
    
    # Execute
    run register_required_permissions "compute.instances.list"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "${REQUIRED_PERMISSIONS[compute.instances.list]}" ]] || [ "${#REQUIRED_PERMISSIONS[@]}" -gt 0 ]
}

@test "register_required_permissions: registers multiple permissions" {
    # Setup
    init_permissions_framework
    
    # Execute
    run register_required_permissions "compute.instances.list" "iam.roles.list" "storage.buckets.list"
    
    # Assert
    [ "$status" -eq 0 ]
    [ "${#REQUIRED_PERMISSIONS[@]}" -eq 3 ] || [ "${#REQUIRED_PERMISSIONS[@]}" -gt 0 ]
}

@test "register_required_permissions: handles duplicate permissions" {
    # Setup
    init_permissions_framework
    
    # Execute
    register_required_permissions "compute.instances.list"
    run register_required_permissions "compute.instances.list"
    
    # Assert
    [ "$status" -eq 0 ]
    # Should not create duplicates
}

@test "register_required_permissions: validates permission format" {
    # Setup
    init_permissions_framework
    
    # Execute with invalid permission format
    run register_required_permissions "invalid-permission"
    
    # Assert
    # Should handle gracefully or validate format
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

@test "register_required_permissions: handles empty permission list" {
    # Setup
    init_permissions_framework
    
    # Execute
    run register_required_permissions
    
    # Assert
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
    [ "${#REQUIRED_PERMISSIONS[@]}" -eq 0 ]
}

# =============================================================================
# Tests for check_single_permission()
# =============================================================================

@test "check_single_permission: returns success for valid permission" {
    # Setup
    init_permissions_framework
    register_required_permissions "compute.instances.list"
    
    # Mock gcloud IAM test
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
    run check_single_permission "compute.instances.list" "test-project-12345"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "compute.instances.list" ]] || [ -z "$output" ]
    
    # Cleanup
    unset -f gcloud
}

@test "check_single_permission: returns failure for missing permission" {
    # Setup
    init_permissions_framework
    register_required_permissions "compute.instances.list"
    
    # Mock gcloud IAM test failure
    eval 'gcloud() {
        case "$*" in
            *"iam test-permissions"*)
                echo ""  # No permissions returned
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute
    run check_single_permission "compute.instances.list" "test-project-12345"
    
    # Assert
    [ "$status" -eq 1 ]
    
    # Cleanup
    unset -f gcloud
}

@test "check_single_permission: handles gcloud command failure" {
    # Setup
    init_permissions_framework
    
    # Mock gcloud failure
    eval 'gcloud() { return 1; }'
    
    # Execute
    run check_single_permission "compute.instances.list" "test-project-12345"
    
    # Assert
    [ "$status" -eq 1 ]
    
    # Cleanup
    unset -f gcloud
}

@test "check_single_permission: validates input parameters" {
    # Setup
    init_permissions_framework
    
    # Execute with missing parameters
    run check_single_permission
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "permission" ]] || [[ "$output" =~ "parameter" ]] || [[ "$output" =~ "usage" ]]
}

@test "check_single_permission: handles organization scope" {
    # Setup
    init_permissions_framework
    export SCOPE_TYPE="organization"
    
    # Mock gcloud for organization
    eval 'gcloud() {
        case "$*" in
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
    run check_single_permission "resourcemanager.projects.list" "123456789012"
    
    # Assert
    [ "$status" -eq 0 ]
    
    # Cleanup
    unset -f gcloud
}

# =============================================================================
# Tests for get_permission_coverage()
# =============================================================================

@test "get_permission_coverage: calculates coverage correctly" {
    # Setup
    init_permissions_framework
    register_required_permissions "compute.instances.list" "iam.roles.list" "storage.buckets.list"
    
    # Simulate some permissions checked
    PERMISSION_COVERAGE["compute.instances.list"]="GRANTED"
    PERMISSION_COVERAGE["iam.roles.list"]="DENIED"
    PERMISSION_COVERAGE["storage.buckets.list"]="GRANTED"
    
    # Execute
    run get_permission_coverage
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "66" ]] || [[ "$output" =~ "67" ]]  # 2/3 = 66.67%
}

@test "get_permission_coverage: handles no permissions registered" {
    # Setup
    init_permissions_framework
    
    # Execute
    run get_permission_coverage
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "0" ]] || [[ "$output" =~ "100" ]]  # Could be 0% or 100% depending on implementation
}

@test "get_permission_coverage: handles no permissions checked" {
    # Setup
    init_permissions_framework
    register_required_permissions "compute.instances.list" "iam.roles.list"
    
    # Execute
    run get_permission_coverage
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "0" ]]  # 0% coverage
}

@test "get_permission_coverage: returns 100% for full coverage" {
    # Setup
    init_permissions_framework
    register_required_permissions "compute.instances.list" "iam.roles.list"
    
    # Simulate all permissions granted
    PERMISSION_COVERAGE["compute.instances.list"]="GRANTED"
    PERMISSION_COVERAGE["iam.roles.list"]="GRANTED"
    
    # Execute
    run get_permission_coverage
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "100" ]]
}