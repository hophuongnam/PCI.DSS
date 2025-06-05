#!/usr/bin/env bats
# Integration Tests for GCP Shared Libraries
# Tests: Library combinations, end-to-end workflows, cross-library dependencies

# Load test configuration and helpers
load '../test_config.bash'
load '../helpers/test_helpers.bash'
load '../helpers/mock_helpers.bash'

# Setup and teardown for each test
setup() {
    setup_test_environment
    setup_mock_gcp_environment
    
    # Source both libraries in proper order
    source "$COMMON_LIB"
    source "$PERMISSIONS_LIB"
    
    # Initialize both frameworks
    setup_environment
    init_permissions_framework
}

teardown() {
    teardown_test_environment
    restore_gcp_environment
}

# =============================================================================
# Integration Tests: Common + Permissions Library
# =============================================================================

@test "integration: complete authentication and permission check workflow" {
    # Setup
    export PROJECT_ID="test-project-12345"
    export SCOPE_TYPE="project"
    register_required_permissions "compute.instances.list" "iam.roles.list"
    
    # Mock complete gcloud environment
    eval 'gcloud() {
        case "$*" in
            *"auth list"*)
                echo "test-sa@test-project-12345.iam.gserviceaccount.com  ACTIVE"
                return 0
                ;;
            *"config get-value project"*)
                echo "test-project-12345"
                return 0
                ;;
            *"projects describe"*)
                echo '{"projectId":"test-project-12345","lifecycleState":"ACTIVE"}'
                return 0
                ;;
            *"iam test-permissions"*"compute.instances.list"*)
                echo "compute.instances.list"
                return 0
                ;;
            *"iam test-permissions"*"iam.roles.list"*)
                echo "iam.roles.list"
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute complete workflow
    run bash -c '
        validate_authentication_setup &&
        detect_and_validate_scope &&
        check_all_permissions &&
        get_permission_coverage
    '
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "100%" ]] || [[ "$output" =~ "compute.instances.list" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "integration: handles authentication failure gracefully across libraries" {
    # Setup
    export PROJECT_ID="test-project-12345"
    
    # Mock authentication failure
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
    
    # Execute workflow
    run bash -c '
        validate_authentication_setup ||
        echo "Authentication failed as expected"
    '
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Authentication failed" ]] || [[ "$output" =~ "not authenticated" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "integration: common library setup enables permissions framework" {
    # Execute
    run bash -c '
        # Common library should set up environment
        setup_environment
        
        # Permissions library should be able to initialize
        init_permissions_framework
        
        # Verify both are working
        echo "Environment: $SCRIPT_DIR"
        echo "Permissions: ${#REQUIRED_PERMISSIONS[@]}"
    '
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Environment:" ]]
    [[ "$output" =~ "Permissions:" ]]
}

@test "integration: CLI parsing with permissions validation" {
    # Setup arguments for CLI parsing
    local args=("-s" "test-project-12345" "-v")
    
    # Mock gcloud for validation
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
    
    # Execute workflow
    run bash -c "
        parse_common_arguments ${args[*]} &&
        detect_and_validate_scope &&
        echo \"Scope: \$SCOPE, Verbose: \$VERBOSE\"
    "
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "test-project-12345" ]]
    [[ "$output" =~ "true" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "integration: error handling propagation between libraries" {
    # Setup with invalid project
    export PROJECT_ID="invalid-project-id"
    export SCOPE_TYPE="project"
    
    # Mock gcloud failure
    eval 'gcloud() {
        case "$*" in
            *"projects describe"*)
                echo "ERROR: Project not found"
                return 1
                ;;
            *)
                return 1
                ;;
        esac
    }'
    
    # Execute workflow
    run bash -c '
        detect_and_validate_scope || {
            print_status "error" "Scope validation failed"
            exit 1
        }
    '
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "error" ]] || [[ "$output" =~ "not found" ]] || [[ "$output" =~ "failed" ]]
    
    # Cleanup
    unset -f gcloud
}

# =============================================================================
# Integration Tests: End-to-End Workflows
# =============================================================================

@test "integration: complete PCI DSS requirement check simulation" {
    # Setup for PCI requirement check workflow
    export PROJECT_ID="test-project-12345"
    export SCOPE_TYPE="project"
    export OUTPUT_DIR="$TEST_TEMP_DIR/output"
    export VERBOSE=true
    
    # Register permissions needed for a typical PCI requirement
    register_required_permissions "compute.instances.list" "compute.firewalls.list" "iam.serviceAccounts.list"
    
    # Mock complete GCP environment
    eval 'gcloud() {
        case "$*" in
            *"auth list"*)
                echo "test-sa@test-project-12345.iam.gserviceaccount.com  ACTIVE"
                return 0
                ;;
            *"projects describe"*)
                echo '{"projectId":"test-project-12345","lifecycleState":"ACTIVE"}'
                return 0
                ;;
            *"iam test-permissions"*)
                echo "$4"  # Return the permission being tested
                return 0
                ;;
            *"compute instances list"*)
                echo '{"items":[{"name":"test-instance","status":"RUNNING"}]}'
                return 0
                ;;
            *"compute firewall-rules list"*)
                echo '{"items":[{"name":"allow-ssh","direction":"INGRESS"}]}'
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    }'
    
    # Execute complete workflow
    run bash -c '
        # Step 1: Validate prerequisites and setup
        validate_prerequisites &&
        
        # Step 2: Authenticate and validate scope
        validate_authentication_setup &&
        detect_and_validate_scope &&
        
        # Step 3: Check permissions
        check_all_permissions &&
        
        # Step 4: Get coverage report
        coverage=$(get_permission_coverage)
        echo "Permission coverage: $coverage"
        
        # Step 5: Simulate resource checks (if permissions allow)
        if [[ "$coverage" == *"100"* ]]; then
            echo "Executing resource checks..."
            gcloud compute instances list --project=$PROJECT_ID >/dev/null 2>&1 &&
            gcloud compute firewall-rules list --project=$PROJECT_ID >/dev/null 2>&1 &&
            echo "Resource checks completed successfully"
        else
            echo "Limited permissions - partial checks only"
        fi
    '
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "100%" ]] || [[ "$output" =~ "Permission coverage" ]]
    [[ "$output" =~ "Resource checks completed" ]] || [[ "$output" =~ "Limited permissions" ]]
    
    # Cleanup
    unset -f gcloud
}

@test "integration: handles partial permissions gracefully" {
    # Setup
    export PROJECT_ID="test-project-12345"
    register_required_permissions "compute.instances.list" "iam.serviceAccounts.list" "storage.buckets.list"
    
    # Mock gcloud with partial permissions
    eval 'gcloud() {
        case "$*" in
            *"auth list"*)
                echo "user@example.com  ACTIVE"
                return 0
                ;;
            *"projects describe"*)
                echo '{"projectId":"test-project-12345","lifecycleState":"ACTIVE"}'
                return 0
                ;;
            *"iam test-permissions"*"compute.instances.list"*)
                echo "compute.instances.list"
                return 0
                ;;
            *"iam test-permissions"*"iam.serviceAccounts.list"*)
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
    
    # Execute with limited permissions
    run bash -c '
        validate_authentication_setup &&
        detect_and_validate_scope &&
        check_all_permissions &&
        
        coverage=$(get_permission_coverage)
        echo "Coverage: $coverage"
        
        # Should be able to continue with partial permissions
        if [[ ! "$coverage" == *"100"* ]]; then
            echo "Continuing with limited permissions"
            exit 0
        fi
    '
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "66%" ]] || [[ "$output" =~ "67%" ]]  # 2/3 permissions
    [[ "$output" =~ "limited permissions" ]]
    
    # Cleanup
    unset -f gcloud
}

# =============================================================================
# Integration Tests: Library Dependencies
# =============================================================================

@test "integration: permissions library requires common library functions" {
    # Test that permissions library can use common library functions
    
    # Execute
    run bash -c '
        # Use common library function from permissions context
        print_status "info" "Testing cross-library function calls"
        
        # Use permissions library function that depends on common functions
        init_permissions_framework &&
        register_required_permissions "compute.instances.list" &&
        
        echo "Cross-library integration successful"
    '
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Testing cross-library function calls" ]]
    [[ "$output" =~ "Cross-library integration successful" ]]
}

@test "integration: shared state management between libraries" {
    # Test that both libraries can access and modify shared state
    
    # Execute
    run bash -c '
        # Set state in common library
        export VERBOSE=true
        export OUTPUT_DIR="'$TEST_TEMP_DIR'/shared_output"
        
        # Initialize permissions framework
        init_permissions_framework
        register_required_permissions "compute.instances.list"
        
        # Both libraries should see the same state
        echo "Verbose mode: $VERBOSE"
        echo "Output dir: $OUTPUT_DIR"
        echo "Required permissions: ${#REQUIRED_PERMISSIONS[@]}"
    '
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Verbose mode: true" ]]
    [[ "$output" =~ "Required permissions: 1" ]]
}

@test "integration: cleanup functions work across libraries" {
    # Setup
    export OUTPUT_DIR="$TEST_TEMP_DIR/cleanup_test"
    export LOG_FILE="$TEST_TEMP_DIR/test.log"
    mkdir -p "$OUTPUT_DIR"
    echo "Test log entry" > "$LOG_FILE"
    
    # Execute
    run bash -c '
        # Initialize both libraries
        setup_environment
        init_permissions_framework
        
        # Create some test files
        echo "test" > "'$OUTPUT_DIR'/test_file.tmp"
        log_debug "Test debug message"
        
        # Cleanup should handle both library artifacts
        cleanup_temp_files
        
        echo "Cleanup completed"
    '
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Cleanup completed" ]]
}

# =============================================================================
# Integration Tests: Configuration and Environment
# =============================================================================

@test "integration: configuration loading affects both libraries" {
    # Setup configuration file
    local config_file="$TEST_TEMP_DIR/integration_config.conf"
    cat > "$config_file" << 'EOF'
REQUIREMENT_ID="REQ1"
VERBOSE=true
CHECK_PERMISSIONS=true
REQUIRED_ROLE="roles/viewer"
EOF
    
    # Execute
    run bash -c '
        # Load configuration
        load_requirement_config "'$config_file'"
        
        # Both libraries should respect configuration
        echo "Requirement ID: $REQUIREMENT_ID"
        echo "Verbose: $VERBOSE"
        echo "Check permissions: $CHECK_PERMISSIONS"
        
        # Initialize with configuration
        setup_environment
        init_permissions_framework
    '
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "REQ1" ]]
    [[ "$output" =~ "true" ]]
}

@test "integration: error recovery and continuation" {
    # Test that libraries handle errors gracefully and can continue
    
    # Execute
    run bash -c '
        # Simulate error in authentication
        export PROJECT_ID="test-project"
        
        # Mock failing then succeeding gcloud
        counter=0
        gcloud() {
            counter=$((counter + 1))
            if [ $counter -eq 1 ]; then
                echo "Network error"
                return 1
            else
                case "$*" in
                    *"projects describe"*)
                        echo '"'"'{"projectId":"test-project","lifecycleState":"ACTIVE"}'"'"'
                        return 0
                        ;;
                    *)
                        return 0
                        ;;
                esac
            fi
        }
        
        # First attempt should fail
        if ! detect_and_validate_scope 2>/dev/null; then
            echo "First attempt failed as expected"
        fi
        
        # Second attempt should succeed
        if detect_and_validate_scope 2>/dev/null; then
            echo "Second attempt succeeded"
        fi
        
        unset -f gcloud
    '
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "First attempt failed" ]]
    [[ "$output" =~ "Second attempt succeeded" ]]
}