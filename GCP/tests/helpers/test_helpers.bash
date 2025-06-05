#!/bin/bash

# =============================================================================
# Test Helper Functions for GCP Shared Library Testing
# =============================================================================

# Global test configuration
TEST_TMPDIR=""
TEST_LIB_DIR=""
TEST_MOCK_DIR=""

# =============================================================================
# Test Environment Setup and Teardown
# =============================================================================

# Setup test environment for each test
setup_test_environment() {
    # Create unique temporary directory for this test
    TEST_TMPDIR=$(mktemp -d "/tmp/gcp_test_$$_XXXXXX")
    export TEST_TMPDIR
    
    # Set up test library directory structure
    TEST_LIB_DIR="$TEST_TMPDIR/lib"
    TEST_MOCK_DIR="$TEST_TMPDIR/mocks"
    mkdir -p "$TEST_LIB_DIR" "$TEST_MOCK_DIR"
    
    # Copy actual library files to test location
    if [[ -d "$(dirname "$BATS_TEST_FILENAME")/../lib" ]]; then
        cp -r "$(dirname "$BATS_TEST_FILENAME")/../lib"/* "$TEST_LIB_DIR/"
    elif [[ -d "$(dirname "$BATS_TEST_FILENAME")/../../lib" ]]; then
        cp -r "$(dirname "$BATS_TEST_FILENAME")/../../lib"/* "$TEST_LIB_DIR/"
    fi
    
    # Set library path for testing
    export LIB_DIR="$TEST_LIB_DIR"
    export GCP_LIB_PATH="$TEST_LIB_DIR"
    
    # Initialize test-specific variables
    export OUTPUT_DIR="$TEST_TMPDIR/output"
    export WORK_DIR="$TEST_TMPDIR/work"
    export REPORT_DIR="$TEST_TMPDIR/reports"
    export LOG_DIR="$TEST_TMPDIR/logs"
    
    # Create required directories
    mkdir -p "$OUTPUT_DIR" "$WORK_DIR" "$REPORT_DIR" "$LOG_DIR"
    
    # Reset global variables for clean test state
    unset PROJECT_ID ORG_ID SCOPE SCOPE_TYPE VERBOSE REPORT_ONLY LOG_FILE
    unset REQUIRED_PERMISSIONS OPTIONAL_PERMISSIONS PERMISSION_RESULTS
    unset PERMISSION_COVERAGE_PERCENTAGE MISSING_PERMISSIONS_COUNT AVAILABLE_PERMISSIONS_COUNT
    unset GCP_COMMON_LOADED GCP_PERMISSIONS_LOADED
    
    # Initialize arrays
    declare -g -a REQUIRED_PERMISSIONS
    declare -g -a OPTIONAL_PERMISSIONS
    declare -g -A PERMISSION_RESULTS
    
    # Set default test values
    export PERMISSION_COVERAGE_PERCENTAGE=0
    export MISSING_PERMISSIONS_COUNT=0
    export AVAILABLE_PERMISSIONS_COUNT=0
    
    # Disable colors for consistent test output
    export NO_COLOR=1
    export RED=""
    export GREEN=""
    export YELLOW=""
    export BLUE=""
    export CYAN=""
    export NC=""
}

# Cleanup test environment after each test
cleanup_test_environment() {
    # Clean up temporary directory
    if [[ -n "$TEST_TMPDIR" && -d "$TEST_TMPDIR" ]]; then
        rm -rf "$TEST_TMPDIR"
    fi
    
    # Reset environment variables
    unset TEST_TMPDIR TEST_LIB_DIR TEST_MOCK_DIR
    unset OUTPUT_DIR WORK_DIR REPORT_DIR LOG_DIR
    unset PROJECT_ID ORG_ID SCOPE SCOPE_TYPE VERBOSE REPORT_ONLY LOG_FILE
    unset REQUIRED_PERMISSIONS OPTIONAL_PERMISSIONS PERMISSION_RESULTS
    unset PERMISSION_COVERAGE_PERCENTAGE MISSING_PERMISSIONS_COUNT AVAILABLE_PERMISSIONS_COUNT
    unset GCP_COMMON_LOADED GCP_PERMISSIONS_LOADED
    
    # Clear function mocks
    unset -f gcloud jq curl
}

# =============================================================================
# Library Loading Functions
# =============================================================================

# Load gcp_common.sh library for testing
load_gcp_common_library() {
    if [[ -f "$TEST_LIB_DIR/gcp_common.sh" ]]; then
        source "$TEST_LIB_DIR/gcp_common.sh"
        export GCP_COMMON_LOADED="true"
    else
        echo "Error: gcp_common.sh not found in $TEST_LIB_DIR" >&2
        return 1
    fi
}

# Load gcp_permissions.sh library for testing
load_gcp_permissions_library() {
    if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
        echo "Error: gcp_common.sh must be loaded before gcp_permissions.sh" >&2
        return 1
    fi
    
    if [[ -f "$TEST_LIB_DIR/gcp_permissions.sh" ]]; then
        source "$TEST_LIB_DIR/gcp_permissions.sh"
        export GCP_PERMISSIONS_LOADED="true"
    else
        echo "Error: gcp_permissions.sh not found in $TEST_LIB_DIR" >&2
        return 1
    fi
}

# Create mock library directory for testing
create_mock_lib_directory() {
    mkdir -p "$TEST_LIB_DIR"
    
    # Create minimal mock gcp_common.sh for dependency testing
    cat > "$TEST_LIB_DIR/gcp_common.sh" << 'EOF'
#!/bin/bash
export GCP_COMMON_LOADED="true"
print_status() { echo "[$1] $2"; }
export -f print_status
EOF
    
    # Create minimal mock gcp_permissions.sh
    cat > "$TEST_LIB_DIR/gcp_permissions.sh" << 'EOF'
#!/bin/bash
if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
    echo "Error: gcp_common.sh must be loaded before gcp_permissions.sh" >&2
    exit 1
fi
export GCP_PERMISSIONS_LOADED="true"
EOF
    
    chmod +x "$TEST_LIB_DIR"/*.sh
}

# =============================================================================
# Test Data and Mock Setup Functions
# =============================================================================

# Create test project data
create_test_project_data() {
    local project_id="${1:-test-project-123}"
    
    cat > "$TEST_MOCK_DIR/project_${project_id}.json" << EOF
{
  "projectId": "$project_id",
  "name": "Test Project",
  "projectNumber": "123456789012",
  "lifecycleState": "ACTIVE",
  "createTime": "2023-01-01T00:00:00.000Z"
}
EOF
}

# Create test organization data
create_test_organization_data() {
    local org_id="${1:-123456789}"
    
    cat > "$TEST_MOCK_DIR/organization_${org_id}.json" << EOF
{
  "name": "organizations/$org_id",
  "organizationId": "$org_id",
  "displayName": "Test Organization",
  "lifecycleState": "ACTIVE",
  "creationTime": "2023-01-01T00:00:00.000Z"
}
EOF
}

# Create test IAM permissions data
create_test_permissions_data() {
    local project_id="${1:-test-project-123}"
    shift
    local permissions=("$@")
    
    local permissions_json=""
    for perm in "${permissions[@]}"; do
        if [[ -n "$permissions_json" ]]; then
            permissions_json+=","
        fi
        permissions_json+="\"$perm\""
    done
    
    cat > "$TEST_MOCK_DIR/permissions_${project_id}.json" << EOF
{
  "permissions": [$permissions_json]
}
EOF
}

# =============================================================================
# Test Assertion Helper Functions
# =============================================================================

# Assert that a file exists
assert_file_exists() {
    local file_path="$1"
    if [[ ! -f "$file_path" ]]; then
        echo "Assertion failed: File '$file_path' does not exist" >&2
        return 1
    fi
}

# Assert that a directory exists
assert_directory_exists() {
    local dir_path="$1"
    if [[ ! -d "$dir_path" ]]; then
        echo "Assertion failed: Directory '$dir_path' does not exist" >&2
        return 1
    fi
}

# Assert that a variable is set
assert_variable_set() {
    local var_name="$1"
    local var_value="${!var_name}"
    if [[ -z "$var_value" ]]; then
        echo "Assertion failed: Variable '$var_name' is not set" >&2
        return 1
    fi
}

# Assert that a variable equals expected value
assert_variable_equals() {
    local var_name="$1"
    local expected="$2"
    local actual="${!var_name}"
    if [[ "$actual" != "$expected" ]]; then
        echo "Assertion failed: Variable '$var_name' expected '$expected', got '$actual'" >&2
        return 1
    fi
}

# Assert that output contains expected string
assert_output_contains() {
    local expected="$1"
    if [[ ! "$output" =~ $expected ]]; then
        echo "Assertion failed: Output does not contain '$expected'" >&2
        echo "Actual output: $output" >&2
        return 1
    fi
}

# Assert that output does not contain string
assert_output_not_contains() {
    local unexpected="$1"
    if [[ "$output" =~ $unexpected ]]; then
        echo "Assertion failed: Output contains unexpected '$unexpected'" >&2
        echo "Actual output: $output" >&2
        return 1
    fi
}

# Assert that status code equals expected value
assert_status_equals() {
    local expected="$1"
    if [[ "$status" != "$expected" ]]; then
        echo "Assertion failed: Status expected '$expected', got '$status'" >&2
        return 1
    fi
}

# Assert that array has expected length
assert_array_length() {
    local array_name="$1"
    local expected_length="$2"
    local -n array_ref="$array_name"
    local actual_length="${#array_ref[@]}"
    
    if [[ "$actual_length" != "$expected_length" ]]; then
        echo "Assertion failed: Array '$array_name' expected length '$expected_length', got '$actual_length'" >&2
        return 1
    fi
}

# Assert that array contains expected value
assert_array_contains() {
    local array_name="$1"
    local expected_value="$2"
    local -n array_ref="$array_name"
    
    for value in "${array_ref[@]}"; do
        if [[ "$value" == "$expected_value" ]]; then
            return 0
        fi
    done
    
    echo "Assertion failed: Array '$array_name' does not contain '$expected_value'" >&2
    echo "Array contents: ${array_ref[*]}" >&2
    return 1
}

# =============================================================================
# Test Utility Functions
# =============================================================================

# Generate random test identifier
generate_test_id() {
    echo "test_$(date +%s)_$$_$RANDOM"
}

# Create temporary test file with content
create_test_file() {
    local filename="$1"
    local content="$2"
    local filepath="$TEST_TMPDIR/$filename"
    
    echo "$content" > "$filepath"
    echo "$filepath"
}

# Wait for condition with timeout
wait_for_condition() {
    local condition="$1"
    local timeout="${2:-10}"
    local interval="${3:-1}"
    
    local count=0
    while ! eval "$condition"; do
        sleep "$interval"
        count=$((count + interval))
        if [[ $count -ge $timeout ]]; then
            echo "Timeout waiting for condition: $condition" >&2
            return 1
        fi
    done
    return 0
}

# Log test message for debugging
log_test_message() {
    local level="$1"
    local message="$2"
    echo "[TEST-$level] $message" >&2
}

# Get test duration since start
get_test_duration() {
    if [[ -n "$TEST_START_TIME" ]]; then
        echo $(($(date +%s) - TEST_START_TIME))
    else
        echo "0"
    fi
}

# Mark test start time
mark_test_start() {
    export TEST_START_TIME=$(date +%s)
}

# =============================================================================
# Test Data Generation Functions
# =============================================================================

# Generate sample GCP project list
generate_sample_projects() {
    local count="${1:-3}"
    
    cat > "$TEST_MOCK_DIR/sample_projects.json" << 'EOF'
[
  {
    "projectId": "sample-project-1",
    "name": "Sample Project 1",
    "projectNumber": "123456789001"
  },
  {
    "projectId": "sample-project-2",
    "name": "Sample Project 2",
    "projectNumber": "123456789002"
  },
  {
    "projectId": "sample-project-3",
    "name": "Sample Project 3",
    "projectNumber": "123456789003"
  }
]
EOF
}

# Generate sample IAM roles
generate_sample_iam_roles() {
    cat > "$TEST_MOCK_DIR/sample_iam_roles.json" << 'EOF'
[
  {
    "name": "roles/viewer",
    "title": "Viewer",
    "description": "Read access to all resources"
  },
  {
    "name": "roles/editor",
    "title": "Editor",
    "description": "Edit access to all resources"
  },
  {
    "name": "roles/owner",
    "title": "Owner",
    "description": "Full access to all resources"
  }
]
EOF
}

# Generate sample compute instances
generate_sample_compute_instances() {
    local project_id="${1:-test-project-123}"
    
    cat > "$TEST_MOCK_DIR/compute_instances_${project_id}.json" << EOF
[
  {
    "name": "instance-1",
    "zone": "us-central1-a",
    "machineType": "e2-medium",
    "status": "RUNNING"
  },
  {
    "name": "instance-2",
    "zone": "us-central1-b",
    "machineType": "e2-small",
    "status": "TERMINATED"
  }
]
EOF
}

# Export all functions for use in tests
export -f setup_test_environment cleanup_test_environment
export -f load_gcp_common_library load_gcp_permissions_library create_mock_lib_directory
export -f create_test_project_data create_test_organization_data create_test_permissions_data
export -f assert_file_exists assert_directory_exists assert_variable_set assert_variable_equals
export -f assert_output_contains assert_output_not_contains assert_status_equals
export -f assert_array_length assert_array_contains
export -f generate_test_id create_test_file wait_for_condition log_test_message
export -f get_test_duration mark_test_start
export -f generate_sample_projects generate_sample_iam_roles generate_sample_compute_instances