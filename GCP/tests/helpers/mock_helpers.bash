#!/bin/bash
# Mock Helper Functions for GCP PCI DSS Testing Framework
# This file provides mock implementations for GCP services and commands

# Mock GCloud Responses Directory
setup_mock_responses_dir() {
    export MOCK_RESPONSES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/mocks/mock_gcloud_responses"
    mkdir -p "$MOCK_RESPONSES_DIR"
}

# Create Mock Project List Response
create_mock_projects_list() {
    cat > "$MOCK_RESPONSES_DIR/projects_list.json" << 'EOF'
[
  {
    "createTime": "2023-01-01T00:00:00.000Z",
    "lifecycleState": "ACTIVE",
    "name": "Test Project",
    "projectId": "test-project-12345",
    "projectNumber": "123456789012"
  },
  {
    "createTime": "2023-01-01T00:00:00.000Z",
    "lifecycleState": "ACTIVE",
    "name": "Test Project 2",
    "projectId": "test-project-67890",
    "projectNumber": "123456789013"
  }
]
EOF
}

# Create Mock IAM Roles Response
create_mock_iam_roles() {
    cat > "$MOCK_RESPONSES_DIR/iam_roles.json" << 'EOF'
{
  "bindings": [
    {
      "members": [
        "user:test@example.com",
        "serviceAccount:test-sa@test-project-12345.iam.gserviceaccount.com"
      ],
      "role": "roles/viewer"
    },
    {
      "members": [
        "serviceAccount:test-sa@test-project-12345.iam.gserviceaccount.com"
      ],
      "role": "roles/securityReviewer"
    },
    {
      "members": [
        "user:admin@example.com"
      ],
      "role": "roles/owner"
    }
  ],
  "etag": "BwXhqDSGKQQ=",
  "version": 1
}
EOF
}

# Create Mock Compute Instances Response
create_mock_compute_instances() {
    cat > "$MOCK_RESPONSES_DIR/compute_instances.json" << 'EOF'
{
  "items": [
    {
      "id": "1234567890123456789",
      "name": "test-instance-1",
      "status": "RUNNING",
      "zone": "projects/test-project-12345/zones/us-central1-a",
      "machineType": "projects/test-project-12345/zones/us-central1-a/machineTypes/e2-medium",
      "networkInterfaces": [
        {
          "network": "projects/test-project-12345/global/networks/default",
          "subnetwork": "projects/test-project-12345/regions/us-central1/subnetworks/default"
        }
      ]
    }
  ]
}
EOF
}

# Create Mock Security Groups/Firewall Rules Response
create_mock_firewall_rules() {
    cat > "$MOCK_RESPONSES_DIR/firewall_rules.json" << 'EOF'
{
  "items": [
    {
      "allowed": [
        {
          "IPProtocol": "tcp",
          "ports": ["22"]
        }
      ],
      "description": "Allow SSH from anywhere",
      "direction": "INGRESS",
      "id": "1234567890123456789",
      "name": "allow-ssh",
      "network": "projects/test-project-12345/global/networks/default",
      "priority": 1000,
      "sourceRanges": ["0.0.0.0/0"],
      "targetTags": ["ssh-server"]
    },
    {
      "allowed": [
        {
          "IPProtocol": "tcp",
          "ports": ["80", "443"]
        }
      ],
      "description": "Allow HTTP/HTTPS",
      "direction": "INGRESS",
      "id": "1234567890123456790",
      "name": "allow-http-https",
      "network": "projects/test-project-12345/global/networks/default",
      "priority": 1000,
      "sourceRanges": ["0.0.0.0/0"]
    }
  ]
}
EOF
}

# Create Mock Storage Buckets Response
create_mock_storage_buckets() {
    cat > "$MOCK_RESPONSES_DIR/storage_buckets.json" << 'EOF'
{
  "items": [
    {
      "id": "test-bucket-12345",
      "name": "test-bucket-12345",
      "projectNumber": "123456789012",
      "location": "US",
      "storageClass": "STANDARD",
      "encryption": {
        "defaultKmsKeyName": "projects/test-project-12345/locations/us/keyRings/test-ring/cryptoKeys/test-key"
      }
    },
    {
      "id": "test-bucket-public",
      "name": "test-bucket-public",
      "projectNumber": "123456789012",
      "location": "US",
      "storageClass": "STANDARD"
    }
  ]
}
EOF
}

# Mock gcloud command with realistic responses
mock_gcloud_command() {
    local subcommand="$1"
    shift
    local args="$*"
    
    case "$subcommand" in
        "auth")
            case "$args" in
                *"activate-service-account"*)
                    echo "Activated service account credentials for: [test-sa@test-project-12345.iam.gserviceaccount.com]"
                    return 0
                    ;;
                *"list"*)
                    echo "test-sa@test-project-12345.iam.gserviceaccount.com"
                    return 0
                    ;;
                *)
                    echo "Mock auth command: $args"
                    return 0
                    ;;
            esac
            ;;
        "config")
            case "$args" in
                *"set project"*)
                    echo "Updated property [core/project]."
                    return 0
                    ;;
                *"get-value project"*)
                    echo "$TEST_PROJECT_ID"
                    return 0
                    ;;
                *)
                    echo "Mock config command: $args"
                    return 0
                    ;;
            esac
            ;;
        "projects")
            case "$args" in
                *"list"*)
                    if [[ -f "$MOCK_RESPONSES_DIR/projects_list.json" ]]; then
                        cat "$MOCK_RESPONSES_DIR/projects_list.json"
                    else
                        echo '[]'
                    fi
                    return 0
                    ;;
                *)
                    echo '{"projectId":"test-project-12345","name":"Test Project"}'
                    return 0
                    ;;
            esac
            ;;
        "iam")
            case "$args" in
                *"get-iam-policy"*)
                    if [[ -f "$MOCK_RESPONSES_DIR/iam_roles.json" ]]; then
                        cat "$MOCK_RESPONSES_DIR/iam_roles.json"
                    else
                        echo '{"bindings":[]}'
                    fi
                    return 0
                    ;;
                *)
                    echo "Mock IAM command: $args"
                    return 0
                    ;;
            esac
            ;;
        "compute")
            case "$args" in
                *"instances list"*)
                    if [[ -f "$MOCK_RESPONSES_DIR/compute_instances.json" ]]; then
                        cat "$MOCK_RESPONSES_DIR/compute_instances.json"
                    else
                        echo '{"items":[]}'
                    fi
                    return 0
                    ;;
                *"firewall-rules list"*)
                    if [[ -f "$MOCK_RESPONSES_DIR/firewall_rules.json" ]]; then
                        cat "$MOCK_RESPONSES_DIR/firewall_rules.json"
                    else
                        echo '{"items":[]}'
                    fi
                    return 0
                    ;;
                *)
                    echo "Mock compute command: $args"
                    return 0
                    ;;
            esac
            ;;
        "storage")
            case "$args" in
                *"buckets list"*)
                    if [[ -f "$MOCK_RESPONSES_DIR/storage_buckets.json" ]]; then
                        cat "$MOCK_RESPONSES_DIR/storage_buckets.json"
                    else
                        echo '{"items":[]}'
                    fi
                    return 0
                    ;;
                *)
                    echo "Mock storage command: $args"
                    return 0
                    ;;
            esac
            ;;
        *)
            echo "Mock gcloud command: $subcommand $args"
            return 0
            ;;
    esac
}

# Setup comprehensive mock environment
setup_mock_gcp_environment() {
    setup_mock_responses_dir
    create_mock_projects_list
    create_mock_iam_roles
    create_mock_compute_instances
    create_mock_firewall_rules
    create_mock_storage_buckets
    
    # Ensure TEST_TEMP_DIR is set
    if [[ -z "${TEST_TEMP_DIR:-}" ]]; then
        export TEST_TEMP_DIR="$(mktemp -d)"
    fi
    
    # Mock environment variables
    export CLOUDSDK_CORE_PROJECT="test-project-12345"
    export GOOGLE_APPLICATION_CREDENTIALS="$TEST_TEMP_DIR/test-service-account.json"
    export CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=true
    export CLOUDSDK_CORE_DISABLE_COLOR=true
    
    # Replace gcloud with mock
    if command -v gcloud >/dev/null 2>&1; then
        eval "original_gcloud_full() { command gcloud \"\$@\"; }"
    fi
    eval "gcloud() { mock_gcloud_command \"\$@\"; }"
    
    echo "Mock GCP environment setup complete"
}

# Restore original GCP environment
restore_gcp_environment() {
    if declare -f original_gcloud_full >/dev/null 2>&1; then
        eval "gcloud() { original_gcloud_full \"\$@\"; }"
        unset -f original_gcloud_full
    fi
    
    unset CLOUDSDK_CORE_PROJECT GOOGLE_APPLICATION_CREDENTIALS
    unset CLOUDSDK_CORE_DISABLE_USAGE_REPORTING CLOUDSDK_CORE_DISABLE_COLOR
    
    echo "GCP environment restored"
}

# Create mock error scenarios
create_mock_error_scenarios() {
    # Mock authentication failure
    mock_auth_failure() {
        echo "ERROR: (gcloud.auth.activate-service-account) Invalid key file" >&2
        return 1
    }
    
    # Mock permission denied
    mock_permission_denied() {
        echo "ERROR: (gcloud.projects.get-iam-policy) User does not have permission to access project" >&2
        return 1
    }
    
    # Mock network connectivity issue
    mock_network_error() {
        echo "ERROR: (gcloud) Network is unreachable" >&2
        return 1
    }
    
    export -f mock_auth_failure mock_permission_denied mock_network_error
}

# Simulate realistic response times
add_response_delay() {
    local delay_type="${1:-normal}"
    
    case "$delay_type" in
        "fast")
            sleep 0.1
            ;;
        "normal")
            sleep 0.3
            ;;
        "slow")
            sleep 1.0
            ;;
        "timeout")
            sleep 5.0
            ;;
    esac
}

# Mock test data sets
create_test_data_sets() {
    local test_data_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/mocks/mock_data_sets"
    mkdir -p "$test_data_dir"
    
    # PCI DSS test scenarios
    cat > "$test_data_dir/pci_compliant_project.json" << 'EOF'
{
  "project_id": "pci-compliant-project",
  "firewall_rules": [
    {
      "name": "allow-ssh-internal",
      "sourceRanges": ["10.0.0.0/8"]
    }
  ],
  "encryption_keys": [
    {
      "name": "projects/pci-compliant-project/locations/us/keyRings/pci-ring/cryptoKeys/pci-key",
      "state": "ENABLED"
    }
  ]
}
EOF
    
    cat > "$test_data_dir/pci_non_compliant_project.json" << 'EOF'
{
  "project_id": "non-compliant-project",
  "firewall_rules": [
    {
      "name": "allow-all",
      "sourceRanges": ["0.0.0.0/0"],
      "ports": ["*"]
    }
  ],
  "encryption_keys": []
}
EOF
    
    echo "Test data sets created in $test_data_dir"
}

# Export mock functions
export -f setup_mock_responses_dir create_mock_projects_list create_mock_iam_roles
export -f create_mock_compute_instances create_mock_firewall_rules create_mock_storage_buckets
export -f mock_gcloud_command setup_mock_gcp_environment restore_gcp_environment
export -f create_mock_error_scenarios add_response_delay create_test_data_sets