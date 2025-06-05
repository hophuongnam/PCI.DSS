#!/usr/bin/env bash

# =============================================================================
# GCP Permissions Library - Permission Management Framework
# =============================================================================
# Description: Manages GCP IAM permission validation and coverage reporting
# Version: 1.0
# Author: PCI DSS Assessment Framework
# Created: 2025-06-05
# =============================================================================

# Global Variables for Permissions Library State
GCP_PERMISSIONS_LOADED="true"

# Permission Management Global Arrays
declare -A PERMISSION_RESULTS
declare -a REQUIRED_PERMISSIONS
declare -a OPTIONAL_PERMISSIONS

# Permission Coverage Variables
PERMISSION_COVERAGE_PERCENTAGE=0
MISSING_PERMISSIONS_COUNT=0
AVAILABLE_PERMISSIONS_COUNT=0

# =============================================================================
# Core Framework Implementation
# =============================================================================

# Initialize permissions framework with proper sourcing patterns
# Usage: init_permissions_framework
# Returns: 0 on success, 1 on error
init_permissions_framework() {
    # Ensure gcp_common.sh is loaded first
    if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
        echo -e "${RED}Error: gcp_common.sh must be loaded before gcp_permissions.sh${NC}" >&2
        return 1
    fi
    
    # Initialize global arrays
    PERMISSION_RESULTS=()
    REQUIRED_PERMISSIONS=()
    OPTIONAL_PERMISSIONS=()
    
    # Reset counters
    PERMISSION_COVERAGE_PERCENTAGE=0
    MISSING_PERMISSIONS_COUNT=0
    AVAILABLE_PERMISSIONS_COUNT=0
    
    print_status "PASS" "GCP Permissions Framework initialized"
    return 0
}

# Validate authentication and setup environment for permission checking
# Usage: validate_authentication_setup
# Returns: 0 on success, 1 on error
validate_authentication_setup() {
    print_status "INFO" "Validating GCP authentication setup..."
    
    # Check gcloud authentication status
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        print_status "FAIL" "gcloud not authenticated. Run 'gcloud auth login'"
        return 1
    fi
    
    local active_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)
    print_status "PASS" "Authenticated as: $active_account"
    
    # Detect authentication type
    if [[ "$active_account" == *"@"*".iam.gserviceaccount.com" ]]; then
        export AUTH_TYPE="service_account"
        print_status "INFO" "Using service account authentication"
    else
        export AUTH_TYPE="user_credential"
        print_status "INFO" "Using user credential authentication"
    fi
    
    return 0
}

# Detect and validate scope (project vs organization)
# Usage: detect_and_validate_scope
# Returns: 0 on success, 1 on error
detect_and_validate_scope() {
    print_status "INFO" "Detecting assessment scope..."
    
    # If PROJECT_ID is set, validate project access
    if [[ -n "$PROJECT_ID" ]]; then
        if gcloud projects describe "$PROJECT_ID" &> /dev/null; then
            export DETECTED_SCOPE="project"
            export ASSESSMENT_PROJECT_ID="$PROJECT_ID"
            print_status "PASS" "Project scope validated: $PROJECT_ID"
        else
            print_status "FAIL" "Cannot access project: $PROJECT_ID"
            return 1
        fi
    fi
    
    # If ORG_ID is set, validate organization access
    if [[ -n "$ORG_ID" ]]; then
        if gcloud organizations describe "$ORG_ID" &> /dev/null; then
            export DETECTED_SCOPE="organization"
            export ASSESSMENT_ORG_ID="$ORG_ID"
            print_status "PASS" "Organization scope validated: $ORG_ID"
        else
            print_status "FAIL" "Cannot access organization: $ORG_ID"
            return 1
        fi
    fi
    
    # If neither is set, try to detect current project
    if [[ -z "$PROJECT_ID" && -z "$ORG_ID" ]]; then
        local current_project=$(gcloud config get-value project 2>/dev/null)
        if [[ -n "$current_project" ]]; then
            export DETECTED_SCOPE="project"
            export ASSESSMENT_PROJECT_ID="$current_project"
            export PROJECT_ID="$current_project"
            print_status "PASS" "Auto-detected project scope: $current_project"
        else
            print_status "FAIL" "No project or organization specified and no default project set"
            return 1
        fi
    fi
    
    return 0
}

# =============================================================================
# Permission Management System
# =============================================================================

# Register API permissions required for a specific requirement
# Usage: register_required_permissions REQUIREMENT_NUMBER PERMISSIONS_ARRAY
# Parameters:
#   REQUIREMENT_NUMBER: PCI DSS requirement number (1-8)
#   PERMISSIONS_ARRAY: Array of required GCP IAM permissions
# Returns: 0 on success
register_required_permissions() {
    local req_num="$1"
    shift
    local permissions=("$@")
    
    if [[ -z "$req_num" ]]; then
        print_status "FAIL" "Requirement number is required"
        return 1
    fi
    
    if [[ ${#permissions[@]} -eq 0 ]]; then
        print_status "WARN" "No permissions specified for requirement $req_num"
        return 0
    fi
    
    # Store permissions in global array
    REQUIRED_PERMISSIONS=("${permissions[@]}")
    
    print_status "PASS" "Registered ${#REQUIRED_PERMISSIONS[@]} required permissions for Requirement $req_num"
    
    # Log permissions in verbose mode
    if [[ "$VERBOSE" == "true" ]]; then
        print_status "INFO" "Required permissions:"
        for perm in "${REQUIRED_PERMISSIONS[@]}"; do
            print_status "INFO" "  - $perm"
        done
    fi
    
    return 0
}

# Check a single permission against current user/service account
# Usage: check_single_permission PERMISSION
# Returns: 0 if permission available, 1 if missing
check_single_permission() {
    local permission="$1"
    local resource=""
    
    if [[ -z "$permission" ]]; then
        return 1
    fi
    
    # Determine resource context for permission check
    if [[ "$DETECTED_SCOPE" == "organization" && -n "$ASSESSMENT_ORG_ID" ]]; then
        resource="organizations/$ASSESSMENT_ORG_ID"
    elif [[ "$DETECTED_SCOPE" == "project" && -n "$ASSESSMENT_PROJECT_ID" ]]; then
        resource="projects/$ASSESSMENT_PROJECT_ID"
    else
        print_status "WARN" "No valid scope detected for permission check"
        return 1
    fi
    
    # Use gcloud to test permission
    if gcloud auth print-access-token &> /dev/null && \
       gcloud projects test-iam-permissions "$ASSESSMENT_PROJECT_ID" --permissions="$permission" --format="value(permissions)" 2>/dev/null | grep -q "$permission"; then
        log_debug "Permission available: $permission"
        return 0
    else
        log_debug "Permission missing: $permission"
        return 1
    fi
}

# Check all registered permissions against current user/service account
# Usage: check_all_permissions
# Returns: 0 if all permissions available, 1 if any missing
check_all_permissions() {
    if [[ ${#REQUIRED_PERMISSIONS[@]} -eq 0 ]]; then
        print_status "WARN" "No permissions registered to check"
        return 0
    fi
    
    print_status "INFO" "Checking ${#REQUIRED_PERMISSIONS[@]} required permissions..."
    
    # Reset counters and results
    AVAILABLE_PERMISSIONS_COUNT=0
    MISSING_PERMISSIONS_COUNT=0
    PERMISSION_RESULTS=()
    
    # Check each permission
    for permission in "${REQUIRED_PERMISSIONS[@]}"; do
        if check_single_permission "$permission"; then
            PERMISSION_RESULTS["$permission"]="AVAILABLE"
            ((AVAILABLE_PERMISSIONS_COUNT++))
            print_status "PASS" "✓ $permission"
        else
            PERMISSION_RESULTS["$permission"]="MISSING"
            ((MISSING_PERMISSIONS_COUNT++))
            print_status "FAIL" "✗ $permission"
        fi
    done
    
    # Calculate coverage percentage
    if [[ ${#REQUIRED_PERMISSIONS[@]} -gt 0 ]]; then
        PERMISSION_COVERAGE_PERCENTAGE=$((AVAILABLE_PERMISSIONS_COUNT * 100 / ${#REQUIRED_PERMISSIONS[@]}))
    else
        PERMISSION_COVERAGE_PERCENTAGE=100
    fi
    
    print_status "INFO" "Permission check completed: ${AVAILABLE_PERMISSIONS_COUNT}/${#REQUIRED_PERMISSIONS[@]} available (${PERMISSION_COVERAGE_PERCENTAGE}%)"
    
    if [[ $MISSING_PERMISSIONS_COUNT -eq 0 ]]; then
        print_status "PASS" "All required permissions are available"
        return 0
    else
        print_status "WARN" "$MISSING_PERMISSIONS_COUNT permissions are missing"
        return 1
    fi
}

# Calculate permission coverage percentage
# Usage: get_permission_coverage
# Returns: Permission coverage percentage (0-100)
get_permission_coverage() {
    echo "$PERMISSION_COVERAGE_PERCENTAGE"
}

# Validate scope-specific permissions for project or organization assessment
# Usage: validate_scope_permissions
# Returns: 0 on success, 1 on error
validate_scope_permissions() {
    print_status "INFO" "Validating scope-specific permissions..."
    
    case "$DETECTED_SCOPE" in
        "project")
            # Project-specific permission validation
            if [[ -z "$ASSESSMENT_PROJECT_ID" ]]; then
                print_status "FAIL" "Project ID not set for project scope validation"
                return 1
            fi
            
            # Test basic project access
            if ! gcloud projects describe "$ASSESSMENT_PROJECT_ID" &> /dev/null; then
                print_status "FAIL" "Cannot access project: $ASSESSMENT_PROJECT_ID"
                return 1
            fi
            
            print_status "PASS" "Project scope permissions validated for: $ASSESSMENT_PROJECT_ID"
            ;;
            
        "organization")
            # Organization-specific permission validation
            if [[ -z "$ASSESSMENT_ORG_ID" ]]; then
                print_status "FAIL" "Organization ID not set for organization scope validation"
                return 1
            fi
            
            # Test basic organization access
            if ! gcloud organizations describe "$ASSESSMENT_ORG_ID" &> /dev/null; then
                print_status "FAIL" "Cannot access organization: $ASSESSMENT_ORG_ID"
                return 1
            fi
            
            print_status "PASS" "Organization scope permissions validated for: $ASSESSMENT_ORG_ID"
            ;;
            
        *)
            print_status "FAIL" "Unknown scope type: $DETECTED_SCOPE"
            return 1
            ;;
    esac
    
    return 0
}

# =============================================================================
# User Interaction Framework
# =============================================================================

# Standardized user interaction function for limited access scenarios
# Usage: prompt_continue_limited
# Returns: 0 if user chooses to continue, 1 if user cancels
prompt_continue_limited() {
    local coverage=$(get_permission_coverage)
    
    echo
    print_status "WARN" "Limited permissions detected (${coverage}% coverage)"
    print_status "INFO" "Missing ${MISSING_PERMISSIONS_COUNT} of ${#REQUIRED_PERMISSIONS[@]} required permissions"
    
    # Show missing permissions
    if [[ "$VERBOSE" == "true" ]]; then
        echo
        print_status "INFO" "Missing permissions:"
        for permission in "${!PERMISSION_RESULTS[@]}"; do
            if [[ "${PERMISSION_RESULTS[$permission]}" == "MISSING" ]]; then
                print_status "INFO" "  - $permission"
            fi
        done
    fi
    
    echo
    print_status "INFO" "Assessment can continue with limited functionality"
    print_status "INFO" "Some checks may be skipped or provide incomplete results"
    echo
    
    while true; do
        read -p "Do you want to continue with limited permissions? [y/N]: " response
        case "$response" in
            [Yy]|[Yy][Ee][Ss])
                print_status "PASS" "Continuing assessment with limited permissions"
                return 0
                ;;
            [Nn]|[Nn][Oo]|"")
                print_status "INFO" "Assessment cancelled by user"
                return 1
                ;;
            *)
                echo "Please answer yes (y) or no (n)"
                ;;
        esac
    done
}

# Display permission requirement guidance
# Usage: display_permission_guidance
display_permission_guidance() {
    echo
    print_status "INFO" "Permission Guidance:"
    print_status "INFO" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [[ "$AUTH_TYPE" == "service_account" ]]; then
        print_status "INFO" "Service Account Authentication:"
        print_status "INFO" "  Grant the following roles to your service account:"
        print_status "INFO" "  - roles/viewer (comprehensive read access)"
        print_status "INFO" "  - roles/iam.securityReviewer (IAM and security access)"
        print_status "INFO" "  - roles/logging.viewer (audit log access)"
        print_status "INFO" "  - roles/monitoring.viewer (monitoring data access)"
    else
        print_status "INFO" "User Authentication:"
        print_status "INFO" "  Ensure your account has the following roles:"
        print_status "INFO" "  - Viewer"
        print_status "INFO" "  - Security Reviewer"
        print_status "INFO" "  - Logs Viewer"
        print_status "INFO" "  - Monitoring Viewer"
    fi
    
    echo
    print_status "INFO" "For detailed permission requirements, see:"
    print_status "INFO" "  https://cloud.google.com/docs/security/compliance/pci-dss"
    echo
}

# Create audit trail and logging for permission checks
# Usage: log_permission_audit_trail
log_permission_audit_trail() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local audit_entry="[$timestamp] Permission Check: ${AVAILABLE_PERMISSIONS_COUNT}/${#REQUIRED_PERMISSIONS[@]} available (${PERMISSION_COVERAGE_PERCENTAGE}%)"
    
    # Log to file if configured
    if [[ -n "$LOG_FILE" ]]; then
        echo "$audit_entry" >> "$LOG_FILE"
        echo "[$timestamp] Authentication: $AUTH_TYPE" >> "$LOG_FILE"
        echo "[$timestamp] Scope: $DETECTED_SCOPE" >> "$LOG_FILE"
        
        # Log detailed permission results
        for permission in "${!PERMISSION_RESULTS[@]}"; do
            echo "[$timestamp] Permission: $permission = ${PERMISSION_RESULTS[$permission]}" >> "$LOG_FILE"
        done
    fi
    
    log_debug "Permission audit trail logged"
}

# =============================================================================
# Library Initialization and Export
# =============================================================================

# Auto-initialize permissions framework when library is sourced
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    # Library is being sourced, not executed directly
    init_permissions_framework
    log_debug "gcp_permissions.sh library loaded"
fi

# Export all functions for use in other scripts
export -f init_permissions_framework
export -f validate_authentication_setup
export -f detect_and_validate_scope
export -f register_required_permissions
export -f check_single_permission
export -f check_all_permissions
export -f get_permission_coverage
export -f validate_scope_permissions
export -f prompt_continue_limited
export -f display_permission_guidance
export -f log_permission_audit_trail

# Mark library as loaded
export GCP_PERMISSIONS_LOADED="true"

print_status "PASS" "GCP Permissions Library v1.0 loaded successfully"