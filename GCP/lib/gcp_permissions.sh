#!/usr/bin/env bash
# GCP Permissions Library - Core Permission Management
declare -A PERMISSION_RESULTS
declare -A ROLE_RESULTS
declare -a REQUIRED_PERMISSIONS
declare -a REQUIRED_ROLES
declare -a OPTIONAL_PERMISSIONS
PERMISSION_COVERAGE_PERCENTAGE=0
MISSING_PERMISSIONS_COUNT=0
AVAILABLE_PERMISSIONS_COUNT=0
MISSING_ROLES_COUNT=0
AVAILABLE_ROLES_COUNT=0

# Standard GCP roles required for PCI DSS assessment
declare -A STANDARD_PCI_ROLES=(
    ["roles/viewer"]="Viewer"
    ["roles/iam.securityReviewer"]="Security Reviewer"
    ["roles/logging.viewer"]="Logging Viewer"
    ["roles/monitoring.viewer"]="Monitoring Viewer"
    ["roles/cloudasset.viewer"]="Cloud Asset Viewer"
    ["roles/accesscontextmanager.policyReader"]="Access Context Manager Policy Reader"
)

# Check if current user has required standard GCP roles
check_standard_roles() {
    print_status "INFO" "Checking standard GCP roles for PCI DSS assessment..."
    
    # Get current user email
    local current_user
    current_user=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -1)
    
    if [[ -z "$current_user" ]]; then
        print_status "FAIL" "Cannot determine current authenticated user"
        return 1
    fi
    
    print_status "INFO" "Checking roles for user: $current_user"
    
    AVAILABLE_ROLES_COUNT=0
    MISSING_ROLES_COUNT=0
    ROLE_RESULTS=()
    
    # Check each standard PCI role
    for role in "${!STANDARD_PCI_ROLES[@]}"; do
        local role_name="${STANDARD_PCI_ROLES[$role]}"
        
        if [[ -n "$PROJECT_ID" ]]; then
            # Check project-level role binding
            if gcloud projects get-iam-policy "$PROJECT_ID" --format="value(bindings.members)" 2>/dev/null | \
               grep -q "user:$current_user" && \
               gcloud projects get-iam-policy "$PROJECT_ID" --format="value(bindings[role=$role].members)" 2>/dev/null | \
               grep -q "user:$current_user"; then
                ROLE_RESULTS["$role"]="AVAILABLE"
                ((AVAILABLE_ROLES_COUNT++))
                print_status "PASS" "✓ $role_name ($role)"
            else
                ROLE_RESULTS["$role"]="MISSING"
                ((MISSING_ROLES_COUNT++))
                print_status "FAIL" "✗ $role_name ($role)"
            fi
        elif [[ -n "$ORG_ID" ]]; then
            # Check organization-level role binding
            if gcloud organizations get-iam-policy "$ORG_ID" --format="value(bindings.members)" 2>/dev/null | \
               grep -q "user:$current_user" && \
               gcloud organizations get-iam-policy "$ORG_ID" --format="value(bindings[role=$role].members)" 2>/dev/null | \
               grep -q "user:$current_user"; then
                ROLE_RESULTS["$role"]="AVAILABLE"
                ((AVAILABLE_ROLES_COUNT++))
                print_status "PASS" "✓ $role_name ($role)"
            else
                ROLE_RESULTS["$role"]="MISSING"
                ((MISSING_ROLES_COUNT++))
                print_status "FAIL" "✗ $role_name ($role)"
            fi
        fi
    done
    
    local total_roles=${#STANDARD_PCI_ROLES[@]}
    local role_coverage_percentage=$((AVAILABLE_ROLES_COUNT * 100 / total_roles))
    
    print_status "INFO" "Role check: ${AVAILABLE_ROLES_COUNT}/${total_roles} available (${role_coverage_percentage}%)"
    
    if [[ $MISSING_ROLES_COUNT -gt 0 ]]; then
        print_status "WARN" "Missing ${MISSING_ROLES_COUNT} required standard roles"
        echo ""
        print_status "INFO" "Required standard roles for PCI DSS assessment:"
        for role in "${!STANDARD_PCI_ROLES[@]}"; do
            local role_name="${STANDARD_PCI_ROLES[$role]}"
            local status="${ROLE_RESULTS[$role]:-MISSING}"
            if [[ "$status" == "MISSING" ]]; then
                print_status "WARN" "  - $role_name ($role)"
            fi
        done
        echo ""
        print_status "INFO" "Please ensure the current user has these standard roles assigned"
        return 1
    fi
    
    print_status "PASS" "All required standard roles are available"
    return 0
}

register_required_permissions() {
    local req_num="$1"
    shift
    local permissions=("$@")
    
    if [[ -z "$req_num" || ${#permissions[@]} -eq 0 ]]; then
        print_status "FAIL" "Invalid parameters for permission registration"
        return 1
    fi
    
    REQUIRED_PERMISSIONS=("${permissions[@]}")
    print_status "PASS" "Registered ${#REQUIRED_PERMISSIONS[@]} permissions for Requirement $req_num"
    
    if [[ "$VERBOSE" == "true" ]]; then
        for perm in "${REQUIRED_PERMISSIONS[@]}"; do
            print_status "INFO" "  - $perm"
        done
    fi
    return 0
}

check_all_permissions() {
    if [[ ${#REQUIRED_PERMISSIONS[@]} -eq 0 ]]; then
        print_status "WARN" "No permissions registered to check"
        return 0
    fi
    
    print_status "INFO" "Checking ${#REQUIRED_PERMISSIONS[@]} required permissions..."
    
    AVAILABLE_PERMISSIONS_COUNT=0
    MISSING_PERMISSIONS_COUNT=0
    PERMISSION_RESULTS=()
    
    for permission in "${REQUIRED_PERMISSIONS[@]}"; do
        if [[ -n "$PROJECT_ID" ]] && \
           gcloud projects test-iam-permissions "$PROJECT_ID" \
           --permissions="$permission" --format="value(permissions)" 2>/dev/null | \
           grep -q "$permission"; then
            PERMISSION_RESULTS["$permission"]="AVAILABLE"
            ((AVAILABLE_PERMISSIONS_COUNT++))
            print_status "PASS" "✓ $permission"
        else
            PERMISSION_RESULTS["$permission"]="MISSING"
            ((MISSING_PERMISSIONS_COUNT++))
            print_status "FAIL" "✗ $permission"
        fi
    done
    
    if [[ ${#REQUIRED_PERMISSIONS[@]} -gt 0 ]]; then
        PERMISSION_COVERAGE_PERCENTAGE=$((AVAILABLE_PERMISSIONS_COUNT * 100 / ${#REQUIRED_PERMISSIONS[@]}))
    else
        PERMISSION_COVERAGE_PERCENTAGE=100
    fi
    
    print_status "INFO" "Permission check: ${AVAILABLE_PERMISSIONS_COUNT}/${#REQUIRED_PERMISSIONS[@]} available (${PERMISSION_COVERAGE_PERCENTAGE}%)"
    
    [[ $MISSING_PERMISSIONS_COUNT -eq 0 ]]
}

get_permission_coverage() {
    echo "$PERMISSION_COVERAGE_PERCENTAGE"
}

prompt_continue_limited() {
    local coverage=$(get_permission_coverage)
    
    echo
    print_status "WARN" "Limited permissions detected (${coverage}% coverage)"
    print_status "INFO" "Missing ${MISSING_PERMISSIONS_COUNT} of ${#REQUIRED_PERMISSIONS[@]} required permissions"
    
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
    echo
    
    while true; do
        read -p "Continue with limited permissions? [y/N]: " response
        case "$response" in
            [Yy]|[Yy][Ee][Ss])
                print_status "PASS" "Continuing with limited permissions"
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

# Comprehensive permission check combining roles and specific permissions
check_required_permissions() {
    local requirement_permissions=("$@")
    
    print_status "INFO" "=== PCI DSS PERMISSION VALIDATION ==="
    echo ""
    
    # First check standard GCP roles
    print_status "INFO" "Step 1: Checking standard GCP roles..."
    local roles_ok=true
    if ! check_standard_roles; then
        roles_ok=false
    fi
    
    echo ""
    
    # Then check specific permissions if provided
    if [[ ${#requirement_permissions[@]} -gt 0 ]]; then
        print_status "INFO" "Step 2: Checking requirement-specific permissions..."
        REQUIRED_PERMISSIONS=("${requirement_permissions[@]}")
        if ! check_all_permissions; then
            local coverage=$(get_permission_coverage)
            if [[ $coverage -lt 80 ]]; then
                print_status "WARN" "Low permission coverage for requirement-specific checks"
            fi
        fi
    else
        print_status "INFO" "Step 2: No requirement-specific permissions to check"
    fi
    
    echo ""
    print_status "INFO" "=== PERMISSION VALIDATION SUMMARY ==="
    
    # Determine overall status
    if [[ "$roles_ok" == "true" ]]; then
        print_status "PASS" "✓ Standard GCP roles: All required roles available"
    else
        print_status "FAIL" "✗ Standard GCP roles: Missing required roles"
    fi
    
    if [[ ${#requirement_permissions[@]} -gt 0 ]]; then
        local coverage=$(get_permission_coverage)
        if [[ $coverage -eq 100 ]]; then
            print_status "PASS" "✓ Requirement permissions: All permissions available"
        else
            print_status "WARN" "⚠ Requirement permissions: ${coverage}% coverage"
        fi
    fi
    
    echo ""
    
    # Overall decision
    if [[ "$roles_ok" == "true" ]]; then
        if [[ ${#requirement_permissions[@]} -eq 0 ]] || [[ $(get_permission_coverage) -ge 80 ]]; then
            print_status "PASS" "Permission validation successful - proceeding with assessment"
            return 0
        else
            print_status "WARN" "Some requirement-specific permissions missing"
            return $(prompt_continue_limited; echo $?)
        fi
    else
        print_status "FAIL" "Critical standard roles missing - assessment quality will be significantly impacted"
        echo ""
        print_status "INFO" "Recommendation: Assign the missing standard roles before proceeding"
        return $(prompt_continue_limited; echo $?)
    fi
}

validate_scope_permissions() {
    print_status "INFO" "Validating scope permissions..."
    if [[ -z "$PROJECT_ID" && -z "$ORG_ID" ]]; then
        print_status "FAIL" "No project or organization scope defined"
        return 1
    fi
    if [[ -n "$PROJECT_ID" ]]; then
        if gcloud projects describe "$PROJECT_ID" &> /dev/null; then
            print_status "PASS" "Project scope validated: $PROJECT_ID"
        else
            print_status "FAIL" "Cannot access project: $PROJECT_ID"
            return 1
        fi
    fi
    if [[ -n "$ORG_ID" ]]; then
        if gcloud organizations describe "$ORG_ID" &> /dev/null; then
            print_status "PASS" "Organization scope validated: $ORG_ID"
        else
            print_status "FAIL" "Cannot access organization: $ORG_ID"
            return 1
        fi
    fi
    return 0
}

if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
    echo "Error: gcp_common.sh must be loaded before gcp_permissions.sh" >&2
    exit 1
fi
# Initialize global variables
PERMISSION_RESULTS=()
ROLE_RESULTS=()
REQUIRED_PERMISSIONS=()
REQUIRED_ROLES=()
OPTIONAL_PERMISSIONS=()
PERMISSION_COVERAGE_PERCENTAGE=0
MISSING_PERMISSIONS_COUNT=0
AVAILABLE_PERMISSIONS_COUNT=0
MISSING_ROLES_COUNT=0
AVAILABLE_ROLES_COUNT=0

# Export all functions
export -f check_standard_roles register_required_permissions check_all_permissions get_permission_coverage prompt_continue_limited check_required_permissions validate_scope_permissions
export GCP_PERMISSIONS_LOADED="true"