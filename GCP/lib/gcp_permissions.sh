#!/usr/bin/env bash
# GCP Permissions Library - Core Permission Management (150 line limit)
declare -A PERMISSION_RESULTS
declare -a REQUIRED_PERMISSIONS
declare -a OPTIONAL_PERMISSIONS
PERMISSION_COVERAGE_PERCENTAGE=0
MISSING_PERMISSIONS_COUNT=0
AVAILABLE_PERMISSIONS_COUNT=0

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
PERMISSION_RESULTS=()
REQUIRED_PERMISSIONS=()
OPTIONAL_PERMISSIONS=()
PERMISSION_COVERAGE_PERCENTAGE=0
MISSING_PERMISSIONS_COUNT=0
AVAILABLE_PERMISSIONS_COUNT=0
export -f register_required_permissions check_all_permissions get_permission_coverage prompt_continue_limited validate_scope_permissions
export GCP_PERMISSIONS_LOADED="true"