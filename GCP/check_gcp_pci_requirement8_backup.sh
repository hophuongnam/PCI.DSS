#!/usr/bin/env bash

# PCI DSS Requirement 8 Compliance Check Script for GCP
# Identify Users and Authenticate Access to System Components

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="8"

# Initialize environment
setup_environment || exit 1

# Parse command line arguments using shared function
parse_common_arguments "$@"
case $? in
    1) exit 1 ;;  # Error
    2) exit 0 ;;  # Help displayed
esac

# Setup report configuration using shared library
load_requirement_config "${REQUIREMENT_NUMBER}"

# Validate scope and setup project context using shared library
setup_assessment_scope || exit 1

# Check permissions using shared library
check_required_permissions "iam.serviceAccounts.list" "cloudidentity.groups.list" || exit 1

# Initialize HTML report using shared library
# Set output file path
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"

# Initialize HTML report using shared library
initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"











print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 8 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information using shared library
# Display scope information using shared library - now handled in print_status calls
print_status "INFO" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "INFO" "Organization ID: ${ORG_ID}"
else
    print_status "INFO" "Project ID: ${PROJECT_ID}"
fi

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to check user identification and account management
check_user_identification() {
    local details=""
    local found_issues=false
    
    details+="<p>Analysis of user identification and account management:</p>"
    
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        details+="<p><strong>Organization-wide user management assessment:</strong></p>"
        
        # Check Cloud Identity users (if available) at organization level
        local users=$(gcloud identity users list --format="value(name,primaryEmail)" 2>/dev/null)
        
        if [ -n "$users" ]; then
            details+="<p>Cloud Identity users found:</p><ul>"
            
            local shared_accounts=""
            while IFS=$'\t' read -r user_name email; do
                # Check for potential shared/generic accounts
                if [[ "$email" == *"admin"* ]] || [[ "$email" == *"shared"* ]] || [[ "$email" == *"service"* ]] || [[ "$email" == *"system"* ]]; then
                    shared_accounts+="$email, "
                    found_issues=true
                fi
                
                details+="<li>$email</li>"
            done <<< "$users"
            
            details+="</ul>"
            
            if [ -n "$shared_accounts" ]; then
                details+="<p class='red'>Potential shared/generic accounts detected: ${shared_accounts%, }</p>"
            fi
        else
            details+="<p>No Cloud Identity users found or unable to retrieve user list.</p>"
        fi
        
        # Check service accounts across all projects
        local projects=$(get_projects_in_scope)
        details+="<p>Service account analysis across organization:</p><table>"
        details+="<tr><th>Project</th><th>Service Account</th><th>Display Name</th><th>Status</th></tr>"
        
        for project in $projects; do
            local service_accounts=$(gcloud iam service-accounts list --project="$project" --format="value(email,displayName,disabled)" 2>/dev/null)
            
            if [ -n "$service_accounts" ]; then
                while IFS=$'\t' read -r sa_email display_name disabled; do
                    if [ -z "$sa_email" ]; then
                        continue
                    fi
                    
                    local status_class="green"
                    local status_text="Active"
                    
                    if [ "$disabled" = "True" ]; then
                        status_class="yellow"
                        status_text="Disabled (good for unused accounts)"
                    fi
                    
                    details+="<tr><td>$project</td><td>$sa_email</td><td>$display_name</td><td class='$status_class'>$status_text</td></tr>"
                done <<< "$service_accounts"
            fi
        done
        
        details+="</table>"
    else
        # Single project analysis
        local users=$(gcloud identity users list --format="value(name,primaryEmail)" 2>/dev/null)
        
        if [ -n "$users" ]; then
            details+="<p>Cloud Identity users found:</p><ul>"
            
            local shared_accounts=""
            while IFS=$'\t' read -r user_name email; do
                # Check for potential shared/generic accounts
                if [[ "$email" == *"admin"* ]] || [[ "$email" == *"shared"* ]] || [[ "$email" == *"service"* ]] || [[ "$email" == *"system"* ]]; then
                    shared_accounts+="$email, "
                    found_issues=true
                fi
                
                details+="<li>$email</li>"
            done <<< "$users"
            
            details+="</ul>"
            
            if [ -n "$shared_accounts" ]; then
                details+="<p class='red'>Potential shared/generic accounts detected: ${shared_accounts%, }</p>"
            fi
        else
            details+="<p>No Cloud Identity users found or unable to retrieve user list.</p>"
        fi
        
        # Check service accounts for proper naming and management
        local service_accounts=$(gcloud iam service-accounts list --format="value(email,displayName,disabled)" 2>/dev/null)
        
        if [ -n "$service_accounts" ]; then
            details+="<p>Service account analysis:</p><ul>"
            
            while IFS=$'\t' read -r sa_email display_name disabled; do
                if [ "$disabled" = "True" ]; then
                    details+="<li class='yellow'>$sa_email ($display_name) - Disabled (good for unused accounts)</li>"
                else
                    details+="<li>$sa_email ($display_name) - Active</li>"
                fi
            done <<< "$service_accounts"
            
            details+="</ul>"
        else
            details+="<p>No service accounts found in project $DEFAULT_PROJECT.</p>"
        fi
    fi
    
    # Manual verification requirements
    details+="<p><strong>Manual verification required for:</strong></p><ul>"
    details+="<li>Unique user ID assignment before access is granted</li>"
    details+="<li>Group, shared, or generic ID usage controls and approvals</li>"
    details+="<li>Proper authorization for user ID modifications</li>"
    details+="<li>Immediate access revocation for terminated users</li>"
    details+="<li>Inactive account management (90-day rule)</li>"
    details+="</ul>"
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 8 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information using shared library
# Display scope information using shared library - now handled in print_status calls
print_status "INFO" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "INFO" "Organization ID: ${ORG_ID}"
else
    print_status "INFO" "Project ID: ${PROJECT_ID}"
fi

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to check multi-factor authentication
check_mfa_configuration() {
    local details=""
    local found_issues=false
    
    details+="<p>Analysis of multi-factor authentication configuration:</p>"
    
    # Check organization policy for MFA enforcement
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        details+="<p><strong>Organization-wide MFA policy analysis:</strong></p>"
        
        # Check for MFA enforcement policies at organization level
        local org_policies=$(gcloud resource-manager org-policies list --organization="$DEFAULT_ORG" --format="value(constraint)" 2>/dev/null | grep -E "constraints/iam.disableServiceAccountKeyCreation|constraints/compute.requireOsLogin")
        
        if [ -n "$org_policies" ]; then
            details+="<p class='green'>Found organization policies that support MFA enforcement:</p><ul>"
            echo "$org_policies" | while read -r policy; do
                details+="<li>$policy</li>"
            done
            details+="</ul>"
        else
            details+="<p class='yellow'>No MFA-related organization policies found. Consider implementing policies to enforce MFA.</p>"
            found_issues=true
        fi
        
        # Check OS Login configuration across projects
        local projects=$(get_projects_in_scope)
        details+="<p>OS Login configuration across projects:</p><table>"
        details+="<tr><th>Project</th><th>OS Login Enabled</th><th>Instances with OS Login</th><th>Status</th></tr>"
        
        for project in $projects; do
            local project_metadata=$(gcloud compute project-info describe --project="$project" --format="value(commonInstanceMetadata.items)" 2>/dev/null)
            local project_os_login="false"
            
            if echo "$project_metadata" | grep -q "enable-oslogin.*True"; then
                project_os_login="true"
            fi
            
            local instances=$(gcloud compute instances list --project="$project" --format="value(name,zone,metadata.items)" 2>/dev/null)
            local os_login_instances=0
            local total_instances=0
            
            if [ -n "$instances" ]; then
                while IFS=$'\t' read -r instance_name zone metadata; do
                    if [ -n "$instance_name" ]; then
                        ((total_instances++))
                        
                        if echo "$metadata" | grep -q "enable-oslogin.*True"; then
                            ((os_login_instances++))
                        fi
                    fi
                done <<< "$instances"
            fi
            
            local status_class="green"
            local status_text="Good"
            
            if [ "$project_os_login" = "false" ] && [ "$os_login_instances" -eq 0 ]; then
                status_class="red"
                status_text="No OS Login"
                found_issues=true
            elif [ "$os_login_instances" -lt "$total_instances" ]; then
                status_class="yellow"
                status_text="Partial OS Login"
                found_issues=true
            fi
            
            details+="<tr><td>$project</td><td>$project_os_login</td><td>$os_login_instances/$total_instances</td><td class='$status_class'>$status_text</td></tr>"
        done
        
        details+="</table>"
    else
        # Single project analysis
        local mfa_policies=$(gcloud resource-manager org-policies list --project="$DEFAULT_PROJECT" --format="value(constraint)" 2>/dev/null | grep -E "constraints/iam.disableServiceAccountKeyCreation|constraints/compute.requireOsLogin")
        
        if [ -n "$mfa_policies" ]; then
            details+="<p class='green'>Found organization policies that support MFA enforcement:</p><ul>"
            echo "$mfa_policies" | while read -r policy; do
                details+="<li>$policy</li>"
            done
            details+="</ul>"
        else
            details+="<p class='yellow'>No MFA-related organization policies found. Consider implementing policies to enforce MFA.</p>"
            found_issues=true
        fi
        
        # Check for OS Login configuration
        local project_metadata=$(gcloud compute project-info describe --format="value(commonInstanceMetadata.items)" 2>/dev/null)
        
        if echo "$project_metadata" | grep -q "enable-oslogin.*True"; then
            details+="<p class='green'>OS Login is enabled at the project level, which supports centralized authentication and can enforce MFA.</p>"
        else
            details+="<p class='yellow'>OS Login is not enabled at the project level. Consider enabling OS Login for centralized authentication.</p>"
            found_issues=true
        fi
        
        # Check Compute Engine instances for OS Login
        local instances=$(gcloud compute instances list --format="value(name,zone,metadata.items)" 2>/dev/null)
        
        if [ -n "$instances" ]; then
            details+="<p>Compute Engine instance authentication analysis:</p><ul>"
            
            local os_login_enabled=0
            local total_instances=0
            
            while IFS=$'\t' read -r instance_name zone metadata; do
                ((total_instances++))
                
                if echo "$metadata" | grep -q "enable-oslogin.*True"; then
                    ((os_login_enabled++))
                    details+="<li class='green'>$instance_name (Zone: $zone) - OS Login enabled</li>"
                else
                    details+="<li class='yellow'>$instance_name (Zone: $zone) - OS Login not enabled</li>"
                    found_issues=true
                fi
            done <<< "$instances"
            
            details+="</ul>"
            
            if [ "$os_login_enabled" -eq "$total_instances" ]; then
                details+="<p class='green'>All instances have OS Login enabled.</p>"
            else
                details+="<p class='yellow'>$os_login_enabled out of $total_instances instances have OS Login enabled.</p>"
                found_issues=true
            fi
        else
            details+="<p>No Compute Engine instances found in project $DEFAULT_PROJECT.</p>"
        fi
    fi
    
    # Check for Identity-Aware Proxy (supports MFA)
    local iap_resources
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        iap_resources=$(run_gcp_command_across_projects "gcloud iap settings get" "--format='value(name)'")
    else
        iap_resources=$(gcloud iap settings get --project="$DEFAULT_PROJECT" --format="value(name)" 2>/dev/null)
    fi
    
    if [ -n "$iap_resources" ]; then
        details+="<p class='green'>Identity-Aware Proxy is configured, which can enforce MFA for application access.</p>"
    else
        details+="<p class='yellow'>Identity-Aware Proxy is not configured. Consider using IAP for application-level MFA enforcement.</p>"
        found_issues=true
    fi
    
    # Manual verification requirements
    details+="<p><strong>Manual verification required for MFA implementation:</strong></p><ul>"
    details+="<li>MFA enabled for all non-console administrative access to CDE</li>"
    details+="<li>MFA enabled for all non-console access to CDE</li>"
    details+="<li>MFA enabled for all remote access from outside entity's network</li>"
    details+="<li>MFA system configured to prevent replay attacks</li>"
    details+="<li>MFA system requires at least two different authentication factors</li>"
    details+="<li>No MFA bypass capabilities except for documented exceptions</li>"
    details+="</ul>"
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 8 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information using shared library
# Display scope information using shared library - now handled in print_status calls
print_status "INFO" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "INFO" "Organization ID: ${ORG_ID}"
else
    print_status "INFO" "Project ID: ${PROJECT_ID}"
fi

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to check authentication policies and mechanisms
check_authentication_policies() {
    local details=""
    local found_issues=false
    
    details+="<p>Analysis of authentication policies and mechanisms:</p>"
    
    # Check service account key management across scope
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        details+="<p><strong>Organization-wide service account key analysis:</strong></p>"
        
        local projects=$(get_projects_in_scope)
        details+="<table><tr><th>Project</th><th>Service Account</th><th>Key Count</th><th>Old Keys (>90 days)</th><th>Status</th></tr>"
        
        local current_time=$(date +%s)
        
        for project in $projects; do
            local service_accounts=$(gcloud iam service-accounts list --project="$project" --format="value(email)" 2>/dev/null)
            
            for sa_email in $service_accounts; do
                if [ -z "$sa_email" ]; then
                    continue
                fi
                
                # Get service account keys
                local sa_keys=$(gcloud iam service-accounts keys list --iam-account="$sa_email" --format="json" 2>/dev/null)
                
                if [ -n "$sa_keys" ]; then
                    local key_count=$(echo "$sa_keys" | jq -r '. | length' 2>/dev/null)
                    local user_managed_keys=0
                    local old_keys=0
                    
                    for key_info in $(echo "$sa_keys" | jq -c '.[]'); do
                        local key_type=$(echo "$key_info" | jq -r '.keyType' 2>/dev/null)
                        local create_time=$(echo "$key_info" | jq -r '.validAfterTime' 2>/dev/null)
                        
                        if [ "$key_type" = "USER_MANAGED" ]; then
                            ((user_managed_keys++))
                            
                            # Calculate key age
                            local create_epoch=$(date -d "$create_time" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$create_time" +%s 2>/dev/null)
                            
                            if [ -n "$create_epoch" ]; then
                                local days_old=$(( (current_time - create_epoch) / 86400 ))
                                
                                if [ "$days_old" -gt 90 ]; then
                                    ((old_keys++))
                                fi
                            fi
                        fi
                    done
                    
                    # Determine status
                    local status_class="green"
                    local status_text="Good"
                    
                    if [ "$user_managed_keys" -eq 0 ]; then
                        status_text="System-managed only"
                    elif [ "$old_keys" -gt 0 ]; then
                        status_class="red"
                        status_text="Old keys detected"
                        found_issues=true
                    else
                        status_text="All keys recent"
                    fi
                    
                    details+="<tr><td>$project</td><td>$(echo $sa_email | cut -c1-30)...</td><td>$key_count ($user_managed_keys user-managed)</td><td>$old_keys</td><td class='$status_class'>$status_text</td></tr>"
                fi
            done
        done
        
        details+="</table>"
    else
        # Single project analysis
        local service_accounts=$(gcloud iam service-accounts list --format="value(email)" 2>/dev/null)
        
        if [ -n "$service_accounts" ]; then
            details+="<p>Service account key analysis:</p><table>"
            details+="<tr><th>Service Account</th><th>Key Count</th><th>Key Ages</th><th>Status</th></tr>"
            
            local current_time=$(date +%s)
            
            for sa_email in $service_accounts; do
                # Get service account keys
                local sa_keys=$(gcloud iam service-accounts keys list --iam-account="$sa_email" --format="json" 2>/dev/null)
                
                if [ -n "$sa_keys" ]; then
                    local key_count=$(echo "$sa_keys" | jq -r '. | length' 2>/dev/null)
                    local user_managed_keys=0
                    local old_keys=0
                    local key_ages=""
                    
                    for key_info in $(echo "$sa_keys" | jq -c '.[]'); do
                        local key_type=$(echo "$key_info" | jq -r '.keyType' 2>/dev/null)
                        local create_time=$(echo "$key_info" | jq -r '.validAfterTime' 2>/dev/null)
                        
                        if [ "$key_type" = "USER_MANAGED" ]; then
                            ((user_managed_keys++))
                            
                            # Calculate key age
                            local create_epoch=$(date -d "$create_time" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$create_time" +%s 2>/dev/null)
                            
                            if [ -n "$create_epoch" ]; then
                                local days_old=$(( (current_time - create_epoch) / 86400 ))
                                
                                if [ "$days_old" -gt 90 ]; then
                                    ((old_keys++))
                                fi
                                
                                if [ -n "$key_ages" ]; then
                                    key_ages+=", "
                                fi
                                key_ages+="${days_old}d"
                            fi
                        fi
                    done
                    
                    # Determine status
                    local status_class="green"
                    local status_text="System-managed only"
                    
                    if [ "$user_managed_keys" -eq 0 ]; then
                        status_text="System-managed only"
                    elif [ "$old_keys" -gt 0 ]; then
                        status_class="red"
                        status_text="$old_keys old keys (>90 days)"
                        found_issues=true
                    else
                        status_text="All keys recent"
                    fi
                    
                    details+="<tr><td>$sa_email</td><td>$key_count ($user_managed_keys user-managed)</td><td>$key_ages</td><td class='$status_class'>$status_text</td></tr>"
                fi
            done
            
            details+="</table>"
        else
            details+="<p>No service accounts found in project $DEFAULT_PROJECT.</p>"
        fi
    fi
    
    # Manual verification requirements
    details+="<p><strong>Manual verification required for authentication policies:</strong></p><ul>"
    details+="<li>Password/passphrase minimum length of 12 characters</li>"
    details+="<li>Password complexity (numeric and alphabetic characters)</li>"
    details+="<li>Password history prevention (last 4 passwords)</li>"
    details+="<li>Password change requirements (90 days for single-factor)</li>"
    details+="<li>Account lockout after 10 invalid attempts</li>"
    details+="<li>Session timeout after 15 minutes of inactivity</li>"
    details+="<li>First-time password change requirements</li>"
    details+="<li>Authentication factor protection and non-sharing</li>"
    details+="</ul>"
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 8 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information using shared library
# Display scope information using shared library - now handled in print_status calls
print_status "INFO" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "INFO" "Organization ID: ${ORG_ID}"
else
    print_status "INFO" "Project ID: ${PROJECT_ID}"
fi

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to check access monitoring and control
check_access_monitoring() {
    local details=""
    local found_issues=false
    
    details+="<p>Analysis of access monitoring and control mechanisms:</p>"
    
    # Check Cloud Audit Logs across scope
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        details+="<p><strong>Organization-wide audit logging analysis:</strong></p>"
        
        local projects=$(get_projects_in_scope)
        local projects_with_audit_logs=0
        local total_projects=0
        
        for project in $projects; do
            ((total_projects++))
            
            local audit_logs=$(gcloud logging logs list --project="$project" --filter="name~'cloudaudit'" --format="value(name)" 2>/dev/null)
            
            if [ -n "$audit_logs" ]; then
                ((projects_with_audit_logs++))
            fi
        done
        
        details+="<p>Audit logging coverage: $projects_with_audit_logs out of $total_projects projects have audit logs configured</p>"
        
        if [ "$projects_with_audit_logs" -lt "$total_projects" ]; then
            details+="<p class='yellow'>Some projects missing audit log configuration. Ensure Cloud Audit Logs are enabled for all projects.</p>"
            found_issues=true
        else
            details+="<p class='green'>All projects have audit logging configured.</p>"
        fi
        
        # Check for log sinks at organization level
        local org_sinks=$(gcloud logging sinks list --organization="$DEFAULT_ORG" --format="value(name,destination)" 2>/dev/null)
        
        if [ -n "$org_sinks" ]; then
            details+="<p class='green'>Organization-level log sinks configured:</p><ul>"
            echo "$org_sinks" | while IFS=$'\t' read -r sink_name destination; do
                details+="<li>$sink_name → $destination</li>"
            done
            details+="</ul>"
        else
            details+="<p class='yellow'>No organization-level log sinks found. Consider centralized log export and analysis.</p>"
            found_issues=true
        fi
    else
        # Single project analysis
        local audit_logs=$(gcloud logging logs list --filter="name~'cloudaudit'" --format="value(name)" 2>/dev/null)
        
        if [ -n "$audit_logs" ]; then
            details+="<p class='green'>Cloud Audit Logs are configured:</p><ul>"
            echo "$audit_logs" | while read -r log_name; do
                details+="<li>$log_name</li>"
            done
            details+="</ul>"
        else
            details+="<p class='yellow'>No audit logs found. Ensure Cloud Audit Logs are properly configured.</p>"
            found_issues=true
        fi
        
        # Check for log sinks and exports
        local sinks=$(gcloud logging sinks list --format="value(name,destination)" 2>/dev/null)
        
        if [ -n "$sinks" ]; then
            details+="<p class='green'>Log sinks configured for log export and analysis:</p><ul>"
            while IFS=$'\t' read -r sink_name destination; do
                details+="<li>$sink_name → $destination</li>"
            done <<< "$sinks"
            details+="</ul>"
        else
            details+="<p class='yellow'>No log sinks found. Consider exporting logs for long-term storage and analysis.</p>"
            found_issues=true
        fi
    fi
    
    # Check for Security Command Center (if available)
    if [ -n "$DEFAULT_ORG" ]; then
        local auth_findings=$(gcloud scc findings list --organization="organizations/$DEFAULT_ORG" --filter="category:AUTH OR category:IAM" --format="value(name)" --limit=5 2>/dev/null)
        
        if [ -n "$auth_findings" ]; then
            local finding_count=$(echo "$auth_findings" | wc -l)
            details+="<p class='yellow'>$finding_count authentication-related security findings found in Security Command Center. Review these findings.</p>"
            found_issues=true
        else
            details+="<p class='green'>No authentication-related security findings in Security Command Center.</p>"
        fi
    else
        details+="<p class='yellow'>Organization not configured for Security Command Center.</p>"
        found_issues=true
    fi
    
    # Manual verification requirements
    details+="<p><strong>Manual verification required for access monitoring:</strong></p><ul>"
    details+="<li>Regular review of user access and privileges</li>"
    details+="<li>Monitoring of authentication failures and suspicious activities</li>"
    details+="<li>Log retention policies meet PCI DSS requirements</li>"
    details+="<li>Automated alerting for security events</li>"
    details+="<li>Regular access recertification processes</li>"
    details+="<li>Segregation of duties in access management</li>"
    details+="</ul>"
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Validate scope and requirements
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    if [ -z "$DEFAULT_ORG" ]; then
        print_status "FAIL" "Error: Organization scope requires an organization ID."
        print_status "WARN" "Please provide organization ID with --org flag or ensure you have organization access."
        exit 1
    fi
else
    # Project scope validation
    if [ -z "$DEFAULT_PROJECT" ]; then
        print_status "FAIL" "Error: No project specified."
        print_status "WARN" "Please set a default project with: gcloud config set project PROJECT_ID"
        print_status "WARN" "Or specify a project with: --project PROJECT_ID"
        exit 1
    fi
fi

# Start script execution
print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER (GCP)"
print_status "INFO" "  (Identify Users and Authenticate Access)"
print_status "INFO" "============================================="
echo ""

# Display scope information
print_status "INFO" "Assessment Scope: $ASSESSMENT_SCOPE"
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    print_status "INFO" "Organization: $DEFAULT_ORG"
    print_status "WARN" "Note: Organization-wide assessment may take longer and requires broader permissions"
else
    print_status "INFO" "Project: $DEFAULT_PROJECT"
fi
echo ""

# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE"

echo ""
echo "Starting assessment at $(date)"
echo ""

#----------------------------------------------------------------------
# SECTION 1: PERMISSIONS CHECK
#----------------------------------------------------------------------
add_html_section "$OUTPUT_FILE" "GCP Permissions Check" "<p>Verifying access to required GCP services for PCI Requirement $REQUIREMENT_NUMBER assessment...</p>" "info"

print_status "INFO" "=== CHECKING REQUIRED GCP PERMISSIONS ==="

# Check all required permissions based on scope
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    # Organization-wide permission checks
    check_gcp_permission "Projects" "list" "gcloud projects list --filter='parent.id:$DEFAULT_ORG' --limit=1"
    ((total_checks++))
    
    check_gcp_permission "Organizations" "access" "gcloud organizations list --filter='name:organizations/$DEFAULT_ORG' --limit=1"
    ((total_checks++))
fi

# Scope-aware permission checks
PROJECT_FLAG=""
if [ "$ASSESSMENT_SCOPE" == "project" ]; then
    PROJECT_FLAG="--project=$DEFAULT_PROJECT"
fi

# Requirement 8 specific permission checks
check_gcp_permission "Projects" "get-iam-policy" "gcloud projects get-iam-policy $DEFAULT_PROJECT --limit=1"
((total_checks++))

check_gcp_permission "IAM" "service-accounts" "gcloud iam service-accounts list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Identity" "users" "gcloud identity users list --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "instances" "gcloud compute instances list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Logging" "logs" "gcloud logging logs list $PROJECT_FLAG --limit=1"
((total_checks++))

# Calculate permissions percentage
available_permissions=$((total_checks - access_denied_checks))
if [ $available_permissions -gt 0 ]; then
    permissions_percentage=$(( ((total_checks - access_denied_checks) * 100) / total_checks ))
else
    permissions_percentage=0
fi

if [ $permissions_percentage -lt 70 ]; then
    print_status "FAIL" "WARNING: Insufficient permissions to perform a complete PCI Requirement $REQUIREMENT_NUMBER assessment."
    add_html_section "$OUTPUT_FILE" "Permission Assessment" "<p class='red'>Insufficient permissions detected. Only $permissions_percentage% of required permissions are available.</p><p>Without these permissions, the assessment will be incomplete and may not accurately reflect your PCI DSS compliance status.</p>" "fail"
    read -p "Continue with limited assessment? (y/n): " CONTINUE
    if [[ ! $CONTINUE =~ ^[Yy]$ ]]; then
        echo "Assessment aborted."
        exit 1
    fi
else
    print_status "PASS" "Permission check complete: $permissions_percentage% permissions available"
    add_html_section "$OUTPUT_FILE" "Permission Assessment" "<p class='green'>Sufficient permissions detected. $permissions_percentage% of required permissions are available.</p>" "pass"
fi

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

#----------------------------------------------------------------------
# SECTION 2: REQUIREMENT 8 ASSESSMENT LOGIC
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT $REQUIREMENT_NUMBER: IDENTIFY USERS AND AUTHENTICATE ACCESS ==="

# Requirement 8.2: User identification and account management
add_html_section "$OUTPUT_FILE" "Requirement 8.2: User identification and account management" "<p>Verifying user identification and account management implementation...</p>" "info"

# Check 8.2.1-8.2.8 - User identification and account management
print_status "INFO" "Checking user identification and account management..."
user_id_details=$(check_user_identification)
if [[ "$user_id_details" == *"class='red'"* ]] || [[ "$user_id_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "8.2.1-8.2.8 - User identification and account management" "$user_id_details<p><strong>Remediation:</strong> Implement proper user identification and account management controls using Cloud Identity and IAM best practices.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "8.2.1-8.2.8 - User identification and account management" "$user_id_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Requirement 8.3: Strong authentication is implemented
add_html_section "$OUTPUT_FILE" "Requirement 8.3: Strong authentication" "<p>Verifying strong authentication mechanisms and policies...</p>" "info"

# Check 8.3.1-8.3.11 - Authentication policies and mechanisms
print_status "INFO" "Checking authentication policies and mechanisms..."
auth_details=$(check_authentication_policies)
if [[ "$auth_details" == *"class='red'"* ]] || [[ "$auth_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "8.3.1-8.3.11 - Strong authentication mechanisms" "$auth_details<p><strong>Remediation:</strong> Implement strong authentication mechanisms including proper password policies, service account key management, and credential protection.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "8.3.1-8.3.11 - Strong authentication mechanisms" "$auth_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Requirement 8.4: Multi-factor authentication (MFA) is implemented
add_html_section "$OUTPUT_FILE" "Requirement 8.4: Multi-factor authentication" "<p>Verifying MFA implementation and configuration...</p>" "info"

# Check 8.4.1-8.4.3 - MFA requirements
print_status "INFO" "Checking multi-factor authentication configuration..."
mfa_details=$(check_mfa_configuration)
if [[ "$mfa_details" == *"class='red'"* ]] || [[ "$mfa_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "8.4.1-8.4.3 - Multi-factor authentication" "$mfa_details<p><strong>Remediation:</strong> Implement MFA for all access to CDE using OS Login, IAP, and organization policies. Ensure MFA is enforced for administrative and remote access.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "8.4.1-8.4.3 - Multi-factor authentication" "$mfa_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Requirement 8.6: Application and system account management
add_html_section "$OUTPUT_FILE" "Requirement 8.6: System account management" "<p>Verifying system account management and access monitoring...</p>" "info"

# Check access monitoring and control mechanisms
print_status "INFO" "Checking access monitoring and control mechanisms..."
monitoring_details=$(check_access_monitoring)
if [[ "$monitoring_details" == *"class='red'"* ]] || [[ "$monitoring_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "8.6 - Access monitoring and control" "$monitoring_details<p><strong>Remediation:</strong> Implement comprehensive access monitoring using Cloud Audit Logs, Security Command Center, and proper log management.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "8.6 - Access monitoring and control" "$monitoring_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Manual verification requirements
manual_checks="<p>Manual verification required for complete PCI DSS Requirement 8 compliance:</p>
<ul>
<li><strong>8.1:</strong> Governance and documentation of authentication policies and procedures</li>
<li><strong>8.3:</strong> Password/passphrase policies meeting PCI DSS requirements (12+ characters, complexity, history)</li>
<li><strong>8.5.1:</strong> MFA system configuration with anti-replay protection and proper factor requirements</li>
<li><strong>8.6:</strong> Session management controls with 15-minute inactivity timeout</li>
<li><strong>System accounts:</strong> Authentication requirements and management for application/system accounts</li>
<li><strong>Account lockout:</strong> Implementation after 10 invalid authentication attempts</li>
</ul>
<p><strong>GCP Tools and Recommendations:</strong></p>
<ul>
<li>Use Advanced Protection Program for high-risk users</li>
<li>Implement Security Keys (FIDO2) for phishing-resistant authentication</li>
<li>Configure Context-Aware Access for conditional authentication</li>
<li>Use Cloud Identity for centralized MFA management</li>
<li>Enable OS Login for centralized authentication on Compute Engine</li>
<li>Configure Identity-Aware Proxy for application-level authentication</li>
<li>Use Cloud Audit Logs for authentication event monitoring</li>
<li>Implement Security Command Center for centralized security monitoring</li>
</ul>"

add_html_section "$OUTPUT_FILE" "Manual Verification Requirements" "$manual_checks" "warning"
((warning_checks++))
((total_checks++))

#----------------------------------------------------------------------

#----------------------------------------------------------------------
# FINAL REPORT
#----------------------------------------------------------------------

# Finalize HTML report using shared library
# Add final summary metrics
add_summary_metrics "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"

# Finalize HTML report using shared library
finalize_report "$OUTPUT_FILE" "${REQUIREMENT_NUMBER}"

# Display final summary using shared library
# Display final summary using shared library
print_status "INFO" "=== ASSESSMENT SUMMARY ==="
print_status "INFO" "Total checks: $total_checks"
print_status "PASS" "Passed: $passed_checks"
print_status "FAIL" "Failed: $failed_checks"
print_status "WARN" "Warnings: $warning_checks"
print_status "INFO" "Report has been generated: $OUTPUT_FILE"
print_status "PASS" "=================================================================="
