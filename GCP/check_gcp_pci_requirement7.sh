#!/usr/bin/env bash

# PCI DSS Requirement 7 Compliance Check Script for GCP
# Restrict Access to System Components and Cardholder Data by Business Need to Know

# Set output colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables for scope control
ASSESSMENT_SCOPE="project"  # Default to project scope
SPECIFIC_PROJECT=""
SPECIFIC_ORG=""
REQUIREMENT_NUMBER="7"

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement $REQUIREMENT_NUMBER Assessment Script"
    echo "==============================================="
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --scope SCOPE          Assessment scope: 'project' or 'organization' (default: project)"
    echo "  -p, --project PROJECT_ID   Specific project to assess (overrides current gcloud config)"
    echo "  -o, --org ORG_ID          Specific organization ID to assess (required for organization scope)"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Assess current project"
    echo "  $0 --scope project --project my-proj # Assess specific project" 
    echo "  $0 --scope organization --org 123456 # Assess entire organization"
    echo ""
    echo "Note: Organization scope requires appropriate permissions across all projects in the organization."
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--scope)
            ASSESSMENT_SCOPE="$2"
            if [[ "$ASSESSMENT_SCOPE" != "project" && "$ASSESSMENT_SCOPE" != "organization" ]]; then
                echo "Error: Scope must be 'project' or 'organization'"
                exit 1
            fi
            shift 2
            ;;
        -p|--project)
            SPECIFIC_PROJECT="$2"
            shift 2
            ;;
        -o|--org)
            SPECIFIC_ORG="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Define variables
REPORT_TITLE="PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report (GCP)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./reports"

# Set scope-specific variables
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    OUTPUT_FILE="$OUTPUT_DIR/gcp_org_pci_req${REQUIREMENT_NUMBER}_report_$TIMESTAMP.html"
    REPORT_TITLE="$REPORT_TITLE (Organization-wide)"
else
    OUTPUT_FILE="$OUTPUT_DIR/gcp_project_pci_req${REQUIREMENT_NUMBER}_report_$TIMESTAMP.html"
    REPORT_TITLE="$REPORT_TITLE (Project-specific)"
fi

# Create reports directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Counters for checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0
access_denied_checks=0

# Get project and organization info based on scope
if [ -n "$SPECIFIC_PROJECT" ]; then
    DEFAULT_PROJECT="$SPECIFIC_PROJECT"
else
    DEFAULT_PROJECT=$(gcloud config get-value project 2>/dev/null)
fi

if [ -n "$SPECIFIC_ORG" ]; then
    DEFAULT_ORG="$SPECIFIC_ORG"
else
    DEFAULT_ORG=$(gcloud organizations list --format="value(name)" --limit=1 2>/dev/null | sed 's/organizations\///')
fi

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to add HTML report sections
add_html_section() {
    local file=$1
    local title=$2
    local content=$3
    local status=$4
    
    cat >> "$file" << EOF
<div class="check-item $status">
    <h3>$title</h3>
    <div class="content">$content</div>
</div>
EOF
}

# Function to initialize HTML report
initialize_html_report() {
    local file=$1
    local title=$2
    
    cat > "$file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>$title</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2e7d32; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .check-item { margin: 20px 0; padding: 15px; border-radius: 5px; border-left: 5px solid; }
        .pass { background: #e8f5e8; border-color: #4caf50; }
        .fail { background: #ffebee; border-color: #f44336; }
        .warning { background: #fff3e0; border-color: #ff9800; }
        .info { background: #e3f2fd; border-color: #2196f3; }
        .red { color: #f44336; font-weight: bold; }
        .green { color: #4caf50; font-weight: bold; }
        .yellow { color: #ff9800; font-weight: bold; }
        pre { background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
        ul { margin: 10px 0; }
        li { margin: 5px 0; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { padding: 8px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #f0f0f0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>$title</h1>
        <p>Generated on: $(date)</p>
        <p>Assessment Scope: $ASSESSMENT_SCOPE</p>
        <p>Project: ${DEFAULT_PROJECT:-Not specified}</p>
        <p>Organization: ${DEFAULT_ORG:-Not available}</p>
    </div>
EOF
}

# Function to finalize HTML report
finalize_html_report() {
    local file=$1
    local total=$2
    local passed=$3
    local failed=$4
    local warnings=$5
    
    local pass_percentage=0
    if [ $total -gt 0 ]; then
        pass_percentage=$(( (passed * 100) / total ))
    fi
    
    cat >> "$file" << EOF
    <div class="summary">
        <h2>Assessment Summary</h2>
        <p><strong>Total Checks:</strong> $total</p>
        <p><strong>Passed:</strong> <span class="green">$passed</span></p>
        <p><strong>Failed:</strong> <span class="red">$failed</span></p>
        <p><strong>Warnings:</strong> <span class="yellow">$warnings</span></p>
        <p><strong>Success Rate:</strong> $pass_percentage%</p>
        <p><strong>Assessment Scope:</strong> $ASSESSMENT_SCOPE</p>
        $(if [ "$ASSESSMENT_SCOPE" == "organization" ]; then echo "<p><strong>Organization:</strong> $DEFAULT_ORG</p>"; else echo "<p><strong>Project:</strong> $DEFAULT_PROJECT</p>"; fi)
    </div>
</body>
</html>
EOF
}

# Function to check GCP API access
check_gcp_permission() {
    local service=$1
    local operation=$2
    local test_command=$3
    
    print_status $CYAN "Checking $service $operation..."
    
    if eval "$test_command" &>/dev/null; then
        print_status $GREEN "✓ $service $operation access verified"
        return 0
    else
        print_status $RED "✗ $service $operation access failed"
        ((access_denied_checks++))
        return 1
    fi
}

# Function to build scope-aware gcloud commands
build_gcloud_command() {
    local base_command=$1
    local project_override=$2
    
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        if [ -n "$project_override" ]; then
            echo "$base_command --project=$project_override"
        else
            echo "$base_command"
        fi
    else
        echo "$base_command --project=$DEFAULT_PROJECT"
    fi
}

# Function to get all projects in scope
get_projects_in_scope() {
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        gcloud projects list --filter="parent.id:$DEFAULT_ORG" --format="value(projectId)" 2>/dev/null
    else
        echo "$DEFAULT_PROJECT"
    fi
}

# Function to run command across all projects in scope
run_across_projects() {
    local base_command=$1
    local format_option=$2
    
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        local projects=$(get_projects_in_scope)
        local results=""
        
        for project in $projects; do
            local cmd=$(build_gcloud_command "$base_command" "$project")
            if [ -n "$format_option" ]; then
                cmd="$cmd $format_option"
            fi
            
            local project_results=$(eval "$cmd" 2>/dev/null)
            if [ -n "$project_results" ]; then
                # Prefix results with project name for organization scope
                while IFS= read -r line; do
                    if [ -n "$line" ]; then
                        results="${results}${project}/${line}"$'\n'
                    fi
                done <<< "$project_results"
            fi
        done
        
        echo "$results"
    else
        local cmd=$(build_gcloud_command "$base_command")
        if [ -n "$format_option" ]; then
            cmd="$cmd $format_option"
        fi
        eval "$cmd" 2>/dev/null
    fi
}

# Function to check IAM policies for overly permissive permissions
check_overly_permissive_policies() {
    local details=""
    local found_issues=false
    
    details+="<p>Analysis of IAM policies for overly permissive permissions:</p>"
    
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        details+="<p><strong>Organization-wide IAM analysis:</strong></p>"
        
        # Check organization-level IAM policies
        if [ -n "$DEFAULT_ORG" ]; then
            local org_policy=$(gcloud organizations get-iam-policy "organizations/$DEFAULT_ORG" --format="json" 2>/dev/null)
            
            if [ -n "$org_policy" ]; then
                details+="<p>Organization-level IAM analysis:</p><ul>"
                
                # Check for overly broad roles
                local owner_bindings=$(echo "$org_policy" | jq -r '.bindings[] | select(.role=="roles/owner") | .members[]' 2>/dev/null)
                local editor_bindings=$(echo "$org_policy" | jq -r '.bindings[] | select(.role=="roles/editor") | .members[]' 2>/dev/null)
                
                if [ -n "$owner_bindings" ]; then
                    local owner_count=$(echo "$owner_bindings" | wc -l)
                    details+="<li class='red'>Organization Owner role assigned to $owner_count members - this provides excessive privileges</li>"
                    found_issues=true
                fi
                
                if [ -n "$editor_bindings" ]; then
                    local editor_count=$(echo "$editor_bindings" | wc -l)
                    details+="<li class='yellow'>Organization Editor role assigned to $editor_count members - consider using more specific roles</li>"
                    found_issues=true
                fi
                
                details+="</ul>"
            fi
        fi
        
        # Check project-level policies across all projects
        local projects=$(get_projects_in_scope)
        details+="<p>Project-level IAM analysis across organization:</p><table>"
        details+="<tr><th>Project</th><th>Owner Bindings</th><th>Editor Bindings</th><th>External Users</th><th>Status</th></tr>"
        
        for project in $projects; do
            local project_policy=$(gcloud projects get-iam-policy "$project" --format="json" 2>/dev/null)
            
            if [ -n "$project_policy" ]; then
                local project_owner_count=$(echo "$project_policy" | jq -r '.bindings[] | select(.role=="roles/owner") | .members[]' 2>/dev/null | wc -l)
                local project_editor_count=$(echo "$project_policy" | jq -r '.bindings[] | select(.role=="roles/editor") | .members[]' 2>/dev/null | wc -l)
                local external_users=$(echo "$project_policy" | jq -r '.bindings[].members[]' 2>/dev/null | grep -v "@.*\\.gserviceaccount\\.com" | grep -v "group:" | grep -v "domain:" | wc -l)
                
                local status_class="green"
                local status_text="Good"
                
                if [ "$project_owner_count" -gt 2 ]; then
                    status_class="red"
                    status_text="High Risk"
                    found_issues=true
                elif [ "$project_editor_count" -gt 5 ] || [ "$external_users" -gt 3 ]; then
                    status_class="yellow"
                    status_text="Review Needed"
                    found_issues=true
                fi
                
                details+="<tr><td>$project</td><td>$project_owner_count</td><td>$project_editor_count</td><td>$external_users</td><td class='$status_class'>$status_text</td></tr>"
            fi
        done
        
        details+="</table>"
    else
        # Single project analysis
        local project_policy=$(gcloud projects get-iam-policy "$DEFAULT_PROJECT" --format="json" 2>/dev/null)
        
        if [ -n "$project_policy" ]; then
            details+="<p>Project-level IAM analysis:</p><ul>"
            
            # Check for overly broad roles at project level
            local project_owner_bindings=$(echo "$project_policy" | jq -r '.bindings[] | select(.role=="roles/owner") | .members[]' 2>/dev/null)
            local project_editor_bindings=$(echo "$project_policy" | jq -r '.bindings[] | select(.role=="roles/editor") | .members[]' 2>/dev/null)
            
            if [ -n "$project_owner_bindings" ]; then
                local project_owner_count=$(echo "$project_owner_bindings" | wc -l)
                details+="<li class='red'>Project Owner role assigned to $project_owner_count members - this provides excessive privileges</li>"
                found_issues=true
                
                # List the members with owner role
                details+="<ul>"
                echo "$project_owner_bindings" | while read -r member; do
                    details+="<li>$member</li>"
                done
                details+="</ul>"
            fi
            
            if [ -n "$project_editor_bindings" ]; then
                local project_editor_count=$(echo "$project_editor_bindings" | wc -l)
                details+="<li class='yellow'>Project Editor role assigned to $project_editor_count members - consider using more specific roles</li>"
                found_issues=true
            fi
            
            # Check for external users (non-domain users)
            local external_users=$(echo "$project_policy" | jq -r '.bindings[].members[]' 2>/dev/null | grep -v "@.*\\.gserviceaccount\\.com" | grep -v "group:" | grep -v "domain:" | head -10)
            
            if [ -n "$external_users" ]; then
                details+="<li class='yellow'>External users detected in project IAM:</li><ul>"
                echo "$external_users" | while read -r user; do
                    details+="<li>$user</li>"
                done
                details+="</ul>"
                found_issues=true
            fi
            
            details+="</ul>"
        fi
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check for inactive service accounts
check_inactive_service_accounts() {
    local details=""
    local found_inactive=false
    local threshold_days=90
    
    details+="<p>Analysis of service account activity (inactive for more than $threshold_days days):</p>"
    
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        details+="<p><strong>Organization-wide service account analysis:</strong></p>"
        
        local projects=$(get_projects_in_scope)
        details+="<table><tr><th>Project</th><th>Service Account</th><th>Display Name</th><th>Keys</th><th>Status</th></tr>"
        
        for project in $projects; do
            local service_accounts=$(gcloud iam service-accounts list --project="$project" --format="value(email,displayName,disabled)" 2>/dev/null)
            
            if [ -n "$service_accounts" ]; then
                local current_time=$(date +%s)
                
                while IFS=$'\t' read -r sa_email display_name disabled; do
                    if [ -z "$sa_email" ]; then
                        continue
                    fi
                    
                    # Get service account keys
                    local sa_keys=$(gcloud iam service-accounts keys list --iam-account="$sa_email" --format="json" 2>/dev/null)
                    
                    if [ -n "$sa_keys" ]; then
                        local key_count=$(echo "$sa_keys" | jq -r '. | length' 2>/dev/null)
                        local old_keys=0
                        
                        if [ "$key_count" -gt 0 ]; then
                            for key_info in $(echo "$sa_keys" | jq -c '.[]'); do
                                local create_time=$(echo "$key_info" | jq -r '.validAfterTime' 2>/dev/null)
                                local key_type=$(echo "$key_info" | jq -r '.keyType' 2>/dev/null)
                                
                                if [ "$key_type" != "SYSTEM_MANAGED" ]; then
                                    # Convert to epoch time
                                    local create_epoch=$(date -d "$create_time" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$create_time" +%s 2>/dev/null)
                                    
                                    if [ -n "$create_epoch" ]; then
                                        local days_old=$(( (current_time - create_epoch) / 86400 ))
                                        
                                        if [ "$days_old" -gt "$threshold_days" ]; then
                                            ((old_keys++))
                                        fi
                                    fi
                                fi
                            done
                        fi
                        
                        # Determine status
                        local status_class="green"
                        local status_text="Active"
                        
                        if [ "$disabled" = "True" ]; then
                            status_class="yellow"
                            status_text="Disabled (good for unused accounts)"
                        elif [ "$old_keys" -gt 0 ]; then
                            status_class="red"
                            status_text="$old_keys old keys (>$threshold_days days)"
                            found_inactive=true
                        elif [ "$key_count" -eq 0 ]; then
                            status_text="No user-managed keys"
                        fi
                        
                        details+="<tr><td>$project</td><td>$sa_email</td><td>$display_name</td><td>$key_count total</td><td class='$status_class'>$status_text</td></tr>"
                    fi
                    
                done <<< "$service_accounts"
            fi
        done
        
        details+="</table>"
    else
        # Single project analysis
        local service_accounts=$(gcloud iam service-accounts list --format="value(email,displayName,disabled)" 2>/dev/null)
        
        if [ -z "$service_accounts" ]; then
            details+="<p>No service accounts found in project $DEFAULT_PROJECT.</p>"
            echo "$details"
            return
        fi
        
        details+="<table><tr><th>Service Account</th><th>Display Name</th><th>Keys</th><th>Status</th></tr>"
        
        local current_time=$(date +%s)
        
        while IFS=$'\t' read -r sa_email display_name disabled; do
            # Get service account keys
            local sa_keys=$(gcloud iam service-accounts keys list --iam-account="$sa_email" --format="json" 2>/dev/null)
            
            if [ -n "$sa_keys" ]; then
                local key_count=$(echo "$sa_keys" | jq -r '. | length' 2>/dev/null)
                local old_keys=0
                
                if [ "$key_count" -gt 0 ]; then
                    for key_info in $(echo "$sa_keys" | jq -c '.[]'); do
                        local create_time=$(echo "$key_info" | jq -r '.validAfterTime' 2>/dev/null)
                        local key_type=$(echo "$key_info" | jq -r '.keyType' 2>/dev/null)
                        
                        if [ "$key_type" != "SYSTEM_MANAGED" ]; then
                            # Convert to epoch time
                            local create_epoch=$(date -d "$create_time" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$create_time" +%s 2>/dev/null)
                            
                            if [ -n "$create_epoch" ]; then
                                local days_old=$(( (current_time - create_epoch) / 86400 ))
                                
                                if [ "$days_old" -gt "$threshold_days" ]; then
                                    ((old_keys++))
                                fi
                            fi
                        fi
                    done
                fi
                
                # Determine status
                local status_class="green"
                local status_text="Active"
                
                if [ "$disabled" = "True" ]; then
                    status_class="yellow"
                    status_text="Disabled (good for unused accounts)"
                elif [ "$old_keys" -gt 0 ]; then
                    status_class="red"
                    status_text="$old_keys old keys (>$threshold_days days)"
                    found_inactive=true
                elif [ "$key_count" -eq 0 ]; then
                    status_text="No user-managed keys"
                fi
                
                details+="<tr><td>$sa_email</td><td>$display_name</td><td>$key_count total</td><td class='$status_class'>$status_text</td></tr>"
            fi
            
        done <<< "$service_accounts"
        
        details+="</table>"
    fi
    
    if [ "$found_inactive" = false ]; then
        details+="<p class='green'>No service accounts with old keys detected. All service accounts appear to be properly managed.</p>"
    fi
    
    echo "$details"
    if [ "$found_inactive" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check least privilege implementation
check_least_privilege() {
    local details=""
    local found_violations=false
    
    details+="<p>Analysis of least privilege implementation:</p>"
    
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        details+="<p><strong>Organization-wide least privilege analysis:</strong></p>"
        
        local projects=$(get_projects_in_scope)
        local total_primitive_roles=0
        local total_custom_roles=0
        local total_projects=0
        
        for project in $projects; do
            ((total_projects++))
            
            local project_policy=$(gcloud projects get-iam-policy "$project" --format="json" 2>/dev/null)
            
            if [ -n "$project_policy" ]; then
                # Count primitive roles (Owner, Editor, Viewer)
                local primitive_count=$(echo "$project_policy" | jq -r '.bindings[] | select(.role | startswith("roles/owner") or startswith("roles/editor") or startswith("roles/viewer")) | .role' 2>/dev/null | wc -l)
                total_primitive_roles=$((total_primitive_roles + primitive_count))
                
                # Check for custom roles
                local custom_count=$(gcloud iam roles list --project="$project" --format="value(name)" 2>/dev/null | wc -l)
                total_custom_roles=$((total_custom_roles + custom_count))
            fi
        done
        
        details+="<p>Summary across $total_projects projects:</p><ul>"
        details+="<li>Total primitive role bindings: $total_primitive_roles</li>"
        details+="<li>Total custom roles defined: $total_custom_roles</li>"
        details+="</ul>"
        
        if [ "$total_primitive_roles" -gt "$((total_projects * 3))" ]; then
            details+="<p class='yellow'>High number of primitive roles in use. Consider replacing with more specific roles.</p>"
            found_violations=true
        fi
        
        if [ "$total_custom_roles" -lt "$((total_projects / 2))" ]; then
            details+="<p class='yellow'>Few custom roles found. Consider creating custom roles for specific job functions.</p>"
            found_violations=true
        fi
    else
        # Single project analysis
        local project_policy=$(gcloud projects get-iam-policy "$DEFAULT_PROJECT" --format="json" 2>/dev/null)
        
        if [ -n "$project_policy" ]; then
            # Count primitive roles (Owner, Editor, Viewer)
            local primitive_roles=$(echo "$project_policy" | jq -r '.bindings[] | select(.role | startswith("roles/owner") or startswith("roles/editor") or startswith("roles/viewer")) | .role' 2>/dev/null | sort | uniq -c)
            
            if [ -n "$primitive_roles" ]; then
                details+="<p class='yellow'>Primitive roles in use (consider replacing with more specific roles):</p><ul>"
                echo "$primitive_roles" | while read -r count role; do
                    details+="<li>$role: $count bindings</li>"
                done
                details+="</ul>"
                found_violations=true
            fi
            
            # Check for custom roles
            local custom_roles=$(gcloud iam roles list --project="$DEFAULT_PROJECT" --format="value(name,title)" 2>/dev/null)
            
            if [ -n "$custom_roles" ]; then
                details+="<p class='green'>Custom roles defined for least privilege:</p><ul>"
                while IFS=$'\t' read -r role_name title; do
                    details+="<li>$role_name ($title)</li>"
                done <<< "$custom_roles"
                details+="</ul>"
            else
                details+="<p class='yellow'>No custom roles found. Consider creating custom roles for specific job functions to implement least privilege.</p>"
                found_violations=true
            fi
        fi
    fi
    
    # Check Compute Engine instances for OS Login across scope
    local instances
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        instances=$(run_across_projects "gcloud compute instances list" "--format='value(name,zone,metadata.items)'")
    else
        instances=$(gcloud compute instances list --format="value(name,zone,metadata.items)" 2>/dev/null)
    fi
    
    if [ -n "$instances" ]; then
        details+="<p>Compute Engine OS Login analysis:</p><ul>"
        
        local os_login_enabled=0
        local total_instances=0
        
        while IFS=$'\t' read -r instance_info; do
            if [ -z "$instance_info" ]; then
                continue
            fi
            
            ((total_instances++))
            
            # Check if OS Login is enabled
            if echo "$instance_info" | grep -q "enable-oslogin.*TRUE"; then
                ((os_login_enabled++))
            fi
        done <<< "$instances"
        
        if [ "$os_login_enabled" -eq "$total_instances" ]; then
            details+="<li class='green'>All $total_instances instances have OS Login enabled</li>"
        elif [ "$os_login_enabled" -gt 0 ]; then
            details+="<li class='yellow'>$os_login_enabled out of $total_instances instances have OS Login enabled</li>"
            found_violations=true
        else
            details+="<li class='red'>None of $total_instances instances have OS Login enabled</li>"
            found_violations=true
        fi
        
        details+="</ul>"
    fi
    
    echo "$details"
    if [ "$found_violations" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check access control systems configuration
check_access_control_systems() {
    local details=""
    local found_issues=false
    
    details+="<p>Analysis of access control systems configuration:</p>"
    
    # Check VPC firewall rules for default-deny across scope
    local firewall_rules
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        firewall_rules=$(run_across_projects "gcloud compute firewall-rules list" "--format='value(name,direction,sourceRanges)' --filter='disabled:false'")
    else
        firewall_rules=$(gcloud compute firewall-rules list --format="value(name,direction,sourceRanges)" --filter="disabled:false" 2>/dev/null)
    fi
    
    if [ -n "$firewall_rules" ]; then
        # Check for overly permissive rules
        local permissive_rules=$(echo "$firewall_rules" | grep "0.0.0.0/0" | wc -l)
        local total_rules=$(echo "$firewall_rules" | wc -l)
        
        details+="<p>VPC firewall rules analysis:</p><ul>"
        details+="<li>Total active firewall rules: $total_rules</li>"
        details+="<li>Rules allowing access from anywhere (0.0.0.0/0): $permissive_rules</li>"
        
        if [ "$permissive_rules" -gt "$((total_rules / 3))" ]; then
            details+="<li class='red'>High number of permissive firewall rules detected</li>"
            found_issues=true
        else
            details+="<li class='green'>Firewall rules appear to follow principle of least privilege</li>"
        fi
        
        details+="</ul>"
    else
        details+="<p class='red'>No firewall rules found or unable to access firewall configuration.</p>"
        found_issues=true
    fi
    
    # Check for Identity-Aware Proxy usage across scope
    local iap_resources
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        iap_resources=$(run_across_projects "gcloud iap settings get" "--format='value(name)'")
    else
        iap_resources=$(gcloud iap settings get --project="$DEFAULT_PROJECT" --format="value(name)" 2>/dev/null)
    fi
    
    if [ -n "$iap_resources" ]; then
        details+="<p class='green'>Identity-Aware Proxy is configured for additional access control.</p>"
    else
        details+="<p class='yellow'>Identity-Aware Proxy is not configured. Consider using IAP for fine-grained access control to applications.</p>"
        found_issues=true
    fi
    
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
        print_status $RED "Error: Organization scope requires an organization ID."
        print_status $YELLOW "Please provide organization ID with --org flag or ensure you have organization access."
        exit 1
    fi
else
    # Project scope validation
    if [ -z "$DEFAULT_PROJECT" ]; then
        print_status $RED "Error: No project specified."
        print_status $YELLOW "Please set a default project with: gcloud config set project PROJECT_ID"
        print_status $YELLOW "Or specify a project with: --project PROJECT_ID"
        exit 1
    fi
fi

# Start script execution
print_status $BLUE "============================================="
print_status $BLUE "  PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER (GCP)"
print_status $BLUE "  (Restrict Access by Business Need to Know)"
print_status $BLUE "============================================="
echo ""

# Display scope information
print_status $CYAN "Assessment Scope: $ASSESSMENT_SCOPE"
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    print_status $CYAN "Organization: $DEFAULT_ORG"
    print_status $YELLOW "Note: Organization-wide assessment may take longer and requires broader permissions"
else
    print_status $CYAN "Project: $DEFAULT_PROJECT"
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

print_status $CYAN "=== CHECKING REQUIRED GCP PERMISSIONS ==="

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

# Requirement 7 specific permission checks
check_gcp_permission "Projects" "get-iam-policy" "gcloud projects get-iam-policy $DEFAULT_PROJECT --limit=1"
((total_checks++))

check_gcp_permission "IAM" "service-accounts" "gcloud iam service-accounts list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "firewall-rules" "gcloud compute firewall-rules list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "instances" "gcloud compute instances list $PROJECT_FLAG --limit=1"
((total_checks++))

# Calculate permissions percentage
available_permissions=$((total_checks - access_denied_checks))
if [ $available_permissions -gt 0 ]; then
    permissions_percentage=$(( ((total_checks - access_denied_checks) * 100) / total_checks ))
else
    permissions_percentage=0
fi

if [ $permissions_percentage -lt 70 ]; then
    print_status $RED "WARNING: Insufficient permissions to perform a complete PCI Requirement $REQUIREMENT_NUMBER assessment."
    add_html_section "$OUTPUT_FILE" "Permission Assessment" "<p class='red'>Insufficient permissions detected. Only $permissions_percentage% of required permissions are available.</p><p>Without these permissions, the assessment will be incomplete and may not accurately reflect your PCI DSS compliance status.</p>" "fail"
    read -p "Continue with limited assessment? (y/n): " CONTINUE
    if [[ ! $CONTINUE =~ ^[Yy]$ ]]; then
        echo "Assessment aborted."
        exit 1
    fi
else
    print_status $GREEN "Permission check complete: $permissions_percentage% permissions available"
    add_html_section "$OUTPUT_FILE" "Permission Assessment" "<p class='green'>Sufficient permissions detected. $permissions_percentage% of required permissions are available.</p>" "pass"
fi

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

#----------------------------------------------------------------------
# SECTION 2: REQUIREMENT 7 ASSESSMENT LOGIC
#----------------------------------------------------------------------
print_status $CYAN "=== PCI REQUIREMENT $REQUIREMENT_NUMBER: RESTRICT ACCESS BY BUSINESS NEED TO KNOW ==="

# Requirement 7.2: Access to system components and data is appropriately defined and assigned
add_html_section "$OUTPUT_FILE" "Requirement 7.2: Access definition and assignment" "<p>Verifying access control implementation based on job classification and least privilege...</p>" "info"

# Check 7.2.2 - Least privilege implementation
print_status $CYAN "Checking least privilege implementation..."
privilege_details=$(check_least_privilege)
if [[ "$privilege_details" == *"class='red'"* ]] || [[ "$privilege_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "7.2.2 - Least privilege implementation" "$privilege_details<p><strong>Remediation:</strong> Implement least privilege by using specific IAM roles instead of primitive roles. Enable OS Login for Compute Engine instances and create custom roles for specific job functions.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "7.2.2 - Least privilege implementation" "$privilege_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Check 7.2.5 - Service account management
print_status $CYAN "Checking service account management..."
sa_details=$(check_inactive_service_accounts)
if [[ "$sa_details" == *"class='red'"* ]] || [[ "$sa_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "7.2.5 - Service account management" "$sa_details<p><strong>Remediation:</strong> Review and manage service account keys. Remove old or unused keys and ensure service accounts have minimal required privileges.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "7.2.5 - Service account management" "$sa_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Requirement 7.3: Access to system components and data is managed via an access control system(s)
add_html_section "$OUTPUT_FILE" "Requirement 7.3: Access control systems" "<p>Verifying access control system implementation and configuration...</p>" "info"

# Check 7.3.1 - Access control system implementation
print_status $CYAN "Checking access control systems..."
acs_details=$(check_access_control_systems)
if [[ "$acs_details" == *"class='red'"* ]] || [[ "$acs_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "7.3.1 - Access control system implementation" "$acs_details<p><strong>Remediation:</strong> Implement comprehensive access control systems using Cloud IAM, VPC firewalls, and Identity-Aware Proxy. Ensure need-to-know restrictions are enforced.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "7.3.1 - Access control system implementation" "$acs_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Check 7.3.2 - Access control system configuration
print_status $CYAN "Checking overly permissive policies..."
permissive_details=$(check_overly_permissive_policies)
if [[ "$permissive_details" == *"class='red'"* ]] || [[ "$permissive_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "7.3.2 - Access control system configuration" "$permissive_details<p><strong>Remediation:</strong> Review and restrict overly permissive IAM policies. Replace primitive roles with specific roles and limit external user access.</p>" "fail"
    ((failed_checks++))
else
    add_html_section "$OUTPUT_FILE" "7.3.2 - Access control system configuration" "$permissive_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Manual verification requirements
manual_checks="<p>Manual verification required for complete PCI DSS Requirement 7 compliance:</p>
<ul>
<li><strong>7.1:</strong> Governance and documentation of access control policies and procedures</li>
<li><strong>7.2.1:</strong> Job classification definitions and access control model documentation</li>
<li><strong>7.2.3:</strong> Required privileges approval processes with documented authorized approvers</li>
<li><strong>7.2.4:</strong> User account reviews at least every six months with management acknowledgment</li>
<li><strong>7.2.6:</strong> Cardholder data query restrictions via applications with role-based access</li>
<li><strong>7.3.3:</strong> Default-deny configuration verification across all access control systems</li>
</ul>
<p><strong>GCP Tools and Recommendations:</strong></p>
<ul>
<li>Use Cloud Identity groups for role-based access management</li>
<li>Implement IAM Recommender for access optimization suggestions</li>
<li>Use Organization Policies for access restrictions</li>
<li>Configure Cloud Asset Inventory for access tracking</li>
<li>Enable Cloud Audit Logs for approval trail documentation</li>
<li>Use Cloud SQL IAM authentication for database access</li>
<li>Implement VPC Service Controls for CHD systems</li>
<li>Use Cloud IAM conditions for fine-grained access control</li>
</ul>"

add_html_section "$OUTPUT_FILE" "Manual Verification Requirements" "$manual_checks" "warning"
((warning_checks++))
((total_checks++))

#----------------------------------------------------------------------
# FINAL REPORT
#----------------------------------------------------------------------
finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"

echo ""
print_status $GREEN "======================= ASSESSMENT SUMMARY ======================="
echo "Total checks performed: $total_checks"
echo "Passed checks: $passed_checks"
echo "Failed checks: $failed_checks"
echo "Warning checks: $warning_checks"
echo "Assessment scope: $ASSESSMENT_SCOPE"
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    echo "Organization: $DEFAULT_ORG"
else
    echo "Project: $DEFAULT_PROJECT"
fi
print_status $GREEN "=================================================================="
echo ""
print_status $CYAN "Report has been generated: $OUTPUT_FILE"

# Open the report if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE"
fi

print_status $GREEN "=================================================================="