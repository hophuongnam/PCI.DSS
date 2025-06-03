#!/usr/bin/env bash

# PCI DSS Requirement 5 Compliance Check Script for GCP
# Protect all systems against malware and regularly update anti-malware software or programs

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
REQUIREMENT_NUMBER="5"

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

# Function to check Compute Engine instances for anti-malware protection
check_gce_antimalware() {
    local details=""
    local found_unprotected=false
    
    details+="<p>Analysis of Compute Engine instances for anti-malware protection:</p>"
    
    # Get all Compute Engine instances across all zones in scope
    local instance_list
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        details+="<p><strong>Organization-wide assessment:</strong></p>"
        instance_list=$(run_across_projects "gcloud compute instances list" "--format='value(name,zone,status)'")
    else
        instance_list=$(gcloud compute instances list --format="value(name,zone,status)" 2>/dev/null)
    fi
    
    if [ -z "$instance_list" ]; then
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            details+="<p>No Compute Engine instances found in organization $DEFAULT_ORG.</p>"
        else
            details+="<p>No Compute Engine instances found in project $DEFAULT_PROJECT.</p>"
        fi
        echo "$details"
        return
    fi
    
    details+="<ul>"
    
    while IFS=$'\t' read -r instance_info; do
        # Skip empty lines
        if [ -z "$instance_info" ]; then
            continue
        fi
        
        # Parse project/instance info for organization scope
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            local project_instance=$(echo "$instance_info" | cut -d'/' -f1)
            local instance_data=$(echo "$instance_info" | cut -d'/' -f2-)
            instance_name=$(echo "$instance_data" | cut -d$'\t' -f1)
            zone=$(echo "$instance_data" | cut -d$'\t' -f2)
            status=$(echo "$instance_data" | cut -d$'\t' -f3)
            
            # Skip terminated instances
            if [ "$status" == "TERMINATED" ]; then
                continue
            fi
            
            # Get instance metadata for anti-malware information
            metadata=$(gcloud compute instances describe "$instance_name" --zone="$zone" --project="$project_instance" --format="value(metadata.items)" 2>/dev/null)
            
            details+="<li><strong>Project:</strong> $project_instance, <strong>Instance:</strong> $instance_name"
        else
            instance_name=$(echo "$instance_info" | cut -d$'\t' -f1)
            zone=$(echo "$instance_info" | cut -d$'\t' -f2)
            status=$(echo "$instance_info" | cut -d$'\t' -f3)
            
            # Skip terminated instances
            if [ "$status" == "TERMINATED" ]; then
                continue
            fi
            
            metadata=$(gcloud compute instances describe "$instance_name" --zone="$zone" --format="value(metadata.items)" 2>/dev/null)
            
            details+="<li><strong>Instance:</strong> $instance_name (Zone: $zone)"
        fi
        
        # Check for anti-malware related metadata
        antimalware_found=false
        if echo "$metadata" | grep -i -E "antimalware|anti-malware|antivirus|anti-virus|security-agent" > /dev/null; then
            antimalware_info=$(echo "$metadata" | grep -i -E "antimalware|anti-malware|antivirus|anti-virus|security-agent" | head -1)
            details+=" - <span class='green'>Anti-malware metadata found: $antimalware_info</span>"
            antimalware_found=true
        fi
        
        # Check for OS Login which can provide some security features
        os_login=$(echo "$metadata" | grep "enable-oslogin.*TRUE")
        if [ -n "$os_login" ]; then
            details+=" - <span class='green'>OS Login enabled (enhanced security)</span>"
        fi
        
        # Check for Shielded VM features
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            shielded_config=$(gcloud compute instances describe "$instance_name" --zone="$zone" --project="$project_instance" --format="value(shieldedInstanceConfig)" 2>/dev/null)
        else
            shielded_config=$(gcloud compute instances describe "$instance_name" --zone="$zone" --format="value(shieldedInstanceConfig)" 2>/dev/null)
        fi
        
        if [ -n "$shielded_config" ]; then
            integrity_monitoring=$(echo "$shielded_config" | grep -o "enableIntegrityMonitoring: true")
            secure_boot=$(echo "$shielded_config" | grep -o "enableSecureBoot: true")
            vtpm=$(echo "$shielded_config" | grep -o "enableVtpm: true")
            
            if [ -n "$integrity_monitoring" ] || [ -n "$secure_boot" ] || [ -n "$vtpm" ]; then
                details+=" - <span class='green'>Shielded VM features enabled (malware protection)</span>"
                antimalware_found=true
            fi
        fi
        
        if [ "$antimalware_found" = false ]; then
            details+=" - <span class='red'>No anti-malware configuration detected</span>"
            found_unprotected=true
        fi
        
        details+="</li>"
        
    done <<< "$instance_list"
    
    details+="</ul>"
    
    echo "$details"
    if [ "$found_unprotected" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check if anti-malware is regularly updated
check_antimalware_updates() {
    local details=""
    local found_outdated=false
    
    details+="<p>Checking for anti-malware update mechanisms in GCP:</p>"
    
    # Check for OS Config patch management across scope
    local patch_policies
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        details+="<p><strong>Organization-wide patch management:</strong></p>"
        patch_policies=$(run_across_projects "gcloud compute os-config patch-policies list" "--format='value(name)'")
    else
        patch_policies=$(gcloud compute os-config patch-policies list --format="value(name)" 2>/dev/null)
    fi
    
    if [ -z "$patch_policies" ]; then
        details+="<p class='yellow'>No OS Config patch policies found. Consider creating patch policies for regular security updates.</p>"
        found_outdated=true
    else
        details+="<p class='green'>Found OS Config patch policies:</p><ul>"
        echo "$patch_policies" | while read -r policy; do
            if [ -n "$policy" ]; then
                details+="<li>$policy</li>"
            fi
        done
        details+="</ul>"
    fi
    
    # Check for Container Analysis for vulnerability scanning
    local images
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        images=$(run_across_projects "gcloud container images list" "--format='value(name)' --limit=5")
    else
        images=$(gcloud container images list --format="value(name)" --limit=5 2>/dev/null)
    fi
    
    if [ -n "$images" ]; then
        details+="<p>Checking vulnerability scans for container images:</p><ul>"
        echo "$images" | while IFS= read -r image; do
            if [ -n "$image" ]; then
                # For organization scope, extract project from image path
                if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                    project_image=$(echo "$image" | cut -d'/' -f1)
                    image_name=$(echo "$image" | cut -d'/' -f2-)
                    # Get vulnerability scan results
                    vulnerabilities=$(gcloud container images scan "$image_name" --project="$project_image" --format="value(vulnerabilities)" 2>/dev/null | grep -c "CRITICAL\|HIGH" || echo "0")
                    
                    if [ "$vulnerabilities" -gt 0 ]; then
                        details+="<li class='red'>$project_image/$image_name - $vulnerabilities high/critical vulnerabilities found</li>"
                        found_outdated=true
                    else
                        details+="<li class='green'>$project_image/$image_name - No high/critical vulnerabilities found</li>"
                    fi
                else
                    vulnerabilities=$(gcloud container images scan "$image" --format="value(vulnerabilities)" 2>/dev/null | grep -c "CRITICAL\|HIGH" || echo "0")
                    
                    if [ "$vulnerabilities" -gt 0 ]; then
                        details+="<li class='red'>$image - $vulnerabilities high/critical vulnerabilities found</li>"
                        found_outdated=true
                    else
                        details+="<li class='green'>$image - No high/critical vulnerabilities found</li>"
                    fi
                fi
            fi
        done
        details+="</ul>"
    else
        details+="<p>No container images found in scope.</p>"
    fi
    
    echo "$details"
    if [ "$found_outdated" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check for periodic malware scans
check_periodic_scans() {
    local details=""
    local found_issues=false
    
    details+="<p>Checking for evidence of periodic malware scans in GCP:</p>"
    
    # Check for Cloud Scheduler jobs that might trigger scans
    local scan_jobs
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        scan_jobs=$(run_across_projects "gcloud scheduler jobs list" "--format='value(name,schedule)' --filter='name~scan OR name~malware OR name~security'")
    else
        scan_jobs=$(gcloud scheduler jobs list --format="value(name,schedule)" --filter="name~'scan' OR name~'malware' OR name~'security'" 2>/dev/null)
    fi
    
    if [ -z "$scan_jobs" ]; then
        details+="<p class='yellow'>No Cloud Scheduler jobs found for malware scanning. Consider implementing scheduled security scans.</p>"
        found_issues=true
    else
        details+="<p class='green'>Found scheduled jobs that may include malware scanning:</p><ul>"
        echo "$scan_jobs" | while IFS=$'\t' read -r job_info; do
            if [ -n "$job_info" ]; then
                details+="<li>$job_info</li>"
            fi
        done
        details+="</ul>"
    fi
    
    # Check for Cloud Functions that might perform scans
    local scan_functions
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        scan_functions=$(run_across_projects "gcloud functions list" "--format='value(name,updateTime)' --filter='name~scan OR name~malware OR name~security'")
    else
        scan_functions=$(gcloud functions list --format="value(name,updateTime)" --filter="name~'scan' OR name~'malware' OR name~'security'" 2>/dev/null)
    fi
    
    if [ -z "$scan_functions" ]; then
        details+="<p class='yellow'>No Cloud Functions found that appear to perform security scanning.</p>"
        found_issues=true
    else
        details+="<p class='green'>Found Cloud Functions that may perform security scanning:</p><ul>"
        echo "$scan_functions" | while IFS=$'\t' read -r function_info; do
            if [ -n "$function_info" ]; then
                details+="<li>$function_info</li>"
            fi
        done
        details+="</ul>"
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check for anti-malware mechanisms at network boundaries
check_boundary_protection() {
    local details=""
    local found_issues=false
    
    details+="<p>Checking for anti-malware mechanisms at network boundaries:</p>"
    
    # Check for Cloud Armor security policies
    local security_policies
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        security_policies=$(run_across_projects "gcloud compute security-policies list" "--format='value(name,description)'")
    else
        security_policies=$(gcloud compute security-policies list --format="value(name,description)" 2>/dev/null)
    fi
    
    if [ -z "$security_policies" ]; then
        details+="<p class='yellow'>No Cloud Armor security policies found. Cloud Armor can provide protection against malicious traffic.</p>"
        found_issues=true
    else
        details+="<p class='green'>Found Cloud Armor security policies:</p><ul>"
        echo "$security_policies" | while IFS=$'\t' read -r policy_info; do
            if [ -n "$policy_info" ]; then
                details+="<li>$policy_info</li>"
            fi
        done
        details+="</ul>"
    fi
    
    # Check for VPC firewall rules
    local firewall_rules
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        firewall_rules=$(run_across_projects "gcloud compute firewall-rules list" "--format='value(name,direction)' --filter='disabled:false'")
    else
        firewall_rules=$(gcloud compute firewall-rules list --format="value(name,direction)" --filter="disabled:false" 2>/dev/null)
    fi
    
    if [ -n "$firewall_rules" ]; then
        details+="<p>Analyzing VPC firewall rules for boundary protection:</p>"
        
        # Count rules
        local rule_count=$(echo "$firewall_rules" | wc -l)
        
        if [ "$rule_count" -lt 5 ]; then
            details+="<p class='red'>Very few firewall rules found ($rule_count). Ensure proper network boundary controls are in place.</p>"
            found_issues=true
        else
            details+="<p class='green'>Found $rule_count firewall rules configured for network boundary protection.</p>"
        fi
    else
        details+="<p class='red'>No firewall rules found or unable to access firewall configuration.</p>"
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
print_status $BLUE "  (Protect All Systems Against Malware)"
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

# Requirement 5 specific permission checks
check_gcp_permission "Compute Engine" "instances" "gcloud compute instances list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "os-config" "gcloud compute os-config patch-policies list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Container" "images" "gcloud container images list --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "security-policies" "gcloud compute security-policies list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Cloud Scheduler" "jobs" "gcloud scheduler jobs list $PROJECT_FLAG --limit=1"
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
# SECTION 2: REQUIREMENT 5 ASSESSMENT LOGIC
#----------------------------------------------------------------------
print_status $CYAN "=== PCI REQUIREMENT $REQUIREMENT_NUMBER: PROTECT ALL SYSTEMS AGAINST MALWARE ==="

# Requirement 5.2: Anti-malware mechanisms and processes
add_html_section "$OUTPUT_FILE" "Requirement 5.2: Anti-malware mechanisms and processes" "<p>Verifying anti-malware deployment and configuration across systems...</p>" "info"

# Check 5.2.1 - Anti-malware protection is deployed
print_status $CYAN "Checking for anti-malware protection deployment..."
am_details=$(check_gce_antimalware)
if [[ "$am_details" == *"class='red'"* ]]; then
    add_html_section "$OUTPUT_FILE" "5.2.1 - Anti-malware protection deployment" "$am_details<p><strong>Remediation:</strong> Deploy anti-malware software on all systems commonly affected by malware. Consider using GCP security features like Shielded VMs and Security Command Center.</p>" "fail"
    ((failed_checks++))
else
    add_html_section "$OUTPUT_FILE" "5.2.1 - Anti-malware protection deployment" "$am_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Requirement 5.3: Anti-malware mechanisms are maintained and monitored
add_html_section "$OUTPUT_FILE" "Requirement 5.3: Anti-malware maintenance and monitoring" "<p>Verifying anti-malware update mechanisms and monitoring...</p>" "info"

# Check 5.3.1 - Anti-malware updates
print_status $CYAN "Checking anti-malware update mechanisms..."
update_details=$(check_antimalware_updates)
if [[ "$update_details" == *"class='red'"* ]] || [[ "$update_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "5.3.1 - Anti-malware mechanism updates" "$update_details<p><strong>Remediation:</strong> Ensure anti-malware mechanisms are kept current via automatic updates. Use OS Config for patch management and Container Analysis for container security.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "5.3.1 - Anti-malware mechanism updates" "$update_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Check 5.3.2 - Periodic scans and active scanning
print_status $CYAN "Checking for periodic malware scans..."
scan_details=$(check_periodic_scans)
if [[ "$scan_details" == *"class='red'"* ]] || [[ "$scan_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "5.3.2 - Periodic scans and active scanning" "$scan_details<p><strong>Remediation:</strong> Implement periodic scans and active or real-time scanning using Cloud Scheduler, Cloud Functions, or continuous behavioral analysis.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "5.3.2 - Periodic scans and active scanning" "$scan_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Network boundary protection
add_html_section "$OUTPUT_FILE" "Network Boundary Malware Protection" "<p>Verifying anti-malware mechanisms at network entry and exit points...</p>" "info"

print_status $CYAN "Checking for anti-malware at network boundaries..."
boundary_details=$(check_boundary_protection)
if [[ "$boundary_details" == *"class='red'"* ]]; then
    add_html_section "$OUTPUT_FILE" "Malware Protection at Network Boundaries" "$boundary_details<p><strong>Remediation:</strong> Implement anti-malware mechanisms at network entry and exit points using Cloud Armor, VPC firewall rules, and other security controls.</p>" "fail"
    ((failed_checks++))
else
    add_html_section "$OUTPUT_FILE" "Malware Protection at Network Boundaries" "$boundary_details<p><strong>Remediation:</strong> Review and enhance network boundary protections to include anti-malware capabilities.</p>" "warning"
    ((warning_checks++))
fi
((total_checks++))

# Manual verification requirements
manual_checks="<p>Manual verification required for complete PCI DSS Requirement 5 compliance:</p>
<ul>
<li><strong>5.1:</strong> Governance and documentation of anti-malware policies and procedures</li>
<li><strong>5.2.2:</strong> Verify anti-malware mechanisms can detect and address all known types of malware</li>
<li><strong>5.3.3:</strong> Configure automatic scanning of removable electronic media</li>
<li><strong>5.3.4:</strong> Enable and retain anti-malware audit logs per Requirement 10.5.1</li>
<li><strong>5.3.5:</strong> Implement tamper protection to prevent unauthorized disabling or alteration</li>
<li><strong>5.4.1:</strong> Implement anti-phishing mechanisms using Google Workspace security features</li>
</ul>
<p><strong>Recommendations:</strong></p>
<ul>
<li>Use Advanced Protection Program for high-risk users</li>
<li>Implement Security Keys (FIDO2) for phishing-resistant authentication</li>
<li>Configure Gmail security settings and Safe Browsing</li>
<li>Enable Security Command Center for centralized threat detection</li>
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