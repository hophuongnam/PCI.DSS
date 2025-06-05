#!/usr/bin/env bash

# PCI DSS Requirement 2 Compliance Check Script for GCP
# This script evaluates GCP system component configurations for PCI DSS Requirement 2 compliance
# Requirements covered: 2.2 - 2.3 (Secure configurations, vendor defaults, wireless security)
# Requirement 2.1 removed - requires manual verification

# Load shared libraries
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"

# Variables for scope control (will use shared library parsing)
ASSESSMENT_SCOPE="project"  # Default to project scope
SPECIFIC_PROJECT=""
SPECIFIC_ORG=""

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 2 Assessment Script"
    echo "==========================================="
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
REQUIREMENT_NUMBER="2"
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
print_status $BLUE "  PCI DSS 4.0.1 - Requirement 2 (GCP)"
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
add_html_section "$OUTPUT_FILE" "GCP Permissions Check" "<p>Verifying access to required GCP services for PCI Requirement 2 assessment...</p>" "info"

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

check_gcp_permission "Compute Engine" "instances" "gcloud compute instances list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "images" "gcloud compute images list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Cloud SQL" "instances" "gcloud sql instances list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "IAM" "service-accounts" "gcloud iam service-accounts list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Resource Manager" "projects" "gcloud projects describe $DEFAULT_PROJECT --limit=1"
((total_checks++))

check_gcp_permission "Cloud Functions" "list" "gcloud functions list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "GKE" "clusters" "gcloud container clusters list $PROJECT_FLAG --limit=1"
((total_checks++))

# Calculate permissions percentage
available_permissions=$((total_checks - access_denied_checks))
if [ $available_permissions -gt 0 ]; then
    permissions_percentage=$(( ((total_checks - access_denied_checks) * 100) / total_checks ))
else
    permissions_percentage=0
fi

if [ $permissions_percentage -lt 70 ]; then
    print_status $RED "WARNING: Insufficient permissions to perform a complete PCI Requirement 2 assessment."
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
# SECTION 2: PCI REQUIREMENT 2.2 - SECURE SYSTEM COMPONENT CONFIG
#----------------------------------------------------------------------
print_status $CYAN "=== PCI REQUIREMENT 2.2: SYSTEM COMPONENTS CONFIGURED AND MANAGED SECURELY ==="

# Check 2.2.1 - Configuration standards
print_status $BLUE "2.2.1 - Configuration standards for system components"
print_status $CYAN "Checking for evidence of configuration standards implementation..."

config_standards_details="<p>Analysis of configuration standards implementation:</p><ul>"

# Check for OS Config policies (organization policy constraints)
if [ "$ASSESSMENT_SCOPE" == "organization" ] && [ -n "$DEFAULT_ORG" ]; then
    org_policies=$(gcloud resource-manager org-policies list --organization=$DEFAULT_ORG --format="value(constraint)" 2>/dev/null | grep -E "(compute|security)" | wc -l)
    
    if [ $org_policies -gt 0 ]; then
        print_status $GREEN "Organization policies for compute/security found"
        config_standards_details+="<li class='green'>Organization policies for compute/security found: $org_policies</li>"
    else
        print_status $YELLOW "No organization policies for compute/security found"
        config_standards_details+="<li class='yellow'>No organization policies for compute/security found</li>"
    fi
fi

# Check for instance templates with secure configurations
instance_templates=$(run_across_projects "gcloud compute instance-templates list" "--format=value(name)")
template_count=$(echo "$instance_templates" | grep -v "^$" | wc -l)

config_standards_details+="<li>Compute instance templates found: $template_count</li>"

if [ $template_count -gt 0 ]; then
    config_standards_details+="<li class='green'>Instance templates can help enforce configuration standards</li>"
else
    config_standards_details+="<li class='yellow'>No instance templates found - consider using templates for consistent configurations</li>"
fi

config_standards_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.2.1 - Configuration standards" "$config_standards_details" "info"
((total_checks++))

# Check 2.2.2 - Vendor default accounts
print_status $BLUE "2.2.2 - Vendor default accounts management"
print_status $CYAN "Checking for vendor default accounts and configurations..."

default_accounts_details="<p>Analysis of vendor default accounts:</p><ul>"

# Check for default service accounts
default_sas=$(run_across_projects "gcloud iam service-accounts list" "--format=value(email)" | grep -E "(compute@developer|appspot)" | wc -l)

if [ $default_sas -gt 0 ]; then
    print_status $YELLOW "Default service accounts detected"
    default_accounts_details+="<li class='yellow'>Default service accounts detected: $default_sas</li>"
    default_accounts_details+="<li>Review if these are necessary and properly secured</li>"
    ((warning_checks++))
else
    print_status $GREEN "No default service accounts detected"
    default_accounts_details+="<li class='green'>No problematic default service accounts detected</li>"
    ((passed_checks++))
fi

# Check for instances using default service accounts
instances_with_default_sa=$(run_across_projects "gcloud compute instances list" "--format=value(name,serviceAccounts.email)" | grep -E "(compute@developer|appspot)" | wc -l)

if [ $instances_with_default_sa -gt 0 ]; then
    print_status $RED "Instances using default service accounts detected"
    default_accounts_details+="<li class='red'>Instances using default service accounts: $instances_with_default_sa</li>"
    ((failed_checks++))
else
    print_status $GREEN "No instances using default service accounts"
    default_accounts_details+="<li class='green'>No instances using default service accounts</li>"
    ((passed_checks++))
fi

default_accounts_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.2.2 - Vendor default accounts" "$default_accounts_details" "warning"
((total_checks++))

# Check 2.2.3 - Primary functions security isolation
print_status $BLUE "2.2.3 - Primary functions with different security levels"
print_status $CYAN "Checking for proper isolation of functions with different security levels..."

security_isolation_details="<p>Analysis of security function isolation:</p><ul>"

# Check for mixed-purpose instances (web + database on same instance)
mixed_instances=$(run_across_projects "gcloud compute instances list" "--format=value(name,tags.items)" | grep -i -E "(web.*db|db.*web|app.*db|db.*app)" | wc -l)

if [ $mixed_instances -gt 0 ]; then
    print_status $YELLOW "Potential mixed-purpose instances detected"
    security_isolation_details+="<li class='yellow'>Potential mixed-purpose instances detected: $mixed_instances</li>"
    security_isolation_details+="<li>Review for proper security level isolation</li>"
    ((warning_checks++))
else
    print_status $GREEN "No obvious mixed-purpose instances detected"
    security_isolation_details+="<li class='green'>No obvious mixed-purpose instances detected</li>"
    ((passed_checks++))
fi

# Check for VPC separation
vpcs=$(run_across_projects "gcloud compute networks list" "--format=value(name)" | grep -v "^$" | wc -l)
security_isolation_details+="<li>VPC networks for isolation: $vpcs</li>"

if [ $vpcs -gt 1 ]; then
    security_isolation_details+="<li class='green'>Multiple VPCs can provide network isolation</li>"
else
    security_isolation_details+="<li class='yellow'>Single VPC - ensure proper subnet isolation</li>"
fi

security_isolation_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.2.3 - Primary functions security isolation" "$security_isolation_details" "info"
((total_checks++))

# Check 2.2.4 - Unnecessary services/functions disabled
print_status $BLUE "2.2.4 - Unnecessary services, protocols, daemons disabled"
print_status $CYAN "Checking for unnecessary services and open ports..."

unnecessary_services_details="<p>Analysis of potentially unnecessary services:</p><ul>"

# Check for instances with external IPs (potential unnecessary exposure)
external_ip_instances=$(run_across_projects "gcloud compute instances list" "--format=value(name,networkInterfaces[0].accessConfigs[0].natIP)" | grep -v "None" | grep -v "^$" | wc -l)

if [ $external_ip_instances -gt 0 ]; then
    print_status $YELLOW "Instances with external IPs detected"
    unnecessary_services_details+="<li class='yellow'>Instances with external IPs: $external_ip_instances</li>"
    unnecessary_services_details+="<li>Review if external access is necessary</li>"
    ((warning_checks++))
else
    print_status $GREEN "No instances with external IPs detected"
    unnecessary_services_details+="<li class='green'>No instances with external IPs detected</li>"
    ((passed_checks++))
fi

# Check for overly permissive firewall rules with detailed analysis like AWS script
high_risk_ports=("22" "3389" "1433" "3306" "5432" "27017" "27018" "6379" "9200" "9300" "8080" "8443" "21" "23")
exposed_details=""
exposed_count=0

# Get firewall rules that expose high-risk ports to 0.0.0.0/0
permissive_fw_rules=$(run_across_projects "gcloud compute firewall-rules list" "--format=value(name,sourceRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW,targetTags.join(','),network)")

if [ -n "$permissive_fw_rules" ]; then
    while IFS=$'\t' read -r fw_name sources allowed tags network; do
        if [ -z "$fw_name" ]; then continue; fi
        
        if [[ "$sources" == *"0.0.0.0/0"* ]]; then
            rule_has_risk=false
            exposed_ports=""
            
            # Check for high-risk ports in allowed rules
            for port in "${high_risk_ports[@]}"; do
                if [[ "$allowed" == *"tcp:$port"* ]] || [[ "$allowed" == *"udp:$port"* ]]; then
                    rule_has_risk=true
                    port_desc=""
                    case "$port" in
                        "22") port_desc="SSH" ;;
                        "3389") port_desc="RDP" ;;
                        "1433") port_desc="MS SQL" ;;
                        "3306") port_desc="MySQL" ;;
                        "5432") port_desc="PostgreSQL" ;;
                        "27017"|"27018") port_desc="MongoDB" ;;
                        "6379") port_desc="Redis" ;;
                        "9200"|"9300") port_desc="Elasticsearch" ;;
                        "8080") port_desc="HTTP Alt" ;;
                        "8443") port_desc="HTTPS Alt" ;;
                        "21") port_desc="FTP" ;;
                        "23") port_desc="Telnet" ;;
                        *) port_desc="Port $port" ;;
                    esac
                    exposed_ports+="<br>- $port_desc (Port $port)"
                fi
            done
            
            if [ "$rule_has_risk" = true ]; then
                ((exposed_count++))
                exposed_details+="<br><br><strong>Firewall Rule:</strong> $fw_name"
                exposed_details+="<br><strong>Network:</strong> $network"
                exposed_details+="<br><strong>Exposed Ports:</strong> $exposed_ports"
                if [ -n "$tags" ]; then
                    exposed_details+="<br><strong>Target Tags:</strong> $tags"
                fi
            fi
        fi
    done <<< "$permissive_fw_rules"
fi

if [ $exposed_count -gt 0 ]; then
    print_status $RED "High-risk ports exposed to internet detected"
    unnecessary_services_details+="<li class='red'>High-risk ports exposed to internet: $exposed_count firewall rules</li>"
    unnecessary_services_details+="<li><strong>Details:</strong>$exposed_details</li>"
    ((failed_checks++))
else
    print_status $GREEN "No high-risk ports exposed to internet"
    unnecessary_services_details+="<li class='green'>No high-risk ports exposed to internet</li>"
    ((passed_checks++))
fi

unnecessary_services_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.2.4 - Unnecessary services disabled" "$unnecessary_services_details" "warning"
((total_checks++))

# Check 2.2.5 - Insecure services documentation and mitigation
print_status $BLUE "2.2.5 - Insecure services, protocols, daemons"
print_status $CYAN "Checking for insecure services and protocols..."

insecure_services_details="<p>Analysis of potentially insecure services:</p><ul>"

# Check for Cloud SQL instances without SSL
cloud_sql_instances=$(run_across_projects "gcloud sql instances list" "--format=value(name)")
insecure_sql_count=0

if [ -n "$cloud_sql_instances" ]; then
    for instance in $cloud_sql_instances; do
        if [ -z "$instance" ]; then continue; fi
        
        # Extract project from instance name if in org scope
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            project=$(echo "$instance" | cut -d'/' -f1)
            instance_name=$(echo "$instance" | cut -d'/' -f2)
        else
            project="$DEFAULT_PROJECT"
            instance_name="$instance"
        fi
        
        ssl_required=$(gcloud sql instances describe "$instance_name" --project="$project" --format="value(settings.ipConfiguration.requireSsl)" 2>/dev/null)
        
        if [ "$ssl_required" != "True" ]; then
            ((insecure_sql_count++))
        fi
    done
    
    if [ $insecure_sql_count -gt 0 ]; then
        print_status $RED "Cloud SQL instances without required SSL detected"
        insecure_services_details+="<li class='red'>Cloud SQL instances without required SSL: $insecure_sql_count</li>"
        ((failed_checks++))
    else
        print_status $GREEN "All Cloud SQL instances require SSL"
        insecure_services_details+="<li class='green'>All Cloud SQL instances require SSL</li>"
        ((passed_checks++))
    fi
else
    insecure_services_details+="<li>No Cloud SQL instances found</li>"
fi

# Check for firewall rules allowing insecure protocols
insecure_protocols=$(run_across_projects "gcloud compute firewall-rules list" "--format=value(name,allowed)" | grep -E "(tcp:21|tcp:23|tcp:53|udp:69)" | wc -l)

if [ $insecure_protocols -gt 0 ]; then
    print_status $RED "Firewall rules allowing insecure protocols detected"
    insecure_services_details+="<li class='red'>Firewall rules allowing insecure protocols: $insecure_protocols</li>"
    ((failed_checks++))
else
    print_status $GREEN "No firewall rules allowing common insecure protocols"
    insecure_services_details+="<li class='green'>No firewall rules allowing common insecure protocols</li>"
    ((passed_checks++))
fi

insecure_services_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.2.5 - Insecure services mitigation" "$insecure_services_details" "warning"
((total_checks++))

# Check 2.2.6 - System security parameters
print_status $BLUE "2.2.6 - System security parameters configured to prevent misuse"
print_status $CYAN "Checking system security parameters..."

security_params_details="<p>Analysis of system security parameters:</p><ul>"

# Check for OS Login enabled
os_login_enabled=0
if [ "$ASSESSMENT_SCOPE" == "organization" ] && [ -n "$DEFAULT_ORG" ]; then
    os_login_policy=$(gcloud resource-manager org-policies describe compute.requireOsLogin --organization=$DEFAULT_ORG --format="value(booleanPolicy.enforced)" 2>/dev/null)
    if [ "$os_login_policy" == "True" ]; then
        os_login_enabled=1
    fi
fi

if [ $os_login_enabled -eq 1 ]; then
    print_status $GREEN "OS Login enforced at organization level"
    security_params_details+="<li class='green'>OS Login enforced at organization level</li>"
    ((passed_checks++))
else
    print_status $YELLOW "OS Login not enforced at organization level"
    security_params_details+="<li class='yellow'>OS Login not enforced at organization level</li>"
    ((warning_checks++))
fi

# Check for serial port access disabled
serial_port_disabled=0
if [ "$ASSESSMENT_SCOPE" == "organization" ] && [ -n "$DEFAULT_ORG" ]; then
    serial_port_policy=$(gcloud resource-manager org-policies describe compute.disableSerialPortAccess --organization=$DEFAULT_ORG --format="value(booleanPolicy.enforced)" 2>/dev/null)
    if [ "$serial_port_policy" == "True" ]; then
        serial_port_disabled=1
    fi
fi

if [ $serial_port_disabled -eq 1 ]; then
    print_status $GREEN "Serial port access disabled at organization level"
    security_params_details+="<li class='green'>Serial port access disabled at organization level</li>"
    ((passed_checks++))
else
    print_status $YELLOW "Serial port access not disabled at organization level"
    security_params_details+="<li class='yellow'>Serial port access not disabled at organization level</li>"
    ((warning_checks++))
fi

security_params_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.2.6 - System security parameters" "$security_params_details" "warning"
((total_checks++))

# Check 2.2.7 - Non-console administrative access encryption
print_status $BLUE "2.2.7 - Non-console administrative access encryption"
print_status $CYAN "Checking for encrypted administrative access..."

admin_encryption_details="<p>Analysis of administrative access encryption:</p><ul>"

# Check for instances allowing SSH with passwords
ssh_password_instances=$(run_across_projects "gcloud compute instances list" "--format=value(name,metadata.items)" | grep -i "enable-oslogin.*false" | wc -l)

if [ $ssh_password_instances -gt 0 ]; then
    print_status $YELLOW "Instances potentially allowing SSH password authentication"
    admin_encryption_details+="<li class='yellow'>Instances potentially allowing SSH password authentication: $ssh_password_instances</li>"
    ((warning_checks++))
else
    print_status $GREEN "No instances explicitly allowing SSH password authentication"
    admin_encryption_details+="<li class='green'>No instances explicitly allowing SSH password authentication</li>"
    ((passed_checks++))
fi

# GCP uses SSH keys by default, which provides encryption
admin_encryption_details+="<li class='green'>GCP uses SSH key-based authentication by default (encrypted)</li>"

admin_encryption_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.2.7 - Administrative access encryption" "$admin_encryption_details" "pass"
((total_checks++))

# Check for Cloud Storage (equivalent to S3) configurations
print_status $BLUE "2.2.4 continued - Cloud Storage bucket configurations"
print_status $CYAN "Checking Cloud Storage buckets for secure configurations..."

storage_details="<p>Analysis of Cloud Storage bucket configurations:</p><ul>"

# Get all Cloud Storage buckets
buckets=$(run_across_projects "gsutil ls" "" 2>/dev/null | grep "gs://" | sed 's|gs://||' | sed 's|/$||')
bucket_count=0

if [ -n "$buckets" ]; then
    bucket_count=$(echo "$buckets" | grep -v "^$" | wc -l)
    
    if [ $bucket_count -gt 0 ]; then
        public_buckets=0
        unencrypted_buckets=0
        
        while IFS= read -r bucket; do
            if [ -z "$bucket" ]; then continue; fi
            
            # Check for public access
            bucket_iam=$(gsutil iam get "gs://$bucket" 2>/dev/null | grep -E "(allUsers|allAuthenticatedUsers)")
            if [ -n "$bucket_iam" ]; then
                ((public_buckets++))
            fi
            
            # Check for encryption (default encryption is always enabled in GCP)
            # But we can check if customer-managed encryption keys are used
            encryption_info=$(gsutil kms encryption "gs://$bucket" 2>/dev/null)
            if [[ "$encryption_info" == *"No encryption key"* ]]; then
                # This uses Google-managed encryption, which is still secure
                storage_details+="<li>Bucket $bucket: Using Google-managed encryption</li>"
            else
                storage_details+="<li>Bucket $bucket: Using customer-managed encryption</li>"
            fi
            
        done <<< "$buckets"
        
        if [ $public_buckets -gt 0 ]; then
            print_status $RED "Public Cloud Storage buckets detected"
            storage_details+="<li class='red'>Public buckets detected: $public_buckets</li>"
            ((failed_checks++))
        else
            print_status $GREEN "No public Cloud Storage buckets detected"
            storage_details+="<li class='green'>No public buckets detected</li>"
            ((passed_checks++))
        fi
    else
        storage_details+="<li>No Cloud Storage buckets found</li>"
        ((passed_checks++))
    fi
else
    storage_details+="<li>No Cloud Storage buckets found or gsutil not available</li>"
    ((passed_checks++))
fi

storage_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.2.4 - Cloud Storage Security" "$storage_details" "info"
((total_checks++))

#----------------------------------------------------------------------
# SECTION 3: PCI REQUIREMENT 2.3 - WIRELESS ENVIRONMENTS  
#----------------------------------------------------------------------
print_status $CYAN "=== PCI REQUIREMENT 2.3: WIRELESS ENVIRONMENTS CONFIGURED SECURELY ==="

# Check 2.3.1 & 2.3.2 - Wireless security
print_status $BLUE "2.3.1 & 2.3.2 - Wireless environment security"
print_status $CYAN "Checking for wireless environment configurations..."

wireless_details="<p>Analysis of wireless environment security:</p><ul>"

# GCP doesn't have traditional wireless infrastructure, but check for related services
wireless_details+="<li class='green'>GCP cloud infrastructure doesn't include traditional wireless access points</li>"
wireless_details+="<li>Wireless security is the responsibility of client-side infrastructure</li>"
wireless_details+="<li>Consider reviewing any hybrid connectivity solutions for wireless security</li>"

# Check for VPN connections which might involve wireless
vpn_gateways=$(run_across_projects "gcloud compute vpn-gateways list" "--format=value(name)" | grep -v "^$" | wc -l)

if [ $vpn_gateways -gt 0 ]; then
    wireless_details+="<li>VPN gateways found: $vpn_gateways</li>"
    wireless_details+="<li class='yellow'>Ensure VPN connections have appropriate encryption</li>"
    ((warning_checks++))
else
    wireless_details+="<li>No VPN gateways found</li>"
    ((passed_checks++))
fi

# Check for default service accounts (similar to AWS IAM default users)
print_status $BLUE "2.3.1 continued - Default account management"
print_status $CYAN "Checking for usage of default service accounts..."

default_sa_usage=$(run_across_projects "gcloud compute instances list" "--format=value(name,serviceAccounts.email)" | grep -E "(compute@developer|appspot)" | wc -l)

if [ $default_sa_usage -gt 0 ]; then
    wireless_details+="<li class='red'>Instances using default service accounts: $default_sa_usage</li>"
    ((failed_checks++))
else
    wireless_details+="<li class='green'>No instances using default service accounts</li>"
    ((passed_checks++))
fi

wireless_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.3.1 & 2.3.2 - Wireless environment security" "$wireless_details" "warning"
((total_checks++))

#----------------------------------------------------------------------
# SECTION 4: ADDITIONAL CHECKS BASED ON AWS R2 SCRIPT
#----------------------------------------------------------------------

# Check for TLS configuration on Load Balancers (equivalent to AWS ELB)
print_status $BLUE "2.2.7 continued - Load Balancer TLS Configuration"
print_status $CYAN "Checking load balancer TLS configurations..."

tls_details="<p>Analysis of load balancer TLS configurations:</p><ul>"

# Check for Load Balancers
load_balancers=$(run_across_projects "gcloud compute forwarding-rules list" "--format=value(name,target,portRange)" | grep -E "(https|ssl)")
lb_count=$(echo "$load_balancers" | grep -v "^$" | wc -l)

if [ $lb_count -gt 0 ]; then
    tls_details+="<li>HTTPS/SSL load balancers found: $lb_count</li>"
    tls_details+="<li class='green'>Load balancers are using encrypted connections</li>"
    ((passed_checks++))
else
    # Check for HTTP load balancers that should be HTTPS
    http_lbs=$(run_across_projects "gcloud compute forwarding-rules list" "--format=value(name,target,portRange)" | grep -E "80|8080")
    http_count=$(echo "$http_lbs" | grep -v "^$" | wc -l)
    
    if [ $http_count -gt 0 ]; then
        tls_details+="<li class='yellow'>HTTP load balancers found: $http_count</li>"
        tls_details+="<li>Consider migrating to HTTPS for encrypted communication</li>"
        ((warning_checks++))
    else
        tls_details+="<li>No load balancers found or all use encrypted protocols</li>"
        ((passed_checks++))
    fi
fi

tls_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.2.7 - Load Balancer TLS Configuration" "$tls_details" "info"
((total_checks++))

# Check for audit logging (equivalent to AWS CloudTrail)
print_status $BLUE "2.5.1 - Audit logging for change management"
print_status $CYAN "Checking for audit logging configurations..."

audit_details="<p>Analysis of audit logging configurations:</p><ul>"

# Check for Cloud Audit Logs
audit_logs_enabled=0
if [ "$ASSESSMENT_SCOPE" == "organization" ] && [ -n "$DEFAULT_ORG" ]; then
    # Check organization-level audit logging
    org_audit_config=$(gcloud logging sinks list --organization=$DEFAULT_ORG --format="value(name)" 2>/dev/null | wc -l)
    if [ $org_audit_config -gt 0 ]; then
        audit_logs_enabled=1
        audit_details+="<li class='green'>Organization-level audit logging sinks found: $org_audit_config</li>"
    fi
else
    # Check project-level audit logging
    project_audit_config=$(gcloud logging sinks list --project=$DEFAULT_PROJECT --format="value(name)" 2>/dev/null | wc -l)
    if [ $project_audit_config -gt 0 ]; then
        audit_logs_enabled=1
        audit_details+="<li class='green'>Project-level audit logging sinks found: $project_audit_config</li>"
    fi
fi

# Check for Cloud Audit Logs API
audit_logs_api=$(gcloud services list --enabled --filter="name:cloudaudit.googleapis.com" --format="value(name)" 2>/dev/null)
if [ -n "$audit_logs_api" ]; then
    audit_details+="<li class='green'>Cloud Audit Logs API is enabled</li>"
    ((passed_checks++))
else
    audit_details+="<li class='red'>Cloud Audit Logs API is not enabled</li>"
    ((failed_checks++))
fi

audit_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.5.1 - Audit logging for change management" "$audit_details" "info"
((total_checks++))

# Check for unused/unnecessary resources (equivalent to AWS unused security groups)
print_status $BLUE "2.6.1 - Unused resources cleanup"
print_status $CYAN "Checking for unused firewall rules and other resources..."

cleanup_details="<p>Analysis of potentially unused resources:</p><ul>"

# Check for unused firewall rules (rules not applied to any instances)
all_fw_rules=$(run_across_projects "gcloud compute firewall-rules list" "--format=value(name,targetTags.join(','),targetServiceAccounts.join(','),network)")
unused_fw_rules=0

if [ -n "$all_fw_rules" ]; then
    while IFS=$'\t' read -r fw_name tags service_accounts network; do
        if [ -z "$fw_name" ]; then continue; fi
        
        # If rule has no target tags or service accounts, it applies to all instances
        if [ -z "$tags" ] && [ -z "$service_accounts" ]; then
            continue
        fi
        
        # Check if any instances use these tags
        if [ -n "$tags" ]; then
            IFS=',' read -ra TAG_ARRAY <<< "$tags"
            rule_in_use=false
            
            for tag in "${TAG_ARRAY[@]}"; do
                instances_with_tag=$(run_across_projects "gcloud compute instances list" "--format=value(name)" "--filter=tags.items:$tag" | wc -l)
                if [ $instances_with_tag -gt 0 ]; then
                    rule_in_use=true
                    break
                fi
            done
            
            if [ "$rule_in_use" = false ]; then
                ((unused_fw_rules++))
            fi
        fi
    done <<< "$all_fw_rules"
fi

if [ $unused_fw_rules -gt 0 ]; then
    cleanup_details+="<li class='yellow'>Potentially unused firewall rules: $unused_fw_rules</li>"
    cleanup_details+="<li>Review and remove unused firewall rules to reduce complexity</li>"
    ((warning_checks++))
else
    cleanup_details+="<li class='green'>No obviously unused firewall rules detected</li>"
    ((passed_checks++))
fi

# Check for unused static IP addresses
unused_static_ips=$(run_across_projects "gcloud compute addresses list" "--format=value(name,status)" | grep "RESERVED" | wc -l)

if [ $unused_static_ips -gt 0 ]; then
    cleanup_details+="<li class='yellow'>Unused static IP addresses: $unused_static_ips</li>"
    cleanup_details+="<li>Consider releasing unused static IP addresses</li>"
    ((warning_checks++))
else
    cleanup_details+="<li class='green'>No unused static IP addresses found</li>"
    ((passed_checks++))
fi

cleanup_details+="</ul>"

add_html_section "$OUTPUT_FILE" "2.6.1 - Unused resources cleanup" "$cleanup_details" "info"
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
print_status $GREEN "=================================================================="
echo ""
print_status $CYAN "Report has been generated: $OUTPUT_FILE"
print_status $GREEN "=================================================================="