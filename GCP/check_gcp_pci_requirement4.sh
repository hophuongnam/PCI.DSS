#!/usr/bin/env bash

# PCI DSS Requirement 4 Compliance Check Script for GCP
# This script evaluates GCP controls for PCI DSS Requirement 4 compliance
# Requirements covered: 4.2 (Protect Cardholder Data with Strong Cryptography During Transmission)
# Requirement 4.1 removed - requires manual verification

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="4"

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

# Check permissions using shared library based on requirement
case "$REQUIREMENT_NUMBER" in
    "4") check_required_permissions "compute.sslPolicies.list" "compute.targetHttpsProxies.list" "compute.urlMaps.list" || exit 1 ;;
    "5") check_required_permissions "compute.instances.list" "compute.instanceTemplates.list" || exit 1 ;;
    "6") check_required_permissions "clouddeploy.deliveryPipelines.list" "run.services.list" || exit 1 ;;
    "7") check_required_permissions "iam.roles.list" "iam.serviceAccounts.list" || exit 1 ;;
    "8") check_required_permissions "iam.serviceAccounts.list" "compute.instances.list" || exit 1 ;;
    "9") check_required_permissions "compute.instances.list" "compute.zones.list" || exit 1 ;;
    "10") check_required_permissions "logging.logs.list" "logging.sinks.list" || exit 1 ;;
    "11") check_required_permissions "compute.instanceGroups.list" "container.clusters.list" || exit 1 ;;
    "12") check_required_permissions "resourcemanager.projects.getIamPolicy" "iam.serviceAccounts.list" || exit 1 ;;
esac

# Initialize HTML report using shared library
# Set output file path
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"

# Initialize HTML report using shared library
initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"
# Begin main assessment logic











print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 4 (GCP)"
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


# Function to check Load Balancer TLS configurations
check_load_balancer_tls() {
    local details=""
    local found_issues=false
    
    print_status "INFO" "Checking Cloud Load Balancers for TLS configurations..."
    
    # Check HTTPS Load Balancers
    details+="<p>Analysis of GCP Load Balancers for TLS configurations:</p><ul>"
    
    # Get all forwarding rules for HTTPS/SSL
    https_lb_rules=$(run_gcp_command_across_projects "gcloud compute forwarding-rules list" "--format=value(name,target,portRange)" | grep -E "(https|ssl|443)")
    
    if [ -n "$https_lb_rules" ]; then
        details+="<li><strong>HTTPS/SSL Load Balancers:</strong></li><ul>"
        
        while IFS=$'\t' read -r rule_name target port_range; do
            if [ -z "$rule_name" ]; then continue; fi
            
            # Extract project from rule name if in org scope
            if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                project=$(echo "$rule_name" | cut -d'/' -f1)
                rule_name_only=$(echo "$rule_name" | cut -d'/' -f2)
            else
                project="$DEFAULT_PROJECT"
                rule_name_only="$rule_name"
            fi
            
            details+="<li>Load Balancer Rule: $rule_name_only (Project: $project)</li><ul>"
            
            # Check target proxy for SSL policy
            if [[ "$target" == *"targetHttpsProxies"* ]]; then
                proxy_name=$(basename "$target")
                SSL_POLICY=$(gcloud compute target-https-proxies describe "$proxy_name" --project="$project" --format="value(sslPolicy)" 2>/dev/null)
                
                if [ -n "$SSL_POLICY" ]; then
                    # Get SSL policy details
                    policy_name=$(basename "$SSL_POLICY")
                    POLICY_DETAILS=$(gcloud compute ssl-policies describe "$policy_name" --project="$project" 2>/dev/null)
                    
                    # Check minimum TLS version
                    MIN_TLS_VERSION=$(echo "$POLICY_DETAILS" | grep -o '"minTlsVersion": "[^"]*' | cut -d'"' -f4)
                    
                    case "$MIN_TLS_VERSION" in
                        "TLS_1_0")
                            details+="<li class='red'>Uses deprecated minimum TLS version: $MIN_TLS_VERSION</li>"
                            found_issues=true
                            ;;
                        "TLS_1_1")
                            details+="<li class='yellow'>Uses deprecated minimum TLS version: $MIN_TLS_VERSION</li>"
                            found_issues=true
                            ;;
                        "TLS_1_2"|"TLS_1_3")
                            details+="<li class='green'>Uses secure minimum TLS version: $MIN_TLS_VERSION</li>"
                            ;;
                        *)
                            details+="<li class='yellow'>Unknown TLS version: $MIN_TLS_VERSION</li>"
                            found_issues=true
                            ;;
                    esac
                    
                    # Check profile (cipher suite)
                    PROFILE=$(echo "$POLICY_DETAILS" | grep -o '"profile": "[^"]*' | cut -d'"' -f4)
                    case "$PROFILE" in
                        "COMPATIBLE")
                            details+="<li class='yellow'>Uses COMPATIBLE profile (may allow weak ciphers)</li>"
                            found_issues=true
                            ;;
                        "MODERN"|"RESTRICTED")
                            details+="<li class='green'>Uses secure profile: $PROFILE</li>"
                            ;;
                        "CUSTOM")
                            details+="<li class='yellow'>Uses CUSTOM profile (requires manual verification)</li>"
                            found_issues=true
                            ;;
                        *)
                            details+="<li class='yellow'>Unknown profile: $PROFILE</li>"
                            found_issues=true
                            ;;
                    esac
                else
                    details+="<li class='yellow'>No SSL policy configured (using default)</li>"
                    found_issues=true
                fi
            elif [[ "$target" == *"targetSslProxies"* ]]; then
                proxy_name=$(basename "$target")
                SSL_POLICY=$(gcloud compute target-ssl-proxies describe "$proxy_name" --project="$project" --format="value(sslPolicy)" 2>/dev/null)
                
                if [ -n "$SSL_POLICY" ]; then
                    policy_name=$(basename "$SSL_POLICY")
                    details+="<li class='green'>SSL proxy with policy: $policy_name</li>"
                else
                    details+="<li class='yellow'>SSL proxy with default policy</li>"
                    found_issues=true
                fi
            else
                details+="<li class='yellow'>Non-HTTPS/SSL target: $target</li>"
            fi
            
            details+="</ul>"
        done
        
        details+="</ul>"
    else
        details+="<li>No HTTPS/SSL load balancers found</li>"
    fi
    
    # Check for HTTP-only load balancers that should be HTTPS
    http_lb_rules=$(run_gcp_command_across_projects "gcloud compute forwarding-rules list" "--format=value(name,target,portRange)" | grep -E "(80|8080)" | grep -v -E "(https|ssl|443)")
    
    if [ -n "$http_lb_rules" ]; then
        details+="<li><strong>HTTP-only Load Balancers (potential issues):</strong></li><ul>"
        
        while IFS=$'\t' read -r rule_name target port_range; do
            if [ -z "$rule_name" ]; then continue; fi
            
            # Extract project from rule name if in org scope
            if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                project=$(echo "$rule_name" | cut -d'/' -f1)
                rule_name_only=$(echo "$rule_name" | cut -d'/' -f2)
            else
                project="$DEFAULT_PROJECT"
                rule_name_only="$rule_name"
            fi
            
            details+="<li class='yellow'>HTTP-only Load Balancer: $rule_name_only (Project: $project) - Port: $port_range</li>"
            found_issues=true
        done
        
        details+="</ul>"
    fi
    
    details+="</ul>"
    
    # Return the results
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 4 (GCP)"
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


# Function to check SSL certificates inventory and expiration
check_ssl_certificates() {
    local details=""
    local found_issues=false
    
    print_status "INFO" "Checking SSL certificates for inventory and expiration..."
    
    # Get all SSL certificates
    ssl_certs=$(run_gcp_command_across_projects "gcloud compute ssl-certificates list" "--format=value(name,domains,notValidAfter)")
    
    if [ -n "$ssl_certs" ]; then
        details+="<p>Analysis of SSL certificates:</p><ul>"
        
        while IFS=$'\t' read -r cert_name domains expiration; do
            if [ -z "$cert_name" ]; then continue; fi
            
            # Extract project from cert name if in org scope
            if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                project=$(echo "$cert_name" | cut -d'/' -f1)
                cert_name_only=$(echo "$cert_name" | cut -d'/' -f2)
            else
                project="$DEFAULT_PROJECT"
                cert_name_only="$cert_name"
            fi
            
            details+="<li>Certificate: $cert_name_only (Project: $project)</li><ul>"
            details+="<li>Domains: $domains</li>"
            
            if [ -n "$expiration" ]; then
                # Calculate days until expiration
                if [[ "$OSTYPE" == "darwin"* ]]; then
                    # macOS (BSD date)
                    expiration_fmt=$(echo "$expiration" | sed 's/T/ /' | sed 's/\.[0-9]*Z$//')
                    expiration_ts=$(date -j -f "%Y-%m-%d %H:%M:%S" "$expiration_fmt" +%s 2>/dev/null)
                    if [ $? -ne 0 ]; then
                        # Try alternative format
                        expiration_ts=$(date -j -f "%Y-%m-%d" "$(echo $expiration | cut -d'T' -f1)" +%s 2>/dev/null)
                    fi
                else
                    # Linux (GNU date)
                    expiration_ts=$(date -d "$expiration" +%s 2>/dev/null)
                fi
                
                if [ $? -eq 0 ]; then
                    current_ts=$(date +%s)
                    days_remaining=$(( (expiration_ts - current_ts) / 86400 ))
                    
                    if [ $days_remaining -lt 30 ]; then
                        details+="<li class='red'>Expires in $days_remaining days ($expiration)</li>"
                        found_issues=true
                    elif [ $days_remaining -lt 90 ]; then
                        details+="<li class='yellow'>Expires in $days_remaining days ($expiration)</li>"
                        found_issues=true
                    else
                        details+="<li class='green'>Expires in $days_remaining days ($expiration)</li>"
                    fi
                else
                    details+="<li class='yellow'>Unable to parse expiration date: $expiration</li>"
                    found_issues=true
                fi
            else
                details+="<li class='yellow'>No expiration date available</li>"
                found_issues=true
            fi
            
            details+="</ul>"
        done
        
        details+="</ul>"
    else
        details+="<p>No SSL certificates found.</p>"
    fi
    
    # Return the results
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 4 (GCP)"
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


# Function to check for unencrypted services in firewall rules
check_unencrypted_services() {
    local details=""
    local found_issues=false
    
    print_status "INFO" "Checking firewall rules for unencrypted services..."
    
    # Define unencrypted services and their ports
    declare -A unencrypted_services=(
        ["21"]="FTP"
        ["23"]="Telnet"
        ["25"]="SMTP"
        ["53"]="DNS"
        ["80"]="HTTP"
        ["110"]="POP3"
        ["143"]="IMAP"
        ["161"]="SNMP"
        ["1433"]="MS SQL Server"
        ["3306"]="MySQL"
        ["5432"]="PostgreSQL"
        ["6379"]="Redis"
        ["9200"]="Elasticsearch"
        ["27017"]="MongoDB"
    )
    
    details+="<p>Analysis of firewall rules for potentially unencrypted services:</p><ul>"
    
    # Get all firewall rules
    firewall_rules=$(run_gcp_command_across_projects "gcloud compute firewall-rules list" "--format=value(name,direction,sourceRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW,targetTags.join(','),network)")
    
    if [ -n "$firewall_rules" ]; then
        while IFS=$'\t' read -r fw_name direction sources allowed tags network; do
            if [ -z "$fw_name" ]; then continue; fi
            
            # Extract project from fw name if in org scope
            if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                project=$(echo "$fw_name" | cut -d'/' -f1)
                fw_name_only=$(echo "$fw_name" | cut -d'/' -f2)
            else
                project="$DEFAULT_PROJECT"
                fw_name_only="$fw_name"
            fi
            
            # Check if this is an ingress rule allowing traffic from internet
            if [ "$direction" = "INGRESS" ] && [[ "$sources" == *"0.0.0.0/0"* ]]; then
                rule_has_issues=false
                exposed_services=""
                
                # Check for unencrypted services
                for port in "${!unencrypted_services[@]}"; do
                    service_name="${unencrypted_services[$port]}"
                    
                    if [[ "$allowed" == *"tcp:$port"* ]] || [[ "$allowed" == *"udp:$port"* ]]; then
                        rule_has_issues=true
                        exposed_services+="<br>- $service_name (Port $port)"
                        
                        # Special severity for particularly dangerous services
                        case "$port" in
                            "21"|"23"|"110"|"143")
                                service_severity="red"
                                ;;
                            "80"|"25"|"53"|"161")
                                service_severity="yellow"
                                ;;
                            "1433"|"3306"|"5432"|"6379"|"9200"|"27017")
                                service_severity="red"
                                ;;
                            *)
                                service_severity="yellow"
                                ;;
                        esac
                    fi
                done
                
                if [ "$rule_has_issues" = true ]; then
                    details+="<li class='$service_severity'>Firewall Rule: $fw_name_only (Project: $project)</li><ul>"
                    details+="<li>Network: $network</li>"
                    details+="<li>Exposed unencrypted services: $exposed_services</li>"
                    if [ -n "$tags" ]; then
                        details+="<li>Target tags: $tags</li>"
                    fi
                    details+="</ul>"
                    found_issues=true
                fi
            fi
        done
    else
        details+="<li>No firewall rules found</li>"
    fi
    
    details+="</ul>"
    
    # Return the results
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 4 (GCP)"
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


# Function to check Cloud CDN and Cloud Armor configurations
check_cloud_cdn_armor() {
    local details=""
    local found_issues=false
    
    print_status "INFO" "Checking Cloud CDN and Cloud Armor configurations..."
    
    details+="<p>Analysis of Cloud CDN and Cloud Armor for secure transmission:</p><ul>"
    
    # Check Cloud CDN configurations
    cdn_configs=$(run_gcp_command_across_projects "gcloud compute backend-services list" "--format=value(name,enableCDN)")
    
    if [ -n "$cdn_configs" ]; then
        details+="<li><strong>Cloud CDN Backend Services:</strong></li><ul>"
        
        while IFS=$'\t' read -r service_name cdn_enabled; do
            if [ -z "$service_name" ]; then continue; fi
            
            # Extract project from service name if in org scope
            if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                project=$(echo "$service_name" | cut -d'/' -f1)
                service_name_only=$(echo "$service_name" | cut -d'/' -f2)
            else
                project="$DEFAULT_PROJECT"
                service_name_only="$service_name"
            fi
            
            if [ "$cdn_enabled" = "True" ]; then
                details+="<li class='green'>Backend Service: $service_name_only (Project: $project) - CDN enabled</li>"
            else
                details+="<li>Backend Service: $service_name_only (Project: $project) - CDN not enabled</li>"
            fi
        done
        
        details+="</ul>"
    else
        details+="<li>No backend services found</li>"
    fi
    
    # Check Cloud Armor security policies
    armor_policies=$(run_gcp_command_across_projects "gcloud compute security-policies list" "--format=value(name)")
    
    if [ -n "$armor_policies" ]; then
        details+="<li><strong>Cloud Armor Security Policies:</strong></li><ul>"
        
        while IFS= read -r policy_name; do
            if [ -z "$policy_name" ]; then continue; fi
            
            # Extract project from policy name if in org scope
            if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                project=$(echo "$policy_name" | cut -d'/' -f1)
                policy_name_only=$(echo "$policy_name" | cut -d'/' -f2)
            else
                project="$DEFAULT_PROJECT"
                policy_name_only="$policy_name"
            fi
            
            details+="<li class='green'>Security Policy: $policy_name_only (Project: $project)</li>"
        done
        
        details+="</ul>"
    else
        details+="<li>No Cloud Armor security policies found</li>"
    fi
    
    details+="</ul>"
    
    # Return the results
    echo "$details"
    return 0
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
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 4 (GCP)"
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
add_html_section "$OUTPUT_FILE" "GCP Permissions Check" "<p>Verifying access to required GCP services for PCI Requirement 4 assessment...</p>" "info"

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

check_gcp_permission "Compute Engine" "forwarding-rules" "gcloud compute forwarding-rules list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "ssl-certificates" "gcloud compute ssl-certificates list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "ssl-policies" "gcloud compute ssl-policies list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "target-https-proxies" "gcloud compute target-https-proxies list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "firewall-rules" "gcloud compute firewall-rules list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "backend-services" "gcloud compute backend-services list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "security-policies" "gcloud compute security-policies list $PROJECT_FLAG --limit=1"
((total_checks++))

# Calculate permissions percentage
available_permissions=$((total_checks - access_denied_checks))
if [ $available_permissions -gt 0 ]; then
    permissions_percentage=$(( ((total_checks - access_denied_checks) * 100) / total_checks ))
else
    permissions_percentage=0
fi

if [ $permissions_percentage -lt 70 ]; then
    print_status "FAIL" "WARNING: Insufficient permissions to perform a complete PCI Requirement 4 assessment."
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
# SECTION 2: PCI REQUIREMENT 4.2 - STRONG CRYPTOGRAPHY FOR TRANSMISSION
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 4.2: STRONG CRYPTOGRAPHY FOR TRANSMISSION ==="

add_html_section "$OUTPUT_FILE" "Requirement 4.2: PAN is protected with strong cryptography during transmission" "<p>Analyzing strong cryptography and security protocols for PAN transmission protection...</p>" "info"

# Check 4.2.1 - Strong cryptography and security protocols implementation
print_status "INFO" "4.2.1 - Strong cryptography and security protocols implementation"
print_status "INFO" "Checking load balancers for strong cryptography implementation..."

lb_tls_details=$(check_load_balancer_tls)
lb_tls_result=$?

if [ $lb_tls_result -ne 0 ]; then
    add_html_section "$OUTPUT_FILE" "4.2.1 - Strong Cryptography Implementation" "<p>According to PCI DSS Requirement 4.2.1, strong cryptography and security protocols must be implemented to safeguard PAN during transmission over open, public networks, including:</p><ul><li>Only trusted keys and certificates are accepted</li><li>The protocol supports only secure versions or configurations</li><li>The encryption strength is appropriate for the encryption methodology in use</li></ul>$lb_tls_details<p class='yellow'>Review and update TLS configurations to use only secure protocols and cipher suites. Disable support for deprecated protocols like TLS 1.0 and TLS 1.1.</p>" "warning"
    ((total_checks++))
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "4.2.1 - Strong Cryptography Implementation" "<p class='green'>Load balancer TLS configurations appear to use secure protocols and cipher suites.</p>$lb_tls_details" "pass"
    ((total_checks++))
    ((passed_checks++))
fi

# Check 4.2.1.1 - Inventory of trusted keys and certificates
print_status "INFO" "4.2.1.1 - Inventory of trusted keys and certificates"
print_status "INFO" "Checking SSL certificate inventory and expiration..."

cert_details=$(check_ssl_certificates)
cert_result=$?

if [ $cert_result -ne 0 ]; then
    add_html_section "$OUTPUT_FILE" "4.2.1.1 - Certificate Inventory and Management" "<p>According to PCI DSS Requirement 4.2.1.1, an inventory of the entity's trusted keys and certificates used to protect PAN during transmission must be maintained.</p>$cert_details<p class='yellow'>Maintain an inventory of all certificates used to protect PAN during transmission. Regularly review and update the inventory. Replace expiring or expired certificates promptly.</p>" "warning"
    ((total_checks++))
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "4.2.1.1 - Certificate Inventory and Management" "<p class='green'>SSL certificates appear to be properly managed with adequate expiration timeframes.</p>$cert_details" "pass"
    ((total_checks++))
    ((passed_checks++))
fi

# Check 4.2.1.2 - Wireless networks (if applicable)
print_status "INFO" "4.2.1.2 - Wireless networks cryptography"
print_status "INFO" "Checking for wireless network configurations..."

# GCP doesn't have traditional wireless infrastructure, but check for VPN connections
vpn_gateways=$(run_gcp_command_across_projects "gcloud compute vpn-gateways list" "--format=value(name)" | grep -v "^$" | wc -l)

wireless_details="<p>Analysis of wireless and VPN connectivity for PAN transmission:</p><ul>"

if [ $vpn_gateways -gt 0 ]; then
    wireless_details+="<li>VPN gateways found: $vpn_gateways</li>"
    wireless_details+="<li class='yellow'>Manual verification required to ensure VPN connections use strong cryptography for PAN transmission</li>"
    
    add_html_section "$OUTPUT_FILE" "4.2.1.2 - Wireless Networks Cryptography" "$wireless_details</ul><p>According to PCI DSS Requirement 4.2.1.2, wireless networks transmitting PAN or connected to the CDE must use industry best practices to implement strong cryptography for authentication and transmission.</p><p class='yellow'>Verify that VPN connections and any wireless connectivity use industry best practices for strong cryptography when transmitting PAN.</p>" "warning"
    ((total_checks++))
    ((warning_checks++))
else
    wireless_details+="<li class='green'>No VPN gateways found</li>"
    wireless_details+="<li>GCP cloud infrastructure doesn't include traditional wireless access points</li>"
    
    add_html_section "$OUTPUT_FILE" "4.2.1.2 - Wireless Networks Cryptography" "$wireless_details</ul><p>GCP cloud infrastructure doesn't include traditional wireless access points. Wireless security is the responsibility of client-side infrastructure.</p>" "pass"
    ((total_checks++))
    ((passed_checks++))
fi

# Check 4.2.2 - PAN secured via end-user messaging technologies
print_status "INFO" "4.2.2 - PAN secured via end-user messaging technologies"
print_status "INFO" "Checking for unencrypted services that could transmit PAN..."

unencrypted_details=$(check_unencrypted_services)
unencrypted_result=$?

if [ $unencrypted_result -ne 0 ]; then
    add_html_section "$OUTPUT_FILE" "4.2.2 - Prevent Unencrypted PAN Transmission" "<p>According to PCI DSS Requirement 4.2.2, PAN must be secured with strong cryptography whenever it is sent via end-user messaging technologies.</p>$unencrypted_details<p class='red'>Replace unencrypted services with encrypted alternatives. Ensure PAN is never transmitted over unencrypted channels. If unencrypted protocols are necessary for non-PAN data, implement network segmentation to prevent PAN exposure.</p>" "fail"
    ((total_checks++))
    ((failed_checks++))
else
    add_html_section "$OUTPUT_FILE" "4.2.2 - Prevent Unencrypted PAN Transmission" "<p class='green'>No firewall rules allowing unencrypted services from the internet were detected.</p>$unencrypted_details" "pass"
    ((total_checks++))
    ((passed_checks++))
fi

# Additional check - Cloud CDN and Cloud Armor
print_status "INFO" "4.2.1 continued - Cloud CDN and Cloud Armor"
print_status "INFO" "Checking Cloud CDN and Cloud Armor configurations..."

cdn_armor_details=$(check_cloud_cdn_armor)

add_html_section "$OUTPUT_FILE" "4.2.1 - Cloud CDN and Cloud Armor Security" "<p>Analysis of Cloud CDN and Cloud Armor configurations for secure content delivery and protection:</p>$cdn_armor_details<p>Cloud CDN provides TLS encryption for content delivery, and Cloud Armor provides DDoS protection and WAF capabilities that can help secure PAN transmission.</p>" "info"
((total_checks++))

#----------------------------------------------------------------------
# FINALIZE THE REPORT
#----------------------------------------------------------------------
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
