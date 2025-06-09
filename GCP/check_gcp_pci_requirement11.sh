#!/usr/bin/env bash

# PCI DSS Requirement 11 Compliance Check Script for GCP (Framework-Migrated Version)
# This script evaluates GCP security testing and monitoring for PCI DSS Requirement 11 compliance
# Requirements covered: 11.1 - 11.6 (Test Security of Systems and Networks Regularly)

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="11"

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
check_required_permissions "compute.instances.list" "security.assessments.list" || exit 1

# Initialize HTML report using shared library
# Set output file path
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"

# Initialize HTML report using shared library
initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 11 (GCP)"
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


# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 11 Assessment Script (Framework Version)"
    echo "================================================================"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --scope SCOPE          Assessment scope: 'project' or 'organization' (default: project)"
    echo "  -p, --project PROJECT_ID   Specific project to assess (overrides current gcloud config)"
    echo "  -o, --org ORG_ID          Specific organization ID to assess (required for organization scope)"
    echo "  -f, --format FORMAT       Output format: 'html' or 'text' (default: html)"
    echo "  -v, --verbose             Enable verbose output"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Assess current project"
    echo "  $0 --scope project --project my-proj # Assess specific project" 
    echo "  $0 --scope organization --org 123456 # Assess entire organization"
    echo ""
    echo "Note: Organization scope requires appropriate permissions across all projects in the organization."
}

# Register required permissions for Requirement 11
register_required_permissions "$REQUIREMENT_NUMBER" \
    "compute.instances.list" \
    "compute.firewalls.list" \
    "compute.networks.list" \
    "compute.subnetworks.list" \
    "compute.zones.list" \
    "cloudasset.assets.searchAllResources" \
    "securitycenter.findings.list" \
    "securitycenter.sources.list" \
    "container.clusters.list" \
    "container.nodes.list" \
    "logging.logEntries.list" \
    "monitoring.alertPolicies.list" \
    "resourcemanager.projects.get" \
    "resourcemanager.organizations.get" \
    "iam.serviceAccounts.list" \
    "storage.buckets.list" \
    "pubsub.topics.list" \
    "dns.managedZones.list"

# Setup environment and parse command line arguments
setup_environment "requirement11_assessment.log"
parse_common_arguments "$@"

# Validate GCP environment
validate_prerequisites || exit 1

# Check permissions
if ! check_all_permissions; then
    prompt_continue_limited || exit 1
fi

# Setup assessment scope
setup_assessment_scope "$SCOPE" "$PROJECT_ID" "$ORG_ID"

# Configure HTML report
initialize_report "PCI DSS Requirement $REQUIREMENT_NUMBER Assessment" "$ASSESSMENT_SCOPE"

# Add assessment introduction
add_section "security_testing" "Security Testing Assessment" "Assessment of security testing and monitoring controls"

debug_log "Starting PCI DSS Requirement 11 assessment"

# Core Assessment Functions

# 11.1 - Processes and mechanisms for regularly testing security
assess_security_testing_processes() {
    local project_id="$1"
    debug_log "Assessing security testing processes for project: $project_id"
    
    # 11.1.1 - Security policies and operational procedures documentation
    add_check_result "11.1.1 - Security policies documentation" "MANUAL" \
        "Verify documented security policies for Requirement 11 are maintained, up to date, in use, and known to affected parties"
    
    # 11.1.2 - Roles and responsibilities documentation
    add_check_result "11.1.2 - Roles and responsibilities" "MANUAL" \
        "Verify roles and responsibilities for Requirement 11 activities are documented, assigned, and understood"
    
    # Check for Security Command Center as automated security testing
    local scc_sources
    scc_sources=$(gcloud scc sources list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --format="value(displayName)" \
        2>/dev/null)
    
    if [[ -n "$scc_sources" ]]; then
        local source_count=$(echo "$scc_sources" | wc -l)
        add_check_result "Security Command Center sources" "PASS" \
            "Found $source_count Security Command Center sources providing automated security testing"
    else
        add_check_result "Security Command Center sources" "WARN" \
            "No Security Command Center sources found - consider enabling for automated security testing"
    fi
    
    # Check for ongoing security monitoring
    local security_findings
    security_findings=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND state:ACTIVE" \
        --limit=10 \
        --format="value(category,severity)" \
        2>/dev/null)
    
    if [[ -n "$security_findings" ]]; then
        local finding_count=$(echo "$security_findings" | wc -l)
        add_check_result "Ongoing security monitoring" "PASS" \
            "Found $finding_count active security findings indicating ongoing monitoring"
    else
        add_check_result "Ongoing security monitoring" "INFO" \
            "No active security findings - environment may be secure or monitoring not configured"
    fi
}

# 11.2 - Wireless access point identification and monitoring
assess_wireless_access_points() {
    local project_id="$1"
    debug_log "Assessing wireless access point controls for project: $project_id"
    
    # In cloud environments, this typically relates to network access controls
    # Check for VPC networks and their security controls
    local vpc_networks
    vpc_networks=$(gcloud compute networks list \
        --project="$project_id" \
        --format="value(name,mode)" \
        2>/dev/null)
    
    if [[ -z "$vpc_networks" ]]; then
        add_check_result "11.2 - Network access controls" "WARN" \
            "No VPC networks found - cannot assess network access controls"
        return
    fi
    
    local total_networks=0
    local custom_networks=0
    
    while IFS= read -r network; do
        [[ -z "$network" ]] && continue
        ((total_networks++))
        
        local network_name=$(echo "$network" | cut -d$'\t' -f1)
        local network_mode=$(echo "$network" | cut -d$'\t' -f2)
        
        if [[ "$network_mode" == "CUSTOM" ]]; then
            ((custom_networks++))
            add_check_result "Network security control" "PASS" \
                "Custom VPC network '$network_name' provides controlled network access"
        else
            add_check_result "Network security control" "WARN" \
                "Auto VPC network '$network_name' may have default access rules"
        fi
        
        # Check firewall rules for each network
        local firewall_rules
        firewall_rules=$(gcloud compute firewall-rules list \
            --project="$project_id" \
            --filter="network:$network_name" \
            --format="value(name,direction,allowed[].ports)" \
            2>/dev/null)
        
        local rule_count=0
        if [[ -n "$firewall_rules" ]]; then
            rule_count=$(echo "$firewall_rules" | wc -l)
        fi
        
        add_check_result "Network firewall rules" "INFO" \
            "Network '$network_name' has $rule_count firewall rules configured"
        
    done <<< "$vpc_networks"
    
    # 11.2.1 - Authorized and unauthorized access point management
    add_check_result "11.2.1 - Access point testing" "MANUAL" \
        "For physical environments: Test for unauthorized wireless access points at least every 3 months"
    
    # 11.2.2 - Inventory of authorized wireless access points
    add_check_result "11.2.2 - Access point inventory" "MANUAL" \
        "Maintain inventory of authorized wireless access points with business justification"
    
    # Cloud-specific wireless assessment
    add_check_result "Cloud network access control" "PASS" \
        "Found $total_networks VPC networks ($custom_networks custom) providing controlled network access equivalent to wireless AP controls"
}

# 11.3 - Vulnerability scanning
assess_vulnerability_scanning() {
    local project_id="$1"
    debug_log "Assessing vulnerability scanning for project: $project_id"
    
    # Check for Security Command Center findings related to vulnerabilities
    local vulnerability_findings
    vulnerability_findings=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND category:VULNERABILITY" \
        --format="value(name,severity,createTime)" \
        2>/dev/null)
    
    if [[ -n "$vulnerability_findings" ]]; then
        local vuln_count=$(echo "$vulnerability_findings" | wc -l)
        add_check_result "Vulnerability detection" "PASS" \
            "Found $vuln_count vulnerability findings - indicates active vulnerability scanning"
        
        # Analyze severity distribution
        local critical_vulns=$(echo "$vulnerability_findings" | grep -c "CRITICAL" || echo 0)
        local high_vulns=$(echo "$vulnerability_findings" | grep -c "HIGH" || echo 0)
        local medium_vulns=$(echo "$vulnerability_findings" | grep -c "MEDIUM" || echo 0)
        
        add_check_result "Vulnerability severity analysis" "INFO" \
            "Vulnerabilities by severity: Critical=$critical_vulns, High=$high_vulns, Medium=$medium_vulns"
        
        if [[ $critical_vulns -gt 0 ]] || [[ $high_vulns -gt 0 ]]; then
            add_check_result "11.3.1 - Critical/High vulnerability resolution" "FAIL" \
                "Found $critical_vulns critical and $high_vulns high severity vulnerabilities requiring immediate attention"
        else
            add_check_result "11.3.1 - Critical/High vulnerability resolution" "PASS" \
                "No critical or high severity vulnerabilities found"
        fi
    else
        add_check_result "11.3.1 - Internal vulnerability scanning" "WARN" \
            "No vulnerability findings found - verify if vulnerability scanning is configured"
    fi
    
    # Check for Container Analysis API (for container vulnerability scanning)
    local container_vulnerabilities
    container_vulnerabilities=$(gcloud container images scan-results list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null | head -5)
    
    if [[ -n "$container_vulnerabilities" ]]; then
        add_check_result "Container vulnerability scanning" "PASS" \
            "Container vulnerability scanning is active"
    else
        add_check_result "Container vulnerability scanning" "INFO" \
            "No container vulnerability scan results found"
    fi
    
    # 11.3.1.1 - Other vulnerability management
    add_check_result "11.3.1.1 - Vulnerability risk management" "MANUAL" \
        "Verify non-critical vulnerabilities are managed per targeted risk analysis"
    
    # 11.3.1.2 - Authenticated scanning
    add_check_result "11.3.1.2 - Authenticated scanning" "MANUAL" \
        "Verify vulnerability scans use authenticated scanning where possible"
    
    # 11.3.1.3 - Scanning after significant changes
    add_check_result "11.3.1.3 - Change-based scanning" "MANUAL" \
        "Verify vulnerability scans are performed after significant infrastructure changes"
    
    # 11.3.2 - External vulnerability scanning
    add_check_result "11.3.2 - External vulnerability scanning" "MANUAL" \
        "Verify external vulnerability scans are performed quarterly by approved scanning vendor (ASV)"
    
    # Check for Web Security Scanner results
    local web_scan_results
    web_scan_results=$(gcloud logging read \
        'protoPayload.serviceName="websecurityscanner.googleapis.com"' \
        --project="$project_id" \
        --limit=5 \
        --format="value(timestamp)" \
        2>/dev/null)
    
    if [[ -n "$web_scan_results" ]]; then
        add_check_result "Web Security Scanner" "PASS" \
            "Web Security Scanner activity detected for web application testing"
    else
        add_check_result "Web Security Scanner" "INFO" \
            "No Web Security Scanner activity found"
    fi
}

# 11.4 - Penetration testing
assess_penetration_testing() {
    local project_id="$1"
    debug_log "Assessing penetration testing for project: $project_id"
    
    # 11.4.1 - Penetration testing methodology
    add_check_result "11.4.1 - Penetration testing methodology" "MANUAL" \
        "Verify penetration testing methodology is defined, documented, and implemented with industry-accepted approaches"
    
    # 11.4.2 - Internal penetration testing
    add_check_result "11.4.2 - Internal penetration testing" "MANUAL" \
        "Verify internal penetration testing is performed at least annually and after significant changes"
    
    # 11.4.3 - External penetration testing
    add_check_result "11.4.3 - External penetration testing" "MANUAL" \
        "Verify external penetration testing is performed at least annually and after significant changes"
    
    # 11.4.4 - Penetration testing remediation
    add_check_result "11.4.4 - Penetration testing remediation" "MANUAL" \
        "Verify exploitable vulnerabilities found in penetration testing are corrected and retested"
    
    # 11.4.5 - Segmentation testing
    add_check_result "11.4.5 - Segmentation testing" "MANUAL" \
        "If segmentation is used, verify penetration tests validate segmentation controls annually"
    
    # Check for evidence of security testing activities in audit logs
    local security_testing_logs
    security_testing_logs=$(gcloud logging read \
        'protoPayload.methodName:"test" OR protoPayload.methodName:"scan" OR labels.security_testing=true' \
        --project="$project_id" \
        --limit=10 \
        --format="value(timestamp,protoPayload.methodName)" \
        2>/dev/null)
    
    if [[ -n "$security_testing_logs" ]]; then
        local test_count=$(echo "$security_testing_logs" | wc -l)
        add_check_result "Security testing activity" "PASS" \
            "Found $test_count security testing activities in audit logs"
    else
        add_check_result "Security testing activity" "INFO" \
            "No security testing activities found in recent audit logs"
    fi
    
    # Check for penetration testing service accounts or specific IAM roles
    local testing_accounts
    testing_accounts=$(gcloud iam service-accounts list \
        --project="$project_id" \
        --filter="email:*test* OR email:*scan* OR email:*security*" \
        --format="value(email)" \
        2>/dev/null)
    
    if [[ -n "$testing_accounts" ]]; then
        add_check_result "Security testing accounts" "PASS" \
            "Found service accounts that may be used for security testing"
    else
        add_check_result "Security testing accounts" "INFO" \
            "No dedicated security testing service accounts found"
    fi
}

# 11.5 - Network intrusion detection and file integrity monitoring
assess_intrusion_detection() {
    local project_id="$1"
    debug_log "Assessing intrusion detection and file integrity monitoring for project: $project_id"
    
    # Check for Cloud IDS (Intrusion Detection System)
    local ids_instances
    ids_instances=$(gcloud ids endpoints list \
        --project="$project_id" \
        --format="value(name,state)" \
        2>/dev/null)
    
    if [[ -n "$ids_instances" ]]; then
        local active_ids=0
        local total_ids=0
        
        while IFS= read -r ids; do
            [[ -z "$ids" ]] && continue
            ((total_ids++))
            
            local ids_name=$(echo "$ids" | cut -d$'\t' -f1)
            local ids_state=$(echo "$ids" | cut -d$'\t' -f2)
            
            if [[ "$ids_state" == "READY" ]]; then
                ((active_ids++))
                add_check_result "Cloud IDS endpoint" "PASS" \
                    "Cloud IDS endpoint '$ids_name' is active and monitoring"
            else
                add_check_result "Cloud IDS endpoint" "WARN" \
                    "Cloud IDS endpoint '$ids_name' is in state: $ids_state"
            fi
            
        done <<< "$ids_instances"
        
        add_check_result "11.5.1 - Intrusion detection system" "PASS" \
            "Found $active_ids active out of $total_ids Cloud IDS endpoints"
    else
        add_check_result "11.5.1 - Intrusion detection system" "WARN" \
            "No Cloud IDS endpoints found - consider implementing network intrusion detection"
    fi
    
    # Check for VPC Flow Logs (network monitoring)
    local vpc_networks
    vpc_networks=$(gcloud compute networks list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$vpc_networks" ]]; then
        local networks_with_flow_logs=0
        local total_networks=0
        
        while IFS= read -r network; do
            [[ -z "$network" ]] && continue
            ((total_networks++))
            
            # Check subnets for flow logs
            local subnets_with_logs
            subnets_with_logs=$(gcloud compute networks subnets list \
                --network="$network" \
                --project="$project_id" \
                --filter="enableFlowLogs=true" \
                --format="value(name)" \
                2>/dev/null)
            
            if [[ -n "$subnets_with_logs" ]]; then
                ((networks_with_flow_logs++))
                add_check_result "VPC Flow Logs" "PASS" \
                    "Network '$network' has flow logs enabled for traffic monitoring"
            else
                add_check_result "VPC Flow Logs" "WARN" \
                    "Network '$network' does not have flow logs enabled"
            fi
            
        done <<< "$vpc_networks"
        
        add_check_result "Network traffic monitoring" "INFO" \
            "$networks_with_flow_logs out of $total_networks networks have flow logs enabled"
    fi
    
    # 11.5.2 - File integrity monitoring
    # Check for Cloud Asset Inventory changes (equivalent to file integrity monitoring)
    local asset_changes
    asset_changes=$(gcloud logging read \
        'protoPayload.serviceName="cloudasset.googleapis.com"' \
        --project="$project_id" \
        --limit=10 \
        --format="value(timestamp,protoPayload.methodName)" \
        2>/dev/null)
    
    if [[ -n "$asset_changes" ]]; then
        add_check_result "11.5.2 - Asset change monitoring" "PASS" \
            "Cloud Asset Inventory is tracking resource changes (equivalent to file integrity monitoring)"
    else
        add_check_result "11.5.2 - Asset change monitoring" "WARN" \
            "No recent asset change monitoring activity found"
    fi
    
    # Check for Cloud Security Command Center for threat detection
    local threat_detection
    threat_detection=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND category:THREAT_DETECTION" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$threat_detection" ]]; then
        local threat_count=$(echo "$threat_detection" | wc -l)
        add_check_result "Threat detection monitoring" "PASS" \
            "Security Command Center detected $threat_count threat detection events"
    else
        add_check_result "Threat detection monitoring" "INFO" \
            "No threat detection events found in Security Command Center"
    fi
    
    # Check for binary authorization (integrity control for containers)
    local binary_auth_policy
    binary_auth_policy=$(gcloud container binauthz policy import \
        --project="$project_id" \
        --dry-run \
        2>/dev/null && echo "configured" || echo "not_configured")
    
    if [[ "$binary_auth_policy" == "configured" ]]; then
        add_check_result "Binary Authorization" "PASS" \
            "Binary Authorization is configured for container integrity verification"
    else
        add_check_result "Binary Authorization" "INFO" \
            "Binary Authorization not configured - consider for container environments"
    fi
}

# 11.6 - Payment page change detection
assess_payment_page_monitoring() {
    local project_id="$1"
    debug_log "Assessing payment page change detection for project: $project_id"
    
    # Check for App Engine applications (web applications)
    local app_engine_apps
    app_engine_apps=$(gcloud app describe \
        --project="$project_id" \
        --format="value(id)" \
        2>/dev/null)
    
    if [[ -n "$app_engine_apps" ]]; then
        add_check_result "Web application platform" "INFO" \
            "App Engine application found - ensure payment page monitoring is implemented"
        
        # Check for Cloud CDN (might indicate web application)
        local cdn_backends
        cdn_backends=$(gcloud compute backend-services list \
            --project="$project_id" \
            --filter="cdnPolicy.cacheKeyPolicy.includeHost=true" \
            --format="value(name)" \
            2>/dev/null)
        
        if [[ -n "$cdn_backends" ]]; then
            add_check_result "CDN configuration" "INFO" \
                "Cloud CDN detected - ensure payment page change monitoring covers CDN content"
        fi
    fi
    
    # Check for Cloud Load Balancer (indicating web applications)
    local load_balancers
    load_balancers=$(gcloud compute url-maps list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$load_balancers" ]]; then
        local lb_count=$(echo "$load_balancers" | wc -l)
        add_check_result "Load balancer configuration" "INFO" \
            "Found $lb_count load balancers - ensure payment page monitoring covers all endpoints"
    fi
    
    # 11.6.1 - Change and tamper detection mechanism
    add_check_result "11.6.1 - Payment page change detection" "MANUAL" \
        "Verify change and tamper detection mechanism is deployed for payment pages"
    
    # Check for Cloud Functions that might handle payment processing
    local payment_functions
    payment_functions=$(gcloud functions list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null | grep -i -E "(payment|checkout|billing)")
    
    if [[ -n "$payment_functions" ]]; then
        add_check_result "Payment processing functions" "INFO" \
            "Found Cloud Functions that may handle payment processing - ensure monitoring is configured"
    fi
    
    # Check for Cloud Run services (modern web applications)
    local cloud_run_services
    cloud_run_services=$(gcloud run services list \
        --project="$project_id" \
        --format="value(metadata.name)" \
        2>/dev/null)
    
    if [[ -n "$cloud_run_services" ]]; then
        local service_count=$(echo "$cloud_run_services" | wc -l)
        add_check_result "Cloud Run services" "INFO" \
            "Found $service_count Cloud Run services - ensure payment page monitoring if applicable"
    fi
    
    # Manual verification guidance for payment page monitoring
    add_check_result "Payment page monitoring implementation" "MANUAL" \
        "If processing payments: Implement monitoring for HTTP headers and script contents of payment pages"
    
    add_check_result "Payment page monitoring frequency" "MANUAL" \
        "Verify payment page monitoring performs evaluations at least weekly or per risk analysis"
}

# Assessment for cloud-specific security testing
assess_cloud_security_testing() {
    local project_id="$1"
    debug_log "Assessing cloud-specific security testing for project: $project_id"
    
    # Check for Cloud Security Scanner
    local security_scanner_logs
    security_scanner_logs=$(gcloud logging read \
        'protoPayload.serviceName="websecurityscanner.googleapis.com"' \
        --project="$project_id" \
        --limit=5 \
        --format="value(timestamp,protoPayload.methodName)" \
        2>/dev/null)
    
    if [[ -n "$security_scanner_logs" ]]; then
        add_check_result "Cloud Security Scanner" "PASS" \
            "Web Security Scanner is being used for automated security testing"
    else
        add_check_result "Cloud Security Scanner" "INFO" \
            "No Web Security Scanner activity found - consider for web application testing"
    fi
    
    # Check for Event Threat Detection
    local etd_findings
    etd_findings=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND source.displayName:Event" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$etd_findings" ]]; then
        add_check_result "Event Threat Detection" "PASS" \
            "Event Threat Detection is active and generating findings"
    else
        add_check_result "Event Threat Detection" "INFO" \
            "No Event Threat Detection findings found"
    fi
    
    # Check for Container Threat Detection
    local container_threats
    container_threats=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND category:MALWARE" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$container_threats" ]]; then
        add_check_result "Container Threat Detection" "PASS" \
            "Container threat detection is identifying potential threats"
    else
        add_check_result "Container Threat Detection" "INFO" \
            "No container threat findings found"
    fi
    
    # Check for VM threat detection
    local vm_threats
    vm_threats=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND category:ANOMALOUS_ACTIVITY" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$vm_threats" ]]; then
        add_check_result "VM Threat Detection" "PASS" \
            "VM threat detection is identifying anomalous activities"
    else
        add_check_result "VM Threat Detection" "INFO" \
            "No VM threat detection findings found"
    fi
}

# Manual verification guidance
add_manual_verification_guidance() {
    debug_log "Adding manual verification guidance"
    
    add_section "manual_verification" "Manual Verification Required" "Security testing controls requiring manual assessment"
    
    add_check_result "11.1 - Security testing policy" "MANUAL" \
        "Verify documented processes for regularly testing security of systems and networks"
    
    add_check_result "11.2 - Wireless access point testing" "MANUAL" \
        "For physical environments: Test for unauthorized wireless access points quarterly"
    
    add_check_result "11.3 - Vulnerability scanning schedule" "MANUAL" \
        "Verify internal vulnerability scans are performed at least quarterly"
    
    add_check_result "11.4 - Penetration testing program" "MANUAL" \
        "Verify penetration testing is performed annually and after significant changes"
    
    add_check_result "11.5 - IDS/IPS implementation" "MANUAL" \
        "Verify intrusion detection/prevention systems monitor network perimeter and critical points"
    
    add_check_result "11.6 - Payment page monitoring" "MANUAL" \
        "If processing payments: Verify change detection for payment pages is implemented"
    
    add_check_result "Testing independence" "MANUAL" \
        "Verify organizational independence of security testers from system administrators"
    
    add_check_result "Test result documentation" "MANUAL" \
        "Verify security testing results and remediation activities are documented and retained"
}

# Main assessment function
assess_project() {
    local project_id="$1"
    
    info_log "Assessing project: $project_id"
    
    # Add project section to report
    add_section "project_$project_id" "Project: $project_id" "Assessment results for project $project_id"
    
    # Perform assessments
    assess_security_testing_processes "$project_id"
    assess_wireless_access_points "$project_id"
    assess_vulnerability_scanning "$project_id"
    assess_penetration_testing "$project_id"
    assess_intrusion_detection "$project_id"
    assess_payment_page_monitoring "$project_id"
    assess_cloud_security_testing "$project_id"
    
    debug_log "Completed assessment for project: $project_id"
}

# Main execution
main() {
    info_log "Starting PCI DSS Requirement 11 assessment"
    
    # Initialize scope management and enumerate projects
    local projects
    projects=$(get_projects_in_scope)
    
    local project_count=0
    while IFS= read -r project_data; do
        [[ -z "$project_data" ]] && continue
        
        # Setup project context using scope management
        assess_project "$project_data"
        ((project_count++))
        
    done <<< "$projects"
    
    # Add manual verification guidance
    add_manual_verification_guidance
    
    # Generate final report
    local output_file="pci_requirement11_assessment_$(date +%Y%m%d_%H%M%S).html"
    finalize_report "$output_file" "$REQUIREMENT_NUMBER"
    
    success_log "Assessment complete! Report saved to: $output_file"
    success_log "Projects assessed: $project_count"
    
    return 0
}

# Execute main function
main "$@"