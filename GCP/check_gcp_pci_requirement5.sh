#!/usr/bin/env bash
#
# PCI DSS v4.0 Compliance Assessment Script for Requirement 5 (GCP)
# Protect all systems against malware and regularly update anti-malware software or programs
#

# Variables
REQUIREMENT_NUMBER="5"
SCRIPT_DIR="$(dirname "$0")"
REPORT_DIR="$SCRIPT_DIR/reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="$REPORT_DIR/pci_req${REQUIREMENT_NUMBER}_gcp_report_${TIMESTAMP}.html"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report (GCP)"

# Initialize counters
total_checks=0
passed_checks=0
failed_checks=0
warning_checks=0

# Source the HTML report library (use the one from AWS directory if available)
if [ -f "$SCRIPT_DIR/../AWS/pci_html_report_lib.sh" ]; then
    source "$SCRIPT_DIR/../AWS/pci_html_report_lib.sh" || {
        echo "Error: Required library file pci_html_report_lib.sh not found."
        exit 1
    }
else
    echo "Error: HTML report library not found. Please ensure pci_html_report_lib.sh is available."
    exit 1
fi

# Function to validate gcloud CLI is installed and configured
validate_gcloud_cli() {
    which gcloud > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: gcloud CLI is not installed or not in PATH. Please install gcloud CLI."
        exit 1
    fi
    
    gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -1 > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: gcloud CLI is not authenticated. Please run 'gcloud auth login'."
        exit 1
    fi
    
    # Check current project
    PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
    if [ -z "$PROJECT_ID" ]; then
        echo "Error: No GCP project configured. Please run 'gcloud config set project PROJECT_ID'."
        exit 1
    fi
    
    echo "Using GCP project: $PROJECT_ID"
}

# Function to check if a gcloud command is available
check_gcloud_command_access() {
    local output_file="$1"
    local service="$2"
    local command="$3"
    
    echo "Checking access to gcloud $service $command..."
    
    # Test basic access to the service
    gcloud $service --help > /dev/null 2>&1
    local service_available=$?
    
    if [ $service_available -ne 0 ]; then
        add_check_item "$output_file" "warning" "GCloud Service Not Available" \
            "<p>The gcloud service <code>$service</code> is not available. This may indicate missing APIs or permissions.</p>" \
            "Enable the required GCP APIs and ensure proper permissions."
        ((warning_checks++))
        ((total_checks++))
        return 1
    fi
    
    return 0
}

# Function to check Compute Engine instances for anti-malware protection
check_gce_antimalware() {
    local details=""
    local found_unprotected=false
    
    details+="<p>Analysis of Compute Engine instances for anti-malware protection:</p>"
    
    # Get all Compute Engine instances across all zones
    instance_list=$(gcloud compute instances list --format="value(name,zone,status)" 2>/dev/null)
    
    if [ -z "$instance_list" ]; then
        details+="<p>No Compute Engine instances found in project $PROJECT_ID.</p>"
        echo "$details"
        return
    fi
    
    details+="<ul>"
    
    while IFS=$'\t' read -r instance_name zone status; do
        # Skip terminated instances
        if [ "$status" == "TERMINATED" ]; then
            continue
        fi
        
        # Get instance metadata for anti-malware information
        metadata=$(gcloud compute instances describe "$instance_name" --zone="$zone" --format="value(metadata.items)" 2>/dev/null)
        
        # Check for anti-malware related metadata
        antimalware_found=false
        if echo "$metadata" | grep -i -E "antimalware|anti-malware|antivirus|anti-virus|security-agent" > /dev/null; then
            antimalware_info=$(echo "$metadata" | grep -i -E "antimalware|anti-malware|antivirus|anti-virus|security-agent" | head -1)
            details+="<li class=\"green\">Instance $instance_name (Zone: $zone) - Anti-malware metadata: $antimalware_info</li>"
            antimalware_found=true
        fi
        
        # Check for OS Login which can provide some security features
        os_login=$(gcloud compute instances describe "$instance_name" --zone="$zone" --format="value(metadata.items[enable-oslogin])" 2>/dev/null)
        if [ "$os_login" == "TRUE" ]; then
            details+="<li class=\"green\">Instance $instance_name - OS Login enabled (provides enhanced security)</li>"
        fi
        
        # Check for Shielded VM features
        shielded_config=$(gcloud compute instances describe "$instance_name" --zone="$zone" --format="value(shieldedInstanceConfig)" 2>/dev/null)
        if [ -n "$shielded_config" ]; then
            integrity_monitoring=$(echo "$shielded_config" | grep -o "enableIntegrityMonitoring: true")
            secure_boot=$(echo "$shielded_config" | grep -o "enableSecureBoot: true")
            vtpm=$(echo "$shielded_config" | grep -o "enableVtpm: true")
            
            if [ -n "$integrity_monitoring" ] || [ -n "$secure_boot" ] || [ -n "$vtpm" ]; then
                details+="<li class=\"green\">Instance $instance_name - Shielded VM features enabled (provides malware protection)</li>"
                antimalware_found=true
            fi
        fi
        
        if [ "$antimalware_found" = false ]; then
            details+="<li class=\"red\">Instance $instance_name (Zone: $zone, Status: $status) - No anti-malware configuration detected in metadata or Shielded VM features.</li>"
            found_unprotected=true
        fi
        
    done <<< "$instance_list"
    
    details+="</ul>"
    
    # Check for Security Command Center findings related to malware
    if check_gcloud_command_access "$OUTPUT_FILE" "scc" "findings"; then
        details+="<p>Checking Security Command Center for malware-related findings:</p>"
        
        # Get SCC findings related to malware
        scc_findings=$(gcloud scc findings list --organization=$(gcloud organizations list --format="value(name)" | head -1) --filter="category:MALWARE OR category:VIRUS OR state:ACTIVE" --format="value(name,category)" --limit=10 2>/dev/null)
        
        if [ -z "$scc_findings" ]; then
            details+="<p class=\"green\">No active malware-related findings in Security Command Center.</p>"
        else
            details+="<p class=\"red\">Found malware-related findings in Security Command Center:</p><ul>"
            echo "$scc_findings" | while IFS=$'\t' read -r finding_name category; do
                details+="<li>$finding_name (Category: $category)</li>"
            done
            details+="</ul>"
            found_unprotected=true
        fi
    else
        details+="<p class=\"yellow\">Unable to check Security Command Center due to permission restrictions or organization setup.</p>"
        found_unprotected=true
    fi
    
    # Check for Cloud Security Scanner
    if check_gcloud_command_access "$OUTPUT_FILE" "app" "scan"; then
        details+="<p>Checking for Cloud Security Scanner usage:</p>"
        
        scan_configs=$(gcloud app scan-configs list --format="value(name)" 2>/dev/null)
        
        if [ -z "$scan_configs" ]; then
            details+="<p class=\"yellow\">No Cloud Security Scanner configurations found. Consider using it for web application vulnerability scanning.</p>"
            found_unprotected=true
        else
            details+="<p class=\"green\">Found Cloud Security Scanner configurations:</p><ul>"
            for config in $scan_configs; do
                details+="<li>$config</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Cloud Security Scanner due to permission restrictions.</p>"
        found_unprotected=true
    fi
    
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
    
    # Check for OS Config patch management
    if check_gcloud_command_access "$OUTPUT_FILE" "compute" "os-config"; then
        # Check for patch policies
        patch_policies=$(gcloud compute os-config patch-policies list --format="value(name)" 2>/dev/null)
        
        if [ -z "$patch_policies" ]; then
            details+="<p class=\"yellow\">No OS Config patch policies found. Consider creating patch policies for regular security updates.</p>"
            found_outdated=true
        else
            details+="<p class=\"green\">Found OS Config patch policies:</p><ul>"
            for policy in $patch_policies; do
                policy_details=$(gcloud compute os-config patch-policies describe "$policy" --format="value(patchConfig.rebootConfig,updateTime)" 2>/dev/null)
                details+="<li>$policy ($policy_details)</li>"
            done
            details+="</ul>"
        fi
        
        # Check for patch deployments
        patch_deployments=$(gcloud compute os-config patch-deployments list --format="value(name,updateTime)" 2>/dev/null)
        
        if [ -z "$patch_deployments" ]; then
            details+="<p class=\"yellow\">No recent patch deployments found. Verify that systems are being updated regularly.</p>"
            found_outdated=true
        else
            details+="<p class=\"green\">Found recent patch deployments:</p><ul>"
            echo "$patch_deployments" | head -5 | while IFS=$'\t' read -r deployment_name update_time; do
                details+="<li>$deployment_name (Last updated: $update_time)</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check OS Config patch management due to permission restrictions.</p>"
        found_outdated=true
    fi
    
    # Check for Cloud Build for automated security updates
    if check_gcloud_command_access "$OUTPUT_FILE" "builds" "list"; then
        security_builds=$(gcloud builds list --filter="substitutions.TAG_NAME~'security' OR substitutions.TAG_NAME~'patch' OR source.repoSource.repoName~'security'" --format="value(id,createTime)" --limit=5 2>/dev/null)
        
        if [ -z "$security_builds" ]; then
            details+="<p class=\"yellow\">No recent security-related Cloud Build jobs found. Consider automating security updates through CI/CD.</p>"
            found_outdated=true
        else
            details+="<p class=\"green\">Found recent security-related build jobs:</p><ul>"
            echo "$security_builds" | while IFS=$'\t' read -r build_id create_time; do
                details+="<li>Build $build_id (Created: $create_time)</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Cloud Build due to permission restrictions.</p>"
        found_outdated=true
    fi
    
    # Check for Container Analysis for vulnerability scanning
    if check_gcloud_command_access "$OUTPUT_FILE" "container" "images"; then
        details+="<p>Checking Container Analysis for vulnerability scanning:</p>"
        
        # Check for container images with vulnerability scans
        images=$(gcloud container images list --format="value(name)" --limit=5 2>/dev/null)
        
        if [ -z "$images" ]; then
            details+="<p>No container images found in Container Registry.</p>"
        else
            details+="<p>Checking vulnerability scans for container images:</p><ul>"
            for image in $images; do
                # Get vulnerability scan results
                vulnerabilities=$(gcloud container images scan "$image" --format="value(vulnerabilities)" 2>/dev/null | grep -c "CRITICAL\|HIGH")
                
                if [ "$vulnerabilities" -gt 0 ]; then
                    details+="<li class=\"red\">$image - $vulnerabilities high/critical vulnerabilities found</li>"
                    found_outdated=true
                else
                    details+="<li class=\"green\">$image - No high/critical vulnerabilities found</li>"
                fi
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Container Analysis due to permission restrictions.</p>"
        found_outdated=true
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
    if check_gcloud_command_access "$OUTPUT_FILE" "scheduler" "jobs"; then
        scan_jobs=$(gcloud scheduler jobs list --format="value(name,schedule)" --filter="name~'scan' OR name~'malware' OR name~'security'" 2>/dev/null)
        
        if [ -z "$scan_jobs" ]; then
            details+="<p class=\"yellow\">No Cloud Scheduler jobs found for malware scanning. Consider implementing scheduled security scans.</p>"
            found_issues=true
        else
            details+="<p class=\"green\">Found scheduled jobs that may include malware scanning:</p><ul>"
            echo "$scan_jobs" | while IFS=$'\t' read -r job_name schedule; do
                details+="<li>$job_name (Schedule: $schedule)</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Cloud Scheduler due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for Cloud Functions that might perform scans
    if check_gcloud_command_access "$OUTPUT_FILE" "functions" "list"; then
        scan_functions=$(gcloud functions list --format="value(name,updateTime)" --filter="name~'scan' OR name~'malware' OR name~'security'" 2>/dev/null)
        
        if [ -z "$scan_functions" ]; then
            details+="<p class=\"yellow\">No Cloud Functions found that appear to perform security scanning.</p>"
            found_issues=true
        else
            details+="<p class=\"green\">Found Cloud Functions that may perform security scanning:</p><ul>"
            echo "$scan_functions" | while IFS=$'\t' read -r function_name update_time; do
                details+="<li>$function_name (Last updated: $update_time)</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Cloud Functions due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for Cloud Security Scanner scan runs
    if check_gcloud_command_access "$OUTPUT_FILE" "app" "scan-results"; then
        recent_scans=$(gcloud app scan-results list --format="value(name,endTime)" --limit=5 2>/dev/null)
        
        if [ -z "$recent_scans" ]; then
            details+="<p class=\"yellow\">No recent Cloud Security Scanner results found. Consider enabling regular web application scans.</p>"
            found_issues=true
        else
            details+="<p class=\"green\">Found recent Cloud Security Scanner results:</p><ul>"
            echo "$recent_scans" | while IFS=$'\t' read -r scan_name end_time; do
                details+="<li>$scan_name (Completed: $end_time)</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Cloud Security Scanner results due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for Event Arc triggers that might be used for security automation
    if check_gcloud_command_access "$OUTPUT_FILE" "eventarc" "triggers"; then
        security_triggers=$(gcloud eventarc triggers list --format="value(name,eventFilters)" --filter="name~'security' OR name~'scan' OR name~'malware'" 2>/dev/null)
        
        if [ -z "$security_triggers" ]; then
            details+="<p class=\"yellow\">No Eventarc triggers found for security automation. Consider implementing event-driven security scans.</p>"
            found_issues=true
        else
            details+="<p class=\"green\">Found Eventarc triggers for security automation:</p><ul>"
            echo "$security_triggers" | while IFS=$'\t' read -r trigger_name event_filters; do
                details+="<li>$trigger_name (Events: $event_filters)</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Eventarc triggers due to permission restrictions.</p>"
        found_issues=true
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
    if check_gcloud_command_access "$OUTPUT_FILE" "compute" "security-policies"; then
        security_policies=$(gcloud compute security-policies list --format="value(name,description)" 2>/dev/null)
        
        if [ -z "$security_policies" ]; then
            details+="<p class=\"yellow\">No Cloud Armor security policies found. Cloud Armor can provide protection against malicious traffic.</p>"
            found_issues=true
        else
            details+="<p class=\"green\">Found Cloud Armor security policies:</p><ul>"
            echo "$security_policies" | while IFS=$'\t' read -r policy_name description; do
                details+="<li>$policy_name ($description)</li>"
                
                # Check for specific rules that might relate to malware protection
                rules=$(gcloud compute security-policies describe "$policy_name" --format="value(rules[].description)" 2>/dev/null)
                
                security_rules=""
                for rule in $rules; do
                    if echo "$rule" | grep -i -E "malware|virus|security|threat|block" > /dev/null; then
                        security_rules+="$rule, "
                    fi
                done
                
                if [ -n "$security_rules" ]; then
                    details+="<ul><li class=\"green\">Security-related rules: ${security_rules%, }</li></ul>"
                else
                    details+="<ul><li class=\"yellow\">No obvious security-related rules detected.</li></ul>"
                    found_issues=true
                fi
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Cloud Armor security policies due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for VPC firewall rules
    if check_gcloud_command_access "$OUTPUT_FILE" "compute" "firewall-rules"; then
        firewall_rules=$(gcloud compute firewall-rules list --format="value(name,direction,allowed[].map().firewall_rule().list():label=ALLOW_RULES)" --filter="disabled:false" 2>/dev/null)
        
        details+="<p>Analyzing VPC firewall rules for boundary protection:</p>"
        
        # Count rules and look for restrictive patterns
        rule_count=$(echo "$firewall_rules" | wc -l)
        
        if [ "$rule_count" -lt 5 ]; then
            details+="<p class=\"red\">Very few firewall rules found ($rule_count). Ensure proper network boundary controls are in place.</p>"
            found_issues=true
        else
            details+="<p class=\"green\">Found $rule_count firewall rules configured for network boundary protection.</p>"
            
            # Check for overly permissive rules
            permissive_rules=$(echo "$firewall_rules" | grep -c "0.0.0.0/0")
            
            if [ "$permissive_rules" -gt 3 ]; then
                details+="<p class=\"yellow\">Warning: $permissive_rules rules allow traffic from 0.0.0.0/0. Review for security implications.</p>"
                found_issues=true
            else
                details+="<p class=\"green\">Firewall rules appear to follow principle of least privilege.</p>"
            fi
        fi
    else
        details+="<p class=\"yellow\">Unable to check VPC firewall rules due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for Cloud Load Balancing with security features
    if check_gcloud_command_access "$OUTPUT_FILE" "compute" "backend-services"; then
        backend_services=$(gcloud compute backend-services list --format="value(name,securityPolicy)" 2>/dev/null)
        
        if [ -z "$backend_services" ]; then
            details+="<p>No backend services found with load balancing.</p>"
        else
            details+="<p>Checking load balancer security configurations:</p><ul>"
            echo "$backend_services" | while IFS=$'\t' read -r service_name security_policy; do
                if [ -n "$security_policy" ]; then
                    details+="<li class=\"green\">$service_name has security policy: $security_policy</li>"
                else
                    details+="<li class=\"yellow\">$service_name has no security policy attached</li>"
                    found_issues=true
                fi
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check load balancer configurations due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for Cloud DNS security features
    if check_gcloud_command_access "$OUTPUT_FILE" "dns" "policies"; then
        dns_policies=$(gcloud dns policies list --format="value(name,description)" 2>/dev/null)
        
        if [ -z "$dns_policies" ]; then
            details+="<p class=\"yellow\">No Cloud DNS security policies found. DNS policies can help block malicious domains.</p>"
            found_issues=true
        else
            details+="<p class=\"green\">Found Cloud DNS security policies:</p><ul>"
            echo "$dns_policies" | while IFS=$'\t' read -r policy_name description; do
                details+="<li>$policy_name ($description)</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Cloud DNS policies due to permission restrictions.</p>"
        found_issues=true
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check anti-phishing mechanisms
check_antiphishing_protection() {
    local details=""
    local found_issues=false
    
    details+="<p>Checking for anti-phishing mechanisms in GCP:</p>"
    
    # Check for Gmail Advanced Protection (if using Google Workspace)
    details+="<p class=\"yellow\">Note: Anti-phishing protection is primarily handled through Google Workspace security settings, which are not directly accessible via gcloud CLI.</p>"
    
    # Check for Cloud Identity & Access Management policies that might help with phishing
    if check_gcloud_command_access "$OUTPUT_FILE" "iam" "policies"; then
        # Check for MFA enforcement which helps against phishing
        conditional_access=$(gcloud iam policies list --format="value(name)" --filter="bindings.condition" 2>/dev/null)
        
        if [ -z "$conditional_access" ]; then
            details+="<p class=\"yellow\">No conditional IAM policies found. Consider implementing conditional access based on device/location to prevent phishing attacks.</p>"
            found_issues=true
        else
            details+="<p class=\"green\">Found conditional IAM policies that may help prevent phishing:</p><ul>"
            for policy in $conditional_access; do
                details+="<li>$policy</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check IAM policies due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for Security Keys enforcement
    details+="<p class=\"info\">Recommendations for anti-phishing protection:</p><ul>"
    details+="<li>Enable Advanced Protection Program for high-risk users</li>"
    details+="<li>Require Security Keys (FIDO2) for authentication</li>"
    details+="<li>Configure Gmail security settings to block suspicious emails</li>"
    details+="<li>Implement Safe Browsing in Chrome Browser</li>"
    details+="<li>Use Cloud Security Command Center for threat detection</li>"
    details+="</ul>"
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Main script

# Create report directory if it doesn't exist
mkdir -p "$REPORT_DIR"

# Validate gcloud CLI
validate_gcloud_cli

# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$PROJECT_ID"

# Check gcloud CLI permissions
echo "Checking gcloud CLI permissions..."
add_section "$OUTPUT_FILE" "permissions" "GCloud CLI Permissions Check" "active"
check_gcloud_command_access "$OUTPUT_FILE" "compute" "instances"
check_gcloud_command_access "$OUTPUT_FILE" "compute" "os-config"
check_gcloud_command_access "$OUTPUT_FILE" "scc" "findings"
check_gcloud_command_access "$OUTPUT_FILE" "container" "images"
check_gcloud_command_access "$OUTPUT_FILE" "compute" "security-policies"
close_section "$OUTPUT_FILE"

# Requirement 5.2: Anti-malware mechanisms and processes to protect all systems against malware are defined and implemented
add_section "$OUTPUT_FILE" "req-5.2" "Requirement 5.2: Anti-malware mechanisms and processes to protect all systems against malware are defined and implemented" "active"

# Check 5.2.1 - Anti-malware protection is deployed
echo "Checking for anti-malware protection deployment..."
am_details=$(check_gce_antimalware)
if [[ "$am_details" == *"class=\"red\""* ]]; then
    add_check_item "$OUTPUT_FILE" "fail" "5.2.1 - Anti-malware protection deployment" \
        "$am_details" \
        "Deploy anti-malware software on all systems commonly affected by malware, including servers, workstations, and other applicable systems. Consider using GCP security features like Shielded VMs and Security Command Center."
    ((failed_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "5.2.1 - Anti-malware protection deployment" \
        "$am_details"
    ((passed_checks++))
fi
((total_checks++))

# Check 5.2.2 - Anti-malware mechanisms detect and address malware
echo "Checking anti-malware detection and response mechanisms..."
detection_details="<p>GCP provides several mechanisms for malware detection and response:</p><ul>"
detection_details+="<li>Security Command Center for centralized security findings</li>"
detection_details+="<li>Container Analysis for vulnerability scanning</li>"
detection_details+="<li>Cloud Security Scanner for web application scanning</li>"
detection_details+="<li>Shielded VM integrity monitoring</li>"
detection_details+="</ul>"
detection_details+="<p>Manual verification required: Ensure anti-malware solutions can detect and remove/block/contain all known types of malware.</p>"

add_check_item "$OUTPUT_FILE" "warning" "5.2.2 - Malware detection and response" \
    "$detection_details" \
    "Verify that deployed anti-malware mechanisms can detect and address all known types of malware."
((warning_checks++))
((total_checks++))

close_section "$OUTPUT_FILE"

# Requirement 5.3: Anti-malware mechanisms and processes are active, maintained, and monitored
add_section "$OUTPUT_FILE" "req-5.3" "Requirement 5.3: Anti-malware mechanisms and processes are active, maintained, and monitored" "active"

# Check 5.3.1 - Anti-malware updates
echo "Checking anti-malware update mechanisms..."
update_details=$(check_antimalware_updates)
if [[ "$update_details" == *"class=\"red\""* ]] || [[ "$update_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "5.3.1 - Anti-malware mechanism updates" \
        "$update_details" \
        "Ensure anti-malware mechanisms are kept current via automatic updates. Use OS Config for patch management and Container Analysis for container security."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "5.3.1 - Anti-malware mechanism updates" \
        "$update_details"
    ((passed_checks++))
fi
((total_checks++))

# Check 5.3.2 - Periodic scans and active scanning
echo "Checking for periodic malware scans..."
scan_details=$(check_periodic_scans)
if [[ "$scan_details" == *"class=\"red\""* ]] || [[ "$scan_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "5.3.2 - Periodic scans and active scanning" \
        "$scan_details" \
        "Ensure anti-malware mechanisms perform periodic scans and active or real-time scanning OR perform continuous behavioral analysis of systems or processes."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "5.3.2 - Periodic scans and active scanning" \
        "$scan_details"
    ((passed_checks++))
fi
((total_checks++))

# Check 5.3.3 - Removable media scanning
echo "Checking removable media scanning configuration..."
media_details="<p>GCP Compute Engine instances can be configured to scan removable media:</p><ul>"
media_details+="<li>Implement startup scripts that scan mounted drives</li>"
media_details+="<li>Use Cloud Functions to trigger scans when storage is accessed</li>"
media_details+="<li>Configure OS-level anti-malware to scan mounted volumes</li>"
media_details+="</ul>"
media_details+="<p class=\"yellow\">Manual verification required: Ensure removable electronic media is scanned automatically when inserted, connected, or logically mounted.</p>"

add_check_item "$OUTPUT_FILE" "warning" "5.3.3 - Removable media scanning" \
    "$media_details" \
    "Configure anti-malware to automatically scan removable electronic media when inserted, connected, or logically mounted."
((warning_checks++))
((total_checks++))

# Check 5.3.4 - Audit logs
echo "Checking anti-malware audit logging..."
audit_details="<p>Anti-malware audit logging in GCP:</p><ul>"
audit_details+="<li>Security Command Center maintains logs of security findings</li>"
audit_details+="<li>Cloud Logging can capture anti-malware events from instances</li>"
audit_details+="<li>Container Analysis logs vulnerability scan results</li>"
audit_details+="<li>Cloud Audit Logs track security-related API calls</li>"
audit_details+="</ul>"
audit_details+="<p class=\"yellow\">Manual verification required: Ensure anti-malware audit logs are enabled and retained per Requirement 10.5.1.</p>"

add_check_item "$OUTPUT_FILE" "warning" "5.3.4 - Anti-malware audit logs" \
    "$audit_details" \
    "Enable and retain anti-malware audit logs according to Requirement 10.5.1. Configure Cloud Logging to capture anti-malware events."
((warning_checks++))
((total_checks++))

# Check 5.3.5 - Anti-malware protection from tampering
echo "Checking anti-malware tamper protection..."
tamper_details="<p>Anti-malware tamper protection in GCP:</p><ul>"
tamper_details+="<li>Use IAM policies to restrict access to security configurations</li>"
tamper_details+="<li>Implement Shielded VM features for integrity monitoring</li>"
tamper_details+="<li>Use Organization Policy constraints to enforce security settings</li>"
tamper_details+="<li>Configure OS Login for centralized access control</li>"
tamper_details+="</ul>"
tamper_details+="<p class=\"yellow\">Manual verification required: Ensure anti-malware mechanisms cannot be disabled or altered by users unless specifically authorized.</p>"

add_check_item "$OUTPUT_FILE" "warning" "5.3.5 - Anti-malware tamper protection" \
    "$tamper_details" \
    "Implement controls to prevent users from disabling or altering anti-malware mechanisms unless specifically documented and authorized by management."
((warning_checks++))
((total_checks++))

close_section "$OUTPUT_FILE"

# Requirement 5.4: Anti-phishing mechanisms protect users against phishing attacks
add_section "$OUTPUT_FILE" "req-5.4" "Requirement 5.4: Anti-phishing mechanisms protect users against phishing attacks" "active"

# Check 5.4.1 - Anti-phishing processes and mechanisms
echo "Checking for anti-phishing protection mechanisms..."
phishing_details=$(check_antiphishing_protection)
add_check_item "$OUTPUT_FILE" "warning" "5.4.1 - Anti-phishing protection" \
    "$phishing_details" \
    "Implement processes and automated mechanisms to detect and protect personnel against phishing attacks. Use Google Workspace security features and Security Keys."
((warning_checks++))
((total_checks++))

close_section "$OUTPUT_FILE"

# Check boundary protection mechanisms
add_section "$OUTPUT_FILE" "boundary-protection" "Malware Protection at Network Boundaries" "active"

echo "Checking for anti-malware at network boundaries..."
boundary_details=$(check_boundary_protection)
if [[ "$boundary_details" == *"class=\"red\""* ]]; then
    add_check_item "$OUTPUT_FILE" "fail" "Malware Protection at Network Boundaries" \
        "$boundary_details" \
        "Implement anti-malware mechanisms at network entry and exit points using Cloud Armor, VPC firewall rules, and other security controls."
    ((failed_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "Malware Protection at Network Boundaries" \
        "$boundary_details" \
        "Review and enhance network boundary protections to include anti-malware capabilities."
    ((warning_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# Finalize the report
finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"

# Open the report
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE"
else
    echo -e "\nReport generated: $OUTPUT_FILE"
fi

echo "Assessment completed!"
echo "Total checks: $total_checks"
echo "Passed: $passed_checks"
echo "Failed: $failed_checks"
echo "Warnings (manual verification required): $warning_checks"