#!/bin/bash
#
# PCI DSS 4.0 Requirement 4 Assessment Script for Google Cloud Platform
# This script assesses GCP environments for compliance with PCI DSS 4.0 Requirement 4:
# "Protect Cardholder Data with Strong Cryptography During Transmission Over Open, Public Networks"
#
# Version: 1.0
# Compatible with: Bash 3.2+ on MacOS
# 
# Usage: ./pci_dss_req4_assessment.sh [project_id]
#

# ======== CONFIGURATION ========
REPORT_FILE="pci_dss_req4_report_$(date +%Y%m%d_%H%M%S).html"
TEMP_DIR=$(mktemp -d)
LOG_FILE="${TEMP_DIR}/assessment_log.txt"
FINDINGS_FILE="${TEMP_DIR}/findings.json"
SUMMARY_FILE="${TEMP_DIR}/summary.json"

# Initialize findings and summary files
echo "[]" > "${FINDINGS_FILE}"
echo '{"critical": 0, "warning": 0, "pass": 0, "info": 0}' > "${SUMMARY_FILE}"

# ======== UTILITY FUNCTIONS ========

# Log messages to console and log file
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Format based on level
    case "${level}" in
        "INFO")
            echo -e "\033[0;34m[${timestamp}] [INFO] ${message}\033[0m"
            ;;
        "WARNING")
            echo -e "\033[0;33m[${timestamp}] [WARNING] ${message}\033[0m"
            ;;
        "ERROR")
            echo -e "\033[0;31m[${timestamp}] [ERROR] ${message}\033[0m"
            ;;
        "SUCCESS")
            echo -e "\033[0;32m[${timestamp}] [SUCCESS] ${message}\033[0m"
            ;;
        *)
            echo -e "[${timestamp}] [${level}] ${message}"
            ;;
    esac
    
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if jq is installed
check_jq() {
    if ! command_exists jq; then
        log "ERROR" "jq is not installed. Please install jq to continue."
        log "INFO" "On MacOS, you can install jq using: brew install jq"
        exit 1
    fi
}

# Check if gcloud is installed and configured
check_gcloud() {
    if ! command_exists gcloud; then
        log "ERROR" "gcloud CLI is not installed. Please install the Google Cloud SDK to continue."
        log "INFO" "Visit https://cloud.google.com/sdk/docs/install for installation instructions."
        exit 1
    fi
}

# Validate JSON before processing
validate_json() {
    local json_file="$1"
    local default="${2:-[]}"
    
    if [[ ! -f "${json_file}" ]]; then
        echo "${default}"
        return 1
    fi
    
    # Check if file is empty
    if [[ ! -s "${json_file}" ]]; then
        echo "${default}"
        return 1
    fi
    
    # Validate JSON
    if ! jq empty "${json_file}" 2>/dev/null; then
        log "WARNING" "Invalid JSON in ${json_file}, using default value"
        echo "${default}"
        return 1
    fi
    
    cat "${json_file}"
    return 0
}

# Safe JSON extraction with type checking
safe_json_extract() {
    local json="$1"
    local query="$2"
    local default="${3:-}"
    
    # Use echo to handle potential empty input
    result=$(echo "${json}" | jq -r "${query}" 2>/dev/null || echo "${default}")
    
    # Check if result is null or empty
    if [[ "${result}" == "null" || -z "${result}" ]]; then
        echo "${default}"
    else
        echo "${result}"
    fi
}

# Add a finding to the findings file
add_finding() {
    local severity="$1"
    local requirement="$2"
    local title="$3"
    local description="$4"
    local resource_id="$5"
    local recommendation="$6"
    
    # Update summary count
    local current_count=$(jq -r ".${severity,,}" "${SUMMARY_FILE}")
    jq --arg severity "${severity,,}" --argjson count "$((current_count + 1))" '.[$severity] = $count' "${SUMMARY_FILE}" > "${SUMMARY_FILE}.tmp" && mv "${SUMMARY_FILE}.tmp" "${SUMMARY_FILE}"
    
    # Create finding JSON
    local finding=$(jq -n \
        --arg severity "${severity}" \
        --arg requirement "${requirement}" \
        --arg title "${title}" \
        --arg description "${description}" \
        --arg resource_id "${resource_id}" \
        --arg recommendation "${recommendation}" \
        --arg timestamp "$(date +"%Y-%m-%d %H:%M:%S")" \
        '{severity: $severity, requirement: $requirement, title: $title, description: $description, resource_id: $resource_id, recommendation: $recommendation, timestamp: $timestamp}')
    
    # Append to findings file
    jq --argjson finding "${finding}" '. += [$finding]' "${FINDINGS_FILE}" > "${FINDINGS_FILE}.tmp" && mv "${FINDINGS_FILE}.tmp" "${FINDINGS_FILE}"
    
    # Log the finding
    log "${severity}" "${title} - ${resource_id}"
}

# Clean up temporary files
cleanup() {
    log "INFO" "Cleaning up temporary files..."
    rm -rf "${TEMP_DIR}"
}

# Handle script interruption
handle_interrupt() {
    log "WARNING" "Script interrupted. Cleaning up..."
    cleanup
    exit 1
}

# ======== GCP AUTHENTICATION AND VALIDATION ========

# Verify GCP authentication
verify_gcp_auth() {
    log "INFO" "Verifying GCP authentication..."
    
    # Check if user is authenticated
    local auth_status=$(gcloud auth list --format="json" 2>/dev/null)
    if [[ $? -ne 0 || -z "${auth_status}" ]]; then
        log "ERROR" "Not authenticated with GCP. Please run 'gcloud auth login' first."
        exit 1
    fi
    
    # Check if there's an active account
    local active_account=$(echo "${auth_status}" | jq -r '.[] | select(.status=="ACTIVE") | .account' 2>/dev/null)
    if [[ -z "${active_account}" ]]; then
        log "ERROR" "No active GCP account found. Please run 'gcloud auth login' first."
        exit 1
    fi
    
    log "SUCCESS" "Authenticated as ${active_account}"
    return 0
}

# Verify project access
verify_project_access() {
    local project_id="$1"
    
    log "INFO" "Verifying access to project: ${project_id}"
    
    # Check if project exists and is accessible
    local project_info=$(gcloud projects describe "${project_id}" --format="json" 2>/dev/null)
    if [[ $? -ne 0 || -z "${project_info}" ]]; then
        log "ERROR" "Unable to access project ${project_id}. Please check if the project exists and you have sufficient permissions."
        exit 1
    fi
    
    # Extract project name
    local project_name=$(echo "${project_info}" | jq -r '.name // "Unknown"' 2>/dev/null)
    
    log "SUCCESS" "Successfully accessed project: ${project_name} (${project_id})"
    return 0
}

# ======== PCI DSS REQUIREMENT 4 ASSESSMENT FUNCTIONS ========

# Check SSL/TLS configurations for load balancers
check_load_balancer_ssl_config() {
    local project_id="$1"
    local output_file="${TEMP_DIR}/load_balancers.json"
    
    log "INFO" "Checking SSL/TLS configurations for load balancers..."
    
    # Get all SSL certificates
    gcloud compute ssl-certificates list --project="${project_id}" --format="json" > "${output_file}" 2>/dev/null
    
    # Validate JSON
    local ssl_certs=$(validate_json "${output_file}")
    
    # Check if we have any SSL certificates
    local cert_count=$(echo "${ssl_certs}" | jq 'length')
    if [[ "${cert_count}" -eq 0 ]]; then
        log "INFO" "No SSL certificates found in project ${project_id}"
        add_finding "INFO" "4.2.1" "No SSL certificates found" \
            "No SSL certificates were found in the project. If this project handles cardholder data, ensure SSL/TLS is properly configured." \
            "project/${project_id}" \
            "If this project processes cardholder data, configure SSL/TLS certificates for secure transmission."
        return
    fi
    
    # Check each certificate
    echo "${ssl_certs}" | jq -c '.[]' 2>/dev/null | while read -r cert; do
        local cert_name=$(echo "${cert}" | jq -r '.name // "Unknown"')
        local cert_type=$(echo "${cert}" | jq -r '.type // "Unknown"')
        local creation_timestamp=$(echo "${cert}" | jq -r '.creationTimestamp // "Unknown"')
        
        # Check for expired certificates (for managed certificates)
        if [[ "${cert_type}" == "MANAGED" ]]; then
            local expire_time=$(echo "${cert}" | jq -r '.managed.expireTime // ""')
            
            if [[ -n "${expire_time}" ]]; then
                # Convert to timestamp for comparison
                local expire_timestamp=$(date -j -f "%Y-%m-%dT%H:%M:%S.%NZ" "${expire_time}" +%s 2>/dev/null)
                local current_timestamp=$(date +%s)
                
                if [[ $? -eq 0 && "${expire_timestamp}" -lt "${current_timestamp}" ]]; then
                    add_finding "CRITICAL" "4.2.1" "Expired SSL certificate" \
                        "SSL certificate ${cert_name} has expired on ${expire_time}." \
                        "ssl-certificate/${cert_name}" \
                        "Renew or replace the expired SSL certificate immediately to maintain secure transmission of cardholder data."
                elif [[ $? -eq 0 ]]; then
                    # Calculate days until expiration
                    local days_until_expiry=$(( (expire_timestamp - current_timestamp) / 86400 ))
                    
                    if [[ "${days_until_expiry}" -lt 30 ]]; then
                        add_finding "WARNING" "4.2.1" "SSL certificate expiring soon" \
                            "SSL certificate ${cert_name} will expire in ${days_until_expiry} days." \
                            "ssl-certificate/${cert_name}" \
                            "Plan to renew the SSL certificate before it expires to prevent interruption in secure transmission."
                    else
                        add_finding "PASS" "4.2.1" "Valid SSL certificate" \
                            "SSL certificate ${cert_name} is valid and not expiring soon." \
                            "ssl-certificate/${cert_name}" \
                            "Continue to monitor certificate expiration dates."
                    fi
                fi
            fi
        fi
    done
    
    # Check HTTPS proxy configurations
    local target_https_proxies_file="${TEMP_DIR}/target_https_proxies.json"
    gcloud compute target-https-proxies list --project="${project_id}" --format="json" > "${target_https_proxies_file}" 2>/dev/null
    
    # Validate JSON
    local target_https_proxies=$(validate_json "${target_https_proxies_file}")
    
    # Check SSL policies for each HTTPS proxy
    echo "${target_https_proxies}" | jq -c '.[]' 2>/dev/null | while read -r proxy; do
        local proxy_name=$(echo "${proxy}" | jq -r '.name // "Unknown"')
        local ssl_policy_link=$(echo "${proxy}" | jq -r '.sslPolicy // ""')
        
        if [[ -z "${ssl_policy_link}" ]]; then
            add_finding "WARNING" "4.2.1" "HTTPS proxy without SSL policy" \
                "HTTPS proxy ${proxy_name} does not have an SSL policy configured." \
                "target-https-proxy/${proxy_name}" \
                "Configure an SSL policy that enforces strong TLS versions (TLS 1.2+) and secure cipher suites."
        else
            # Extract SSL policy name from the URL
            local ssl_policy_name=$(echo "${ssl_policy_link}" | sed -n 's/.*\/sslPolicies\/\([^\/]*\).*/\1/p')
            
            # Get SSL policy details
            local ssl_policy_file="${TEMP_DIR}/ssl_policy_${ssl_policy_name}.json"
            gcloud compute ssl-policies describe "${ssl_policy_name}" --project="${project_id}" --format="json" > "${ssl_policy_file}" 2>/dev/null
            
            # Validate JSON
            local ssl_policy=$(validate_json "${ssl_policy_file}" "{}")
            
            # Check minimum TLS version
            local min_tls_version=$(echo "${ssl_policy}" | jq -r '.minTlsVersion // "Unknown"')
            
            if [[ "${min_tls_version}" == "TLS_1_0" || "${min_tls_version}" == "TLS_1_1" ]]; then
                add_finding "CRITICAL" "4.2.1" "Insecure TLS version" \
                    "SSL policy ${ssl_policy_name} used by ${proxy_name} allows insecure TLS version: ${min_tls_version}." \
                    "ssl-policy/${ssl_policy_name}" \
                    "Update the SSL policy to enforce a minimum of TLS 1.2 to comply with PCI DSS 4.0 requirements."
            elif [[ "${min_tls_version}" == "TLS_1_2" || "${min_tls_version}" == "TLS_1_3" ]]; then
                add_finding "PASS" "4.2.1" "Secure TLS version" \
                    "SSL policy ${ssl_policy_name} used by ${proxy_name} enforces secure TLS version: ${min_tls_version}." \
                    "ssl-policy/${ssl_policy_name}" \
                    "Continue to monitor for new TLS vulnerabilities and update as needed."
            fi
            
            # Check profile (predefined or custom)
            local profile=$(echo "${ssl_policy}" | jq -r '.profile // "Unknown"')
            
            if [[ "${profile}" == "COMPATIBLE" ]]; then
                add_finding "WARNING" "4.2.1" "Broad compatibility SSL profile" \
                    "SSL policy ${ssl_policy_name} uses COMPATIBLE profile which may allow weaker cipher suites." \
                    "ssl-policy/${ssl_policy_name}" \
                    "Consider using MODERN or RESTRICTED profile to enforce stronger cipher suites."
            elif [[ "${profile}" == "MODERN" ]]; then
                add_finding "PASS" "4.2.1" "Modern SSL profile" \
                    "SSL policy ${ssl_policy_name} uses MODERN profile which enforces reasonably strong cipher suites." \
                    "ssl-policy/${ssl_policy_name}" \
                    "Consider using RESTRICTED profile for even stronger security if compatible with your clients."
            elif [[ "${profile}" == "RESTRICTED" ]]; then
                add_finding "PASS" "4.2.1" "Restricted SSL profile" \
                    "SSL policy ${ssl_policy_name} uses RESTRICTED profile which enforces the strongest cipher suites." \
                    "ssl-policy/${ssl_policy_name}" \
                    "Continue to monitor for new TLS vulnerabilities and update as needed."
            elif [[ "${profile}" == "CUSTOM" ]]; then
                # For custom profiles, check the enabled cipher suites
                local enabled_features=$(echo "${ssl_policy}" | jq -r '.enabledFeatures // []')
                local weak_ciphers=0
                
                # Check for weak cipher suites
                if echo "${enabled_features}" | jq -e 'contains(["TLS_RSA_WITH_AES_128_GCM_SHA256"])' >/dev/null; then
                    weak_ciphers=$((weak_ciphers + 1))
                fi
                if echo "${enabled_features}" | jq -e 'contains(["TLS_RSA_WITH_AES_256_GCM_SHA384"])' >/dev/null; then
                    weak_ciphers=$((weak_ciphers + 1))
                fi
                if echo "${enabled_features}" | jq -e 'contains(["TLS_RSA_WITH_AES_128_CBC_SHA"])' >/dev/null; then
                    weak_ciphers=$((weak_ciphers + 1))
                fi
                if echo "${enabled_features}" | jq -e 'contains(["TLS_RSA_WITH_AES_256_CBC_SHA"])' >/dev/null; then
                    weak_ciphers=$((weak_ciphers + 1))
                fi
                
                if [[ "${weak_ciphers}" -gt 0 ]]; then
                    add_finding "WARNING" "4.2.1" "Custom SSL profile with weak ciphers" \
                        "SSL policy ${ssl_policy_name} uses CUSTOM profile with ${weak_ciphers} potentially weak cipher suites." \
                        "ssl-policy/${ssl_policy_name}" \
                        "Review and update the custom cipher suite list to remove weak ciphers and ensure only strong cryptography is used."
                else
                    add_finding "PASS" "4.2.1" "Custom SSL profile with strong ciphers" \
                        "SSL policy ${ssl_policy_name} uses CUSTOM profile with strong cipher suites." \
                        "ssl-policy/${ssl_policy_name}" \
                        "Continue to monitor for new TLS vulnerabilities and update as needed."
                fi
            fi
        fi
    done
}

# Check Cloud Storage bucket encryption
check_storage_bucket_encryption() {
    local project_id="$1"
    local output_file="${TEMP_DIR}/storage_buckets.json"
    
    log "INFO" "Checking Cloud Storage bucket encryption..."
    
    # Get all storage buckets
    gcloud storage ls --project="${project_id}" --json > "${output_file}" 2>/dev/null
    
    # Validate JSON
    local buckets=$(validate_json "${output_file}")
    
    # Check if we have any buckets
    local bucket_count=$(echo "${buckets}" | jq 'length')
    if [[ "${bucket_count}" -eq 0 ]]; then
        log "INFO" "No Cloud Storage buckets found in project ${project_id}"
        return
    fi
    
    # Check each bucket
    echo "${buckets}" | jq -c '.[]' 2>/dev/null | while read -r bucket_info; do
        local bucket_name=$(echo "${bucket_info}" | jq -r '.name // "Unknown"')
        
        # Get detailed bucket information
        local bucket_detail_file="${TEMP_DIR}/bucket_${bucket_name}.json"
        gcloud storage buckets describe "gs://${bucket_name}" --format="json" > "${bucket_detail_file}" 2>/dev/null
        
        # Validate JSON
        local bucket_detail=$(validate_json "${bucket_detail_file}" "{}")
        
        # Check encryption configuration
        local encryption_type=$(echo "${bucket_detail}" | jq -r '.encryption.defaultKmsKeyName // "Google-managed"')
        
        if [[ "${encryption_type}" == "Google-managed" ]]; then
            add_finding "INFO" "4.2.1" "Google-managed encryption for Cloud Storage" \
                "Cloud Storage bucket ${bucket_name} uses Google-managed encryption keys." \
                "storage-bucket/${bucket_name}" \
                "Consider using customer-managed encryption keys (CMEK) for stronger control over encryption if this bucket stores or transmits cardholder data."
        else
            add_finding "PASS" "4.2.1" "Customer-managed encryption for Cloud Storage" \
                "Cloud Storage bucket ${bucket_name} uses customer-managed encryption keys: ${encryption_type}." \
                "storage-bucket/${bucket_name}" \
                "Ensure key rotation policies are in place for the customer-managed encryption keys."
        fi
        
        # Check bucket ACLs for public access
        local public_access=false
        
        # Check if bucket has public access
        if echo "${bucket_detail}" | jq -e '.iamConfiguration.publicAccessPrevention != "enforced"' >/dev/null; then
            public_access=true
        fi
        
        if [[ "${public_access}" == "true" ]]; then
            add_finding "WARNING" "4.2.1" "Potential public access to Cloud Storage" \
                "Cloud Storage bucket ${bucket_name} may allow public access. If this bucket transmits or stores cardholder data, this could be a security risk." \
                "storage-bucket/${bucket_name}" \
                "Enable 'Prevent public access' for buckets that may contain or transmit cardholder data."
        fi
    done
}

# Check VPC network security
check_vpc_security() {
    local project_id="$1"
    local output_file="${TEMP_DIR}/networks.json"
    
    log "INFO" "Checking VPC network security..."
    
    # Get all VPC networks
    gcloud compute networks list --project="${project_id}" --format="json" > "${output_file}" 2>/dev/null
    
    # Validate JSON
    local networks=$(validate_json "${output_file}")
    
    # Check if we have any networks
    local network_count=$(echo "${networks}" | jq 'length')
    if [[ "${network_count}" -eq 0 ]]; then
        log "INFO" "No VPC networks found in project ${project_id}"
        return
    fi
    
    # Check each network
    echo "${networks}" | jq -c '.[]' 2>/dev/null | while read -r network; do
        local network_name=$(echo "${network}" | jq -r '.name // "Unknown"')
        
        # Check firewall rules for this network
        local firewall_file="${TEMP_DIR}/firewall_${network_name}.json"
        gcloud compute firewall-rules list --filter="network:${network_name}" --project="${project_id}" --format="json" > "${firewall_file}" 2>/dev/null
        
        # Validate JSON
        local firewall_rules=$(validate_json "${firewall_file}")
        
        # Check for insecure firewall rules
        echo "${firewall_rules}" | jq -c '.[]' 2>/dev/null | while read -r rule; do
            local rule_name=$(echo "${rule}" | jq -r '.name // "Unknown"')
            local direction=$(echo "${rule}" | jq -r '.direction // "INGRESS"')
            local source_ranges=$(echo "${rule}" | jq -r '.sourceRanges // []')
            local allowed=$(echo "${rule}" | jq -r '.allowed // []')
            local priority=$(echo "${rule}" | jq -r '.priority // 1000')
            
            # Check for rules allowing traffic from anywhere (0.0.0.0/0)
            if echo "${source_ranges}" | jq -e 'contains(["0.0.0.0/0"])' >/dev/null; then
                # Check for sensitive ports
                local sensitive_ports_allowed=false
                local sensitive_port_list=""
                
                # Check for HTTP/HTTPS
                if echo "${allowed}" | jq -e '.[] | select(.IPProtocol == "tcp") | .ports // [] | contains(["80"]) or contains(["443"])' >/dev/null; then
                    sensitive_ports_allowed=true
                    sensitive_port_list="${sensitive_port_list} HTTP(80)/HTTPS(443)"
                fi
                
                # Check for FTP
                if echo "${allowed}" | jq -e '.[] | select(.IPProtocol == "tcp") | .ports // [] | contains(["21"]) or contains(["20"])' >/dev/null; then
                    sensitive_ports_allowed=true
                    sensitive_port_list="${sensitive_port_list} FTP(20/21)"
                fi
                
                # Check for Telnet
                if echo "${allowed}" | jq -e '.[] | select(.IPProtocol == "tcp") | .ports // [] | contains(["23"])' >/dev/null; then
                    sensitive_ports_allowed=true
                    sensitive_port_list="${sensitive_port_list} Telnet(23)"
                fi
                
                # Check for SMTP
                if echo "${allowed}" | jq -e '.[] | select(.IPProtocol == "tcp") | .ports // [] | contains(["25"])' >/dev/null; then
                    sensitive_ports_allowed=true
                    sensitive_port_list="${sensitive_port_list} SMTP(25)"
                fi
                
                # Check for SSH
                if echo "${allowed}" | jq -e '.[] | select(.IPProtocol == "tcp") | .ports // [] | contains(["22"])' >/dev/null; then
                    sensitive_ports_allowed=true
                    sensitive_port_list="${sensitive_port_list} SSH(22)"
                fi
                
                # Check for RDP
                if echo "${allowed}" | jq -e '.[] | select(.IPProtocol == "tcp") | .ports // [] | contains(["3389"])' >/dev/null; then
                    sensitive_ports_allowed=true
                    sensitive_port_list="${sensitive_port_list} RDP(3389)"
                fi
                
                if [[ "${sensitive_ports_allowed}" == "true" ]]; then
                    add_finding "WARNING" "4.2.1" "Open firewall rule for sensitive ports" \
                        "Firewall rule ${rule_name} in network ${network_name} allows ${direction} traffic from anywhere (0.0.0.0/0) to sensitive ports:${sensitive_port_list}." \
                        "firewall-rule/${rule_name}" \
                        "Restrict access to these ports to specific IP ranges or implement a VPN or Cloud Identity-Aware Proxy for secure remote access."
                fi
                
                # Check for all ports
                if echo "${allowed}" | jq -e '.[] | select(.IPProtocol == "tcp" or .IPProtocol == "udp") | select(has("ports") | not)' >/dev/null; then
                    add_finding "CRITICAL" "4.2.1" "Open firewall rule for all ports" \
                        "Firewall rule ${rule_name} in network ${network_name} allows ${direction} traffic from anywhere (0.0.0.0/0) to ALL ports." \
                        "firewall-rule/${rule_name}" \
                        "Restrict this rule to specific ports and source IP ranges required for business purposes."
                fi
                
                # Check for all protocols
                if echo "${allowed}" | jq -e '.[] | select(.IPProtocol == "all")' >/dev/null; then
                    add_finding "CRITICAL" "4.2.1" "Open firewall rule for all protocols" \
                        "Firewall rule ${rule_name} in network ${network_name} allows ${direction} traffic from anywhere (0.0.0.0/0) for ALL protocols." \
                        "firewall-rule/${rule_name}" \
                        "Restrict this rule to specific protocols, ports, and source IP ranges required for business purposes."
                fi
            fi
        done
    done
}

# Check Cloud SQL instance encryption
check_cloud_sql_encryption() {
    local project_id="$1"
    local output_file="${TEMP_DIR}/sql_instances.json"
    
    log "INFO" "Checking Cloud SQL instance encryption..."
    
    # Get all Cloud SQL instances
    gcloud sql instances list --project="${project_id}" --format="json" > "${output_file}" 2>/dev/null
    
    # Validate JSON
    local instances=$(validate_json "${output_file}")
    
    # Check if we have any instances
    local instance_count=$(echo "${instances}" | jq 'length')
    if [[ "${instance_count}" -eq 0 ]]; then
        log "INFO" "No Cloud SQL instances found in project ${project_id}"
        return
    fi
    
    # Check each instance
    echo "${instances}" | jq -c '.[]' 2>/dev/null | while read -r instance; do
        local instance_name=$(echo "${instance}" | jq -r '.name // "Unknown"')
        local ssl_enabled=$(echo "${instance}" | jq -r '.settings.ipConfiguration.requireSsl // false')
        
        if [[ "${ssl_enabled}" == "true" ]]; then
            add_finding "PASS" "4.2.1" "SSL required for Cloud SQL" \
                "Cloud SQL instance ${instance_name} requires SSL connections." \
                "sql-instance/${instance_name}" \
                "Ensure SSL certificates are properly managed and rotated."
        else
            add_finding "CRITICAL" "4.2.1" "SSL not required for Cloud SQL" \
                "Cloud SQL instance ${instance_name} does not require SSL connections, allowing unencrypted data transmission." \
                "sql-instance/${instance_name}" \
                "Enable 'Require SSL' option for the Cloud SQL instance to enforce encrypted connections."
        fi
        
        # Check for public IP
        local has_public_ip=$(echo "${instance}" | jq -r '.settings.ipConfiguration.ipv4Enabled // false')
        
        if [[ "${has_public_ip}" == "true" ]]; then
            add_finding "WARNING" "4.2.1" "Cloud SQL with public IP" \
                "Cloud SQL instance ${instance_name} has a public IP address, potentially exposing it to the internet." \
                "sql-instance/${instance_name}" \
                "Consider using private IP only, or restrict access to specific IP ranges if public access is required."
        fi
    done
}

# Check Cloud Armor security policies
check_cloud_armor() {
    local project_id="$1"
    local output_file="${TEMP_DIR}/security_policies.json"
    
    log "INFO" "Checking Cloud Armor security policies..."
    
    # Get all Cloud Armor security policies
    gcloud compute security-policies list --project="${project_id}" --format="json" > "${output_file}" 2>/dev/null
    
    # Validate JSON
    local policies=$(validate_json "${output_file}")
    
    # Check if we have any policies
    local policy_count=$(echo "${policies}" | jq 'length')
    if [[ "${policy_count}" -eq 0 ]]; then
        log "INFO" "No Cloud Armor security policies found in project ${project_id}"
        add_finding "INFO" "4.2.1" "No Cloud Armor security policies" \
            "No Cloud Armor security policies were found in the project. Cloud Armor can help protect web applications from attacks." \
            "project/${project_id}" \
            "Consider implementing Cloud Armor security policies to protect web applications that process cardholder data."
        return
    fi
    
    # Check each policy
    echo "${policies}" | jq -c '.[]' 2>/dev/null | while read -r policy; do
        local policy_name=$(echo "${policy}" | jq -r '.name // "Unknown"')
        
        # Get detailed policy information
        local policy_detail_file="${TEMP_DIR}/security_policy_${policy_name}.json"
        gcloud compute security-policies describe "${policy_name}" --project="${project_id}" --format="json" > "${policy_detail_file}" 2>/dev/null
        
        # Validate JSON
        local policy_detail=$(validate_json "${policy_detail_file}" "{}")
        
        # Check for HTTPS enforcement
        local rules=$(echo "${policy_detail}" | jq -r '.rules // []')
        local https_enforced=false
        
        # Look for rules that enforce HTTPS
        if echo "${rules}" | jq -e '.[] | select(.match.config.srcIpRanges | contains(["*"])) | select(.action == "redirect") | select(.redirectConfig.type == "EXTERNAL_302") | select(.redirectConfig.target | contains("https://"))' >/dev/null; then
            https_enforced=true
        fi
        
        if [[ "${https_enforced}" == "true" ]]; then
            add_finding "PASS" "4.2.1" "HTTPS enforced by Cloud Armor" \
                "Cloud Armor security policy ${policy_name} enforces HTTPS by redirecting HTTP traffic." \
                "security-policy/${policy_name}" \
                "Continue to monitor and update security policies as needed."
        else
            add_finding "INFO" "4.2.1" "HTTPS not enforced by Cloud Armor" \
                "Cloud Armor security policy ${policy_name} does not appear to enforce HTTPS by redirecting HTTP traffic." \
                "security-policy/${policy_name}" \
                "Consider adding a rule to redirect HTTP traffic to HTTPS to ensure encrypted transmission of data."
        fi
        
        # Check for XSS protection
        local xss_protection=false
        
        if echo "${rules}" | jq -e '.[] | select(.match.expr.expression | contains("evaluatePreconfiguredExpr(\"xss\")"))' >/dev/null; then
            xss_protection=true
        fi
        
        if [[ "${xss_protection}" == "true" ]]; then
            add_finding "PASS" "4.2.1" "XSS protection enabled in Cloud Armor" \
                "Cloud Armor security policy ${policy_name} has XSS protection enabled." \
                "security-policy/${policy_name}" \
                "Continue to monitor and update security policies as needed."
        else
            add_finding "INFO" "4.2.1" "XSS protection not detected in Cloud Armor" \
                "Cloud Armor security policy ${policy_name} does not appear to have XSS protection enabled." \
                "security-policy/${policy_name}" \
                "Consider enabling XSS protection to prevent cross-site scripting attacks that could compromise cardholder data."
        fi
    done
}

# Check VPN and interconnect configurations
check_vpn_configurations() {
    local project_id="$1"
    local output_file="${TEMP_DIR}/vpn_tunnels.json"
    
    log "INFO" "Checking VPN configurations..."
    
    # Get all VPN tunnels
    gcloud compute vpn-tunnels list --project="${project_id}" --format="json" > "${output_file}" 2>/dev/null
    
    # Validate JSON
    local vpn_tunnels=$(validate_json "${output_file}")
    
    # Check if we have any VPN tunnels
    local tunnel_count=$(echo "${vpn_tunnels}" | jq 'length')
    if [[ "${tunnel_count}" -eq 0 ]]; then
        log "INFO" "No VPN tunnels found in project ${project_id}"
        return
    fi
    
    # Check each VPN tunnel
    echo "${vpn_tunnels}" | jq -c '.[]' 2>/dev/null | while read -r tunnel; do
        local tunnel_name=$(echo "${tunnel}" | jq -r '.name // "Unknown"')
        local ike_version=$(echo "${tunnel}" | jq -r '.ikeVersion // 2')
        
        if [[ "${ike_version}" -lt 2 ]]; then
            add_finding "WARNING" "4.2.1" "Outdated IKE version for VPN" \
                "VPN tunnel ${tunnel_name} uses IKE version ${ike_version}, which is less secure than IKEv2." \
                "vpn-tunnel/${tunnel_name}" \
                "Upgrade to IKEv2 for stronger security in VPN connections."
        else
            add_finding "PASS" "4.2.1" "Secure IKE version for VPN" \
                "VPN tunnel ${tunnel_name} uses IKE version ${ike_version}, which provides strong security." \
                "vpn-tunnel/${tunnel_name}" \
                "Continue to monitor for new security standards and update as needed."
        fi
    done
    
    # Check HA VPN gateways
    local ha_vpn_file="${TEMP_DIR}/ha_vpn_gateways.json"
    gcloud compute vpn-gateways list --project="${project_id}" --format="json" > "${ha_vpn_file}" 2>/dev/null
    
    # Validate JSON
    local ha_vpn_gateways=$(validate_json "${ha_vpn_file}")
    
    # Check if we have any HA VPN gateways
    local gateway_count=$(echo "${ha_vpn_gateways}" | jq 'length')
    if [[ "${gateway_count}" -gt 0 ]]; then
        add_finding "PASS" "4.2.1" "HA VPN gateways in use" \
            "Project uses High Availability VPN gateways, which provide better reliability for secure connections." \
            "project/${project_id}" \
            "Continue to monitor and maintain VPN configurations for secure transmission of data."
    fi
}

# Check Cloud CDN configurations
check_cloud_cdn() {
    local project_id="$1"
    local output_file="${TEMP_DIR}/backend_services.json"
    
    log "INFO" "Checking Cloud CDN configurations..."
    
    # Get all backend services
    gcloud compute backend-services list --project="${project_id}" --format="json" > "${output_file}" 2>/dev/null
    
    # Validate JSON
    local backend_services=$(validate_json "${output_file}")
    
    # Check if we have any backend services
    local service_count=$(echo "${backend_services}" | jq 'length')
    if [[ "${service_count}" -eq 0 ]]; then
        log "INFO" "No backend services found in project ${project_id}"
        return
    fi
    
    # Check each backend service
    echo "${backend_services}" | jq -c '.[]' 2>/dev/null | while read -r service; do
        local service_name=$(echo "${service}" | jq -r '.name // "Unknown"')
        local cdn_enabled=$(echo "${service}" | jq -r '.enableCDN // false')
        
        if [[ "${cdn_enabled}" == "true" ]]; then
            # Check if HTTPS is used
            local protocol=$(echo "${service}" | jq -r '.protocol // "Unknown"')
            
            if [[ "${protocol}" == "HTTPS" || "${protocol}" == "HTTP2" ]]; then
                add_finding "PASS" "4.2.1" "Secure protocol with Cloud CDN" \
                    "Backend service ${service_name} uses ${protocol} with Cloud CDN enabled." \
                    "backend-service/${service_name}" \
                    "Continue to monitor and maintain secure configurations."
            else
                add_finding "WARNING" "4.2.1" "Insecure protocol with Cloud CDN" \
                    "Backend service ${service_name} uses ${protocol} with Cloud CDN enabled, which may not encrypt data in transit." \
                    "backend-service/${service_name}" \
                    "Consider using HTTPS or HTTP2 to ensure encryption of data in transit."
            fi
            
            # Check security policy
            local security_policy=$(echo "${service}" | jq -r '.securityPolicy // ""')
            
            if [[ -z "${security_policy}" ]]; then
                add_finding "INFO" "4.2.1" "No security policy for CDN-enabled backend" \
                    "Backend service ${service_name} with Cloud CDN enabled does not have a security policy attached." \
                    "backend-service/${service_name}" \
                    "Consider attaching a Cloud Armor security policy to protect CDN-enabled content."
            fi
        fi
    done
}

# Check API Gateway configurations
check_api_gateway() {
    local project_id="$1"
    local output_file="${TEMP_DIR}/api_gateways.json"
    
    log "INFO" "Checking API Gateway configurations..."
    
    # Get all API gateways
    gcloud api-gateway gateways list --project="${project_id}" --format="json" > "${output_file}" 2>/dev/null
    
    # Validate JSON
    local gateways=$(validate_json "${output_file}")
    
    # Check if we have any API gateways
    local gateway_count=$(echo "${gateways}" | jq 'length')
    if [[ "${gateway_count}" -eq 0 ]]; then
        log "INFO" "No API gateways found in project ${project_id}"
        return
    fi
    
    # Check each API gateway
    echo "${gateways}" | jq -c '.[]' 2>/dev/null | while read -r gateway; do
        local gateway_id=$(echo "${gateway}" | jq -r '.name // "Unknown"' | sed 's|.*/||')
        local display_name=$(echo "${gateway}" | jq -r '.displayName // "Unknown"')
        
        # Get API configs for this gateway
        local configs_file="${TEMP_DIR}/api_configs_${gateway_id}.json"
        gcloud api-gateway api-configs list --gateway="${gateway_id}" --project="${project_id}" --format="json" > "${configs_file}" 2>/dev/null
        
        # Validate JSON
        local configs=$(validate_json "${configs_file}")
        
        # Check each API config
        echo "${configs}" | jq -c '.[]' 2>/dev/null | while read -r config; do
            local config_id=$(echo "${config}" | jq -r '.name // "Unknown"' | sed 's|.*/||')
            local service_config_id=$(echo "${config}" | jq -r '.serviceConfigId // "Unknown"')
            
            # Get the OpenAPI spec for this config
            local spec_file="${TEMP_DIR}/api_spec_${config_id}.json"
            gcloud api-gateway api-configs describe "${config_id}" --gateway="${gateway_id}" --project="${project_id}" --format="json" > "${spec_file}" 2>/dev/null
            
            # Validate JSON
            local spec=$(validate_json "${spec_file}" "{}")
            
            # Check for HTTPS enforcement
            local schemes=$(echo "${spec}" | jq -r '.serviceConfig.apis[0].source.files[0].contents | fromjson | .schemes // []' 2>/dev/null)
            
            if echo "${schemes}" | jq -e 'contains(["https"])' >/dev/null && ! echo "${schemes}" | jq -e 'contains(["http"])' >/dev/null; then
                add_finding "PASS" "4.2.1" "HTTPS-only API Gateway" \
                    "API Gateway ${display_name} (${gateway_id}) with config ${config_id} enforces HTTPS-only communication." \
                    "api-gateway/${gateway_id}" \
                    "Continue to monitor and maintain secure configurations."
            elif echo "${schemes}" | jq -e 'contains(["https"])' >/dev/null && echo "${schemes}" | jq -e 'contains(["http"])' >/dev/null; then
                add_finding "WARNING" "4.2.1" "Mixed HTTP/HTTPS API Gateway" \
                    "API Gateway ${display_name} (${gateway_id}) with config ${config_id} allows both HTTP and HTTPS communication." \
                    "api-gateway/${gateway_id}" \
                    "Consider enforcing HTTPS-only communication to ensure encryption of data in transit."
            elif ! echo "${schemes}" | jq -e 'contains(["https"])' >/dev/null; then
                add_finding "CRITICAL" "4.2.1" "Non-HTTPS API Gateway" \
                    "API Gateway ${display_name} (${gateway_id}) with config ${config_id} does not enforce HTTPS communication." \
                    "api-gateway/${gateway_id}" \
                    "Configure the API Gateway to enforce HTTPS-only communication to ensure encryption of data in transit."
            fi
            
            # Check for security definitions
            local security_definitions=$(echo "${spec}" | jq -r '.serviceConfig.apis[0].source.files[0].contents | fromjson | .securityDefinitions // {}' 2>/dev/null)
            
            if [[ "${security_definitions}" == "{}" ]]; then
                add_finding "WARNING" "4.2.1" "No security definitions for API Gateway" \
                    "API Gateway ${display_name} (${gateway_id}) with config ${config_id} does not have security definitions configured." \
                    "api-gateway/${gateway_id}" \
                    "Consider implementing security definitions such as API keys, OAuth, or JWT to secure API access."
            else
                add_finding "PASS" "4.2.1" "Security definitions for API Gateway" \
                    "API Gateway ${display_name} (${gateway_id}) with config ${config_id} has security definitions configured." \
                    "api-gateway/${gateway_id}" \
                    "Continue to monitor and maintain secure configurations."
            fi
        done
    done
}

# Check for end-user messaging technologies
check_messaging_technologies() {
    local project_id="$1"
    
    log "INFO" "Checking for end-user messaging technologies..."
    
    # Check Pub/Sub
    local pubsub_file="${TEMP_DIR}/pubsub_topics.json"
    gcloud pubsub topics list --project="${project_id}" --format="json" > "${pubsub_file}" 2>/dev/null
    
    # Validate JSON
    local pubsub_topics=$(validate_json "${pubsub_file}")
    
    # Check if we have any Pub/Sub topics
    local topic_count=$(echo "${pubsub_topics}" | jq 'length')
    if [[ "${topic_count}" -gt 0 ]]; then
        add_finding "INFO" "4.2.2" "Pub/Sub messaging in use" \
            "Project uses Google Cloud Pub/Sub for messaging. If cardholder data is transmitted, ensure it's properly encrypted." \
            "project/${project_id}" \
            "If cardholder data is transmitted via Pub/Sub, implement message-level encryption to protect sensitive data."
    fi
    
    # Check Firebase
    local firebase_file="${TEMP_DIR}/firebase_projects.json"
    gcloud firebase projects list --format="json" > "${firebase_file}" 2>/dev/null
    
    # Validate JSON
    local firebase_projects=$(validate_json "${firebase_file}")
    
    # Check if this project uses Firebase
    if echo "${firebase_projects}" | jq -e ".[] | select(.projectId == \"${project_id}\")" >/dev/null; then
        add_finding "WARNING" "4.2.2" "Firebase in use" \
            "Project uses Firebase, which may include messaging features. If cardholder data is transmitted, ensure it's properly encrypted." \
            "project/${project_id}" \
            "If Firebase Cloud Messaging or Realtime Database is used to transmit cardholder data, implement end-to-end encryption."
    fi
}

# ======== REPORT GENERATION ========

# Generate HTML report
generate_html_report() {
    local project_id="$1"
    local findings=$(cat "${FINDINGS_FILE}")
    local summary=$(cat "${SUMMARY_FILE}")
    
    log "INFO" "Generating HTML report..."
    
    # Get project info
    local project_info=$(gcloud projects describe "${project_id}" --format="json" 2>/dev/null)
    local project_name=$(echo "${project_info}" | jq -r '.name // "Unknown"')
    local project_number=$(echo "${project_info}" | jq -r '.projectNumber // "Unknown"')
    
    # Count findings by severity
    local critical_count=$(echo "${summary}" | jq -r '.critical // 0')
    local warning_count=$(echo "${summary}" | jq -r '.warning // 0')
    local pass_count=$(echo "${summary}" | jq -r '.pass // 0')
    local info_count=$(echo "${summary}" | jq -r '.info // 0')
    local total_count=$((critical_count + warning_count + pass_count + info_count))
    
    # Create HTML report
    cat > "${REPORT_FILE}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS 4.0 Requirement 4 Assessment Report - ${project_id}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            border-radius: 5px;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
            margin-top: 20px;
        }
        h1 {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .summary-box {
            display: flex;
            justify-content: space-between;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        .summary-item {
            flex: 1;
            min-width: 150px;
            margin: 10px;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            box-shadow: 0 0 5px rgba(0,0,0,0.1);
        }
        .critical {
            background-color: #ffebee;
            border-left: 5px solid #f44336;
        }
        .warning {
            background-color: #fff8e1;
            border-left: 5px solid #ffc107;
        }
        .pass {
            background-color: #e8f5e9;
            border-left: 5px solid #4caf50;
        }
        .info {
            background-color: #e3f2fd;
            border-left: 5px solid #2196f3;
        }
        .finding {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 0 5px rgba(0,0,0,0.1);
        }
        .finding h3 {
            margin-top: 0;
        }
        .finding-meta {
            font-size: 0.9em;
            color: #7f8c8d;
            margin-bottom: 10px;
        }
        .finding-description {
            margin-bottom: 10px;
        }
        .finding-recommendation {
            font-style: italic;
            background-color: #f9f9f9;
            padding: 10px;
            border-left: 3px solid #3498db;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .requirement-section {
            margin-top: 30px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }
        .collapsible {
            background-color: #f1f1f1;
            color: #444;
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 15px;
            border-radius: 5px;
            margin-bottom: 5px;
        }
        .active, .collapsible:hover {
            background-color: #e1e1e1;
        }
        .content {
            padding: 0 18px;
            display: none;
            overflow: hidden;
            background-color: #fff;
            border-radius: 0 0 5px 5px;
        }
        .chart-container {
            display: flex;
            justify-content: center;
            margin: 20px 0;
        }
        .chart {
            width: 200px;
            height: 200px;
            position: relative;
        }
        footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>PCI DSS 4.0 Requirement 4 Assessment Report</h1>
        
        <div class="project-info">
            <h2>Project Information</h2>
            <table>
                <tr>
                    <th>Project Name</th>
                    <td>${project_name}</td>
                </tr>
                <tr>
                    <th>Project ID</th>
                    <td>${project_id}</td>
                </tr>
                <tr>
                    <th>Project Number</th>
                    <td>${project_number}</td>
                </tr>
                <tr>
                    <th>Assessment Date</th>
                    <td>$(date +"%Y-%m-%d %H:%M:%S")</td>
                </tr>
            </table>
        </div>
        
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p>
                This report presents the findings of an automated assessment of Google Cloud Platform project <strong>${project_id}</strong> 
                against PCI DSS 4.0 Requirement 4: "Protect Cardholder Data with Strong Cryptography During Transmission Over Open, Public Networks".
            </p>
            <p>
                The assessment evaluates the configuration of various GCP services and resources to identify potential compliance issues 
                and security risks related to the transmission of cardholder data.
            </p>
            
            <div class="summary-box">
                <div class="summary-item critical">
                    <h3>Critical</h3>
                    <p>${critical_count}</p>
                </div>
                <div class="summary-item warning">
                    <h3>Warning</h3>
                    <p>${warning_count}</p>
                </div>
                <div class="summary-item pass">
                    <h3>Pass</h3>
                    <p>${pass_count}</p>
                </div>
                <div class="summary-item info">
                    <h3>Info</h3>
                    <p>${info_count}</p>
                </div>
            </div>
            
            <div class="chart-container">
                <div class="chart">
                    <canvas id="findingsChart" width="200" height="200"></canvas>
                </div>
            </div>
        </div>
        
        <div class="requirement-overview">
            <h2>PCI DSS 4.0 Requirement 4 Overview</h2>
            
            <div class="requirement-section">
                <h3>Requirement 4.1: Processes and mechanisms for protecting cardholder data with strong cryptography during transmission over open, public networks are defined and understood.</h3>
                <p>
                    This requirement focuses on ensuring that security policies, operational procedures, and roles and responsibilities 
                    for protecting cardholder data during transmission are documented, maintained, and understood by all relevant parties.
                </p>
            </div>
            
            <div class="requirement-section">
                <h3>Requirement 4.2: PAN is protected with strong cryptography during transmission.</h3>
                <p>
                    This requirement ensures that Primary Account Numbers (PANs) are protected with strong cryptography during transmission 
                    over open, public networks, including the use of trusted keys and certificates, secure protocols, and appropriate 
                    encryption strength.
                </p>
            </div>
        </div>
        
        <div class="findings">
            <h2>Detailed Findings</h2>
            
            <button type="button" class="collapsible">Critical Findings (${critical_count})</button>
            <div class="content">
EOF

    # Add critical findings
    if [[ "${critical_count}" -gt 0 ]]; then
        echo "${findings}" | jq -c '.[] | select(.severity == "CRITICAL")' | while read -r finding; do
            local title=$(echo "${finding}" | jq -r '.title')
            local requirement=$(echo "${finding}" | jq -r '.requirement')
            local description=$(echo "${finding}" | jq -r '.description')
            local resource_id=$(echo "${finding}" | jq -r '.resource_id')
            local recommendation=$(echo "${finding}" | jq -r '.recommendation')
            
            cat >> "${REPORT_FILE}" << EOF
                <div class="finding critical">
                    <h3>${title}</h3>
                    <div class="finding-meta">
                        <strong>Requirement:</strong> ${requirement} | <strong>Resource:</strong> ${resource_id}
                    </div>
                    <div class="finding-description">
                        ${description}
                    </div>
                    <div class="finding-recommendation">
                        <strong>Recommendation:</strong> ${recommendation}
                    </div>
                </div>
EOF
        done
    else
        cat >> "${REPORT_FILE}" << EOF
                <p>No critical findings were identified.</p>
EOF
    fi

    cat >> "${REPORT_FILE}" << EOF
            </div>
            
            <button type="button" class="collapsible">Warning Findings (${warning_count})</button>
            <div class="content">
EOF

    # Add warning findings
    if [[ "${warning_count}" -gt 0 ]]; then
        echo "${findings}" | jq -c '.[] | select(.severity == "WARNING")' | while read -r finding; do
            local title=$(echo "${finding}" | jq -r '.title')
            local requirement=$(echo "${finding}" | jq -r '.requirement')
            local description=$(echo "${finding}" | jq -r '.description')
            local resource_id=$(echo "${finding}" | jq -r '.resource_id')
            local recommendation=$(echo "${finding}" | jq -r '.recommendation')
            
            cat >> "${REPORT_FILE}" << EOF
                <div class="finding warning">
                    <h3>${title}</h3>
                    <div class="finding-meta">
                        <strong>Requirement:</strong> ${requirement} | <strong>Resource:</strong> ${resource_id}
                    </div>
                    <div class="finding-description">
                        ${description}
                    </div>
                    <div class="finding-recommendation">
                        <strong>Recommendation:</strong> ${recommendation}
                    </div>
                </div>
EOF
        done
    else
        cat >> "${REPORT_FILE}" << EOF
                <p>No warning findings were identified.</p>
EOF
    fi

    cat >> "${REPORT_FILE}" << EOF
            </div>
            
            <button type="button" class="collapsible">Pass Findings (${pass_count})</button>
            <div class="content">
EOF

    # Add pass findings
    if [[ "${pass_count}" -gt 0 ]]; then
        echo "${findings}" | jq -c '.[] | select(.severity == "PASS")' | while read -r finding; do
            local title=$(echo "${finding}" | jq -r '.title')
            local requirement=$(echo "${finding}" | jq -r '.requirement')
            local description=$(echo "${finding}" | jq -r '.description')
            local resource_id=$(echo "${finding}" | jq -r '.resource_id')
            local recommendation=$(echo "${finding}" | jq -r '.recommendation')
            
            cat >> "${REPORT_FILE}" << EOF
                <div class="finding pass">
                    <h3>${title}</h3>
                    <div class="finding-meta">
                        <strong>Requirement:</strong> ${requirement} | <strong>Resource:</strong> ${resource_id}
                    </div>
                    <div class="finding-description">
                        ${description}
                    </div>
                    <div class="finding-recommendation">
                        <strong>Recommendation:</strong> ${recommendation}
                    </div>
                </div>
EOF
        done
    else
        cat >> "${REPORT_FILE}" << EOF
                <p>No pass findings were identified.</p>
EOF
    fi

    cat >> "${REPORT_FILE}" << EOF
            </div>
            
            <button type="button" class="collapsible">Informational Findings (${info_count})</button>
            <div class="content">
EOF

    # Add info findings
    if [[ "${info_count}" -gt 0 ]]; then
        echo "${findings}" | jq -c '.[] | select(.severity == "INFO")' | while read -r finding; do
            local title=$(echo "${finding}" | jq -r '.title')
            local requirement=$(echo "${finding}" | jq -r '.requirement')
            local description=$(echo "${finding}" | jq -r '.description')
            local resource_id=$(echo "${finding}" | jq -r '.resource_id')
            local recommendation=$(echo "${finding}" | jq -r '.recommendation')
            
            cat >> "${REPORT_FILE}" << EOF
                <div class="finding info">
                    <h3>${title}</h3>
                    <div class="finding-meta">
                        <strong>Requirement:</strong> ${requirement} | <strong>Resource:</strong> ${resource_id}
                    </div>
                    <div class="finding-description">
                        ${description}
                    </div>
                    <div class="finding-recommendation">
                        <strong>Recommendation:</strong> ${recommendation}
                    </div>
                </div>
EOF
        done
    else
        cat >> "${REPORT_FILE}" << EOF
                <p>No informational findings were identified.</p>
EOF
    fi

    cat >> "${REPORT_FILE}" << EOF
            </div>
        </div>
        
        <div class="recommendations">
            <h2>Summary of Recommendations</h2>
            <p>
                Based on the findings of this assessment, the following key recommendations should be prioritized:
            </p>
            <ul>
EOF

    # Add critical recommendations
    echo "${findings}" | jq -c '.[] | select(.severity == "CRITICAL")' | while read -r finding; do
        local title=$(echo "${finding}" | jq -r '.title')
        local recommendation=$(echo "${finding}" | jq -r '.recommendation')
        
        cat >> "${REPORT_FILE}" << EOF
                <li><strong>${title}:</strong> ${recommendation}</li>
EOF
    done

    # Add warning recommendations (limit to top 5)
    echo "${findings}" | jq -c '.[] | select(.severity == "WARNING")' | head -5 | while read -r finding; do
        local title=$(echo "${finding}" | jq -r '.title')
        local recommendation=$(echo "${finding}" | jq -r '.recommendation')
        
        cat >> "${REPORT_FILE}" << EOF
                <li><strong>${title}:</strong> ${recommendation}</li>
EOF
    done

    cat >> "${REPORT_FILE}" << EOF
            </ul>
        </div>
        
        <div class="next-steps">
            <h2>Next Steps</h2>
            <ol>
                <li>Review and address all critical findings immediately.</li>
                <li>Develop a remediation plan for warning findings based on risk and business impact.</li>
                <li>Implement a regular assessment schedule to continuously monitor compliance with PCI DSS requirements.</li>
                <li>Consider a comprehensive assessment of all PCI DSS 4.0 requirements.</li>
                <li>Document all changes made to address findings for audit purposes.</li>
            </ol>
        </div>
        
        <footer>
            <p>
                This report was generated on $(date +"%Y-%m-%d %H:%M:%S") using an automated PCI DSS 4.0 Requirement 4 assessment tool.
                The findings and recommendations in this report should be reviewed by qualified security personnel.
            </p>
        </footer>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // Initialize collapsible sections
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.display === "block") {
                    content.style.display = "none";
                } else {
                    content.style.display = "block";
                }
            });
        }
        
        // Create findings chart
        var ctx = document.getElementById('findingsChart').getContext('2d');
        var findingsChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'Warning', 'Pass', 'Info'],
                datasets: [{
                    data: [${critical_count}, ${warning_count}, ${pass_count}, ${info_count}],
                    backgroundColor: [
                        '#f44336',
                        '#ffc107',
                        '#4caf50',
                        '#2196f3'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                legend: {
                    position: 'bottom'
                }
            }
        });
    </script>
</body>
</html>
EOF

    log "SUCCESS" "HTML report generated: ${REPORT_FILE}"
}

# ======== MAIN EXECUTION ========

main() {
    # Set up trap for cleanup
    trap handle_interrupt INT TERM
    
    # Display banner
    echo "============================================================"
    echo "  PCI DSS 4.0 Requirement 4 Assessment for GCP"
    echo "  Version: 1.0"
    echo "============================================================"
    
    # Check for required tools
    check_jq
    check_gcloud
    
    # Get project ID from command line or prompt user
    local project_id="$1"
    if [[ -z "${project_id}" ]]; then
        # Get default project
        project_id=$(gcloud config get-value project 2>/dev/null)
        
        if [[ -z "${project_id}" || "${project_id}" == "(unset)" ]]; then
            log "ERROR" "No project ID provided and no default project set."
            log "INFO" "Usage: $0 [project_id]"
            exit 1
        else
            log "INFO" "Using default project: ${project_id}"
        fi
    fi
    
    # Verify GCP authentication and project access
    verify_gcp_auth
    verify_project_access "${project_id}"
    
    # Run assessment checks
    log "INFO" "Starting assessment of project ${project_id} for PCI DSS 4.0 Requirement 4..."
    
    check_load_balancer_ssl_config "${project_id}"
    check_storage_bucket_encryption "${project_id}"
    check_vpc_security "${project_id}"
    check_cloud_sql_encryption "${project_id}"
    check_cloud_armor "${project_id}"
    check_vpn_configurations "${project_id}"
    check_cloud_cdn "${project_id}"
    check_api_gateway "${project_id}"
    check_messaging_technologies "${project_id}"
    
    # Generate HTML report
    generate_html_report "${project_id}"
    
    # Clean up
    cleanup
    
    log "SUCCESS" "Assessment completed successfully."
    log "INFO" "Report saved to: ${REPORT_FILE}"
    
    # Open the report in the default browser
    if [[ "$(uname)" == "Darwin" ]]; then
        open "${REPORT_FILE}"
    elif [[ "$(uname)" == "Linux" ]]; then
        if command_exists xdg-open; then
            xdg-open "${REPORT_FILE}"
        fi
    fi
}

# Run the main function with all arguments
main "$@"
