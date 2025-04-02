#!/bin/bash
#
# PCI DSS 4.0 Requirement 10 Assessment Script for Google Cloud Platform
# This script assesses compliance with Requirement 10: Log and Monitor All Access to System Components and Cardholder Data
#
# Requirements covered:
# - 10.1: Processes and mechanisms for logging and monitoring
# - 10.2: Audit logs implementation
# - 10.3: Audit logs protection
# - 10.4: Audit logs review
# - 10.5: Audit log history retention
# - 10.6: Time-synchronization mechanisms
# - 10.7: Critical security control systems monitoring

# Set strict error handling
set -e
set -o pipefail

# Global variables
PROJECT_ID=""
REPORT_FILE="pci_dss_req10_report_$(date +%Y%m%d_%H%M%S).html"
TEMP_DIR=$(mktemp -d)
LOG_FILE="${TEMP_DIR}/assessment_log.txt"
ERROR_LOG="${TEMP_DIR}/error_log.txt"
CRITICAL_FINDINGS=0
WARNING_FINDINGS=0
PASS_FINDINGS=0
MANUAL_CHECKS=0

# CSS for HTML report
CSS_STYLE="
<style>
    body { font-family: Arial, sans-serif; margin: 20px; color: #333; line-height: 1.6; }
    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
    h2 { color: #2980b9; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 10px; }
    h3 { color: #3498db; margin-top: 20px; }
    .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
    .finding { margin: 15px 0; padding: 15px; border-radius: 5px; border-left: 5px solid; }
    .critical { background-color: #ffebee; border-left-color: #c62828; }
    .warning { background-color: #fff8e1; border-left-color: #f9a825; }
    .pass { background-color: #e8f5e9; border-left-color: #388e3c; }
    .manual { background-color: #e3f2fd; border-left-color: #1976d2; }
    .req-id { font-weight: bold; color: #555; }
    .evidence { background-color: #f5f5f5; padding: 10px; border-radius: 3px; font-family: monospace; white-space: pre-wrap; margin: 10px 0; font-size: 12px; max-height: 200px; overflow: auto; }
    .recommendation { margin-top: 10px; font-style: italic; }
    .exec-summary { background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }
    table { border-collapse: collapse; width: 100%; margin: 15px 0; }
    th, td { text-align: left; padding: 12px; }
    th { background-color: #3498db; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    .chart-container { display: flex; justify-content: space-around; margin: 30px 0; }
    .chart { width: 300px; height: 300px; }
    .footer { margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }
</style>"

# Function to log messages
log() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Function to handle errors
handle_error() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] ERROR: $1" | tee -a "$ERROR_LOG"
}

# Function to validate JSON
validate_json() {
    local json_file="$1"
    if [[ ! -f "$json_file" ]]; then
        handle_error "JSON file not found: $json_file"
        echo "[]"
        return 1
    fi
    
    # Validate JSON and provide default if invalid
    cat "$json_file" | jq empty 2>/dev/null
    if [[ $? -ne 0 ]]; then
        handle_error "Invalid JSON in file: $json_file"
        echo "[]"
        return 1
    fi
    
    # Check if JSON is empty
    local content=$(cat "$json_file")
    if [[ -z "$content" || "$content" == "null" ]]; then
        echo "[]"
        return 0
    fi
    
    # Return the content
    echo "$content"
    return 0
}

# Function to safely extract fields from JSON
safe_json_extract() {
    local json="$1"
    local query="$2"
    local default="${3:-}"
    
    if [[ -z "$json" || "$json" == "null" ]]; then
        echo "$default"
        return
    fi
    
    local result
    result=$(echo "$json" | jq -r "$query" 2>/dev/null)
    
    if [[ $? -ne 0 || -z "$result" || "$result" == "null" ]]; then
        echo "$default"
    else
        echo "$result"
    fi
}

# Function to add a finding to the report
add_finding() {
    local severity="$1"
    local req_id="$2"
    local title="$3"
    local description="$4"
    local evidence="$5"
    local recommendation="$6"
    
    case "$severity" in
        "CRITICAL")
            ((CRITICAL_FINDINGS++))
            local severity_class="critical"
            ;;
        "WARNING")
            ((WARNING_FINDINGS++))
            local severity_class="warning"
            ;;
        "PASS")
            ((PASS_FINDINGS++))
            local severity_class="pass"
            ;;
        "MANUAL")
            ((MANUAL_CHECKS++))
            local severity_class="manual"
            ;;
    esac
    
    # Escape HTML in evidence
    local escaped_evidence=$(echo "$evidence" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g')
    
    cat >> "$TEMP_DIR/findings.html" << EOF
<div class="finding ${severity_class}">
    <h3>${severity}: ${title}</h3>
    <p><span class="req-id">PCI DSS Requirement: ${req_id}</span></p>
    <p>${description}</p>
    <div class="evidence">${escaped_evidence}</div>
    <p class="recommendation"><strong>Recommendation:</strong> ${recommendation}</p>
</div>
EOF
}

# Function to check if gcloud is installed and authenticated
check_gcloud() {
    log "Checking gcloud installation and authentication..."
    
    if ! command -v gcloud &> /dev/null; then
        handle_error "gcloud CLI is not installed or not in PATH"
        exit 1
    fi
    
    # Check if user is authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        handle_error "Not authenticated with gcloud. Please run 'gcloud auth login' first."
        exit 1
    fi
    
    # Get active project
    if [[ -z "$PROJECT_ID" ]]; then
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
        if [[ -z "$PROJECT_ID" ]]; then
            handle_error "No active project found. Please set a project with 'gcloud config set project PROJECT_ID'"
            exit 1
        fi
    fi
    
    log "Using GCP project: $PROJECT_ID"
    
    # Verify project access
    if ! gcloud projects describe "$PROJECT_ID" &>/dev/null; then
        handle_error "Cannot access project $PROJECT_ID. Please check permissions."
        exit 1
    fi
}

# Function to initialize the HTML report
initialize_report() {
    log "Initializing HTML report..."
    
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS 4.0 Requirement 10 Assessment Report</title>
    ${CSS_STYLE}
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>PCI DSS 4.0 Requirement 10 Assessment Report</h1>
    <p>Project ID: ${PROJECT_ID}</p>
    <p>Assessment Date: $(date +"%Y-%m-%d %H:%M:%S")</p>
    
    <div class="exec-summary">
        <h2>Executive Summary</h2>
        <p>This report presents the findings of an automated assessment of Google Cloud Platform configurations against PCI DSS 4.0 Requirement 10: Log and Monitor All Access to System Components and Cardholder Data.</p>
        <p>The assessment evaluates logging and monitoring controls, audit log protection, review processes, and time synchronization mechanisms within the GCP environment.</p>
    </div>
    
    <div id="findings-placeholder"></div>
    
    <div class="chart-container">
        <div>
            <canvas id="findingsChart" width="300" height="300"></canvas>
        </div>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const ctx = document.getElementById('findingsChart').getContext('2d');
            const findingsChart = new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: ['Critical', 'Warning', 'Pass', 'Manual Check'],
                    datasets: [{
                        data: [CRITICAL_PLACEHOLDER, WARNING_PLACEHOLDER, PASS_PLACEHOLDER, MANUAL_PLACEHOLDER],
                        backgroundColor: ['#c62828', '#f9a825', '#388e3c', '#1976d2']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        },
                        title: {
                            display: true,
                            text: 'Assessment Findings'
                        }
                    }
                }
            });
        });
    </script>
    
    <div class="footer">
        <p>This report was generated automatically and should be reviewed by a qualified security professional. Findings may require additional validation.</p>
    </div>
</body>
</html>
EOF

    # Create empty findings file
    touch "$TEMP_DIR/findings.html"
}

# Function to finalize the HTML report
finalize_report() {
    log "Finalizing HTML report..."
    
    # Add summary statistics
    local total_findings=$((CRITICAL_FINDINGS + WARNING_FINDINGS + PASS_FINDINGS + MANUAL_CHECKS))
    
    # Create summary section
    cat > "$TEMP_DIR/summary.html" << EOF
<div class="summary">
    <h2>Assessment Summary</h2>
    <p>Total findings: ${total_findings}</p>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
            <th>Percentage</th>
        </tr>
        <tr>
            <td>Critical</td>
            <td>${CRITICAL_FINDINGS}</td>
            <td>$(( total_findings > 0 ? (CRITICAL_FINDINGS * 100) / total_findings : 0 ))%</td>
        </tr>
        <tr>
            <td>Warning</td>
            <td>${WARNING_FINDINGS}</td>
            <td>$(( total_findings > 0 ? (WARNING_FINDINGS * 100) / total_findings : 0 ))%</td>
        </tr>
        <tr>
            <td>Pass</td>
            <td>${PASS_FINDINGS}</td>
            <td>$(( total_findings > 0 ? (PASS_FINDINGS * 100) / total_findings : 0 ))%</td>
        </tr>
        <tr>
            <td>Manual Check</td>
            <td>${MANUAL_CHECKS}</td>
            <td>$(( total_findings > 0 ? (MANUAL_CHECKS * 100) / total_findings : 0 ))%</td>
        </tr>
    </table>
</div>
EOF

    # Combine all parts
    sed -i "s/CRITICAL_PLACEHOLDER/${CRITICAL_FINDINGS}/" "$REPORT_FILE"
    sed -i "s/WARNING_PLACEHOLDER/${WARNING_FINDINGS}/" "$REPORT_FILE"
    sed -i "s/PASS_PLACEHOLDER/${PASS_FINDINGS}/" "$REPORT_FILE"
    sed -i "s/MANUAL_PLACEHOLDER/${MANUAL_CHECKS}/" "$REPORT_FILE"
    
    # Replace findings placeholder with actual findings
    sed -i "s|<div id=\"findings-placeholder\"></div>|$(cat "$TEMP_DIR/summary.html")\n<h2>Detailed Findings</h2>\n$(cat "$TEMP_DIR/findings.html")|" "$REPORT_FILE"
    
    log "Report generated: $REPORT_FILE"
}

# Function to check if required APIs are enabled
check_required_apis() {
    log "Checking required GCP APIs..."
    
    local required_apis=(
        "logging.googleapis.com"
        "monitoring.googleapis.com"
        "cloudresourcemanager.googleapis.com"
    )
    
    local disabled_apis=()
    
    for api in "${required_apis[@]}"; do
        log "Checking if $api is enabled..."
        
        local api_status
        api_status=$(gcloud services list --project="$PROJECT_ID" --filter="config.name:$api" --format="value(state)" 2>/dev/null || echo "DISABLED")
        
        if [[ "$api_status" != "ENABLED" ]]; then
            disabled_apis+=("$api")
        fi
    done
    
    if [[ ${#disabled_apis[@]} -gt 0 ]]; then
        local apis_list=$(printf "- %s\n" "${disabled_apis[@]}")
        add_finding "WARNING" "10.1" "Required APIs not enabled" \
            "The following APIs required for logging and monitoring are not enabled in the project:" \
            "$apis_list" \
            "Enable these APIs using 'gcloud services enable API_NAME --project=$PROJECT_ID'"
    else
        add_finding "PASS" "10.1" "Required APIs enabled" \
            "All required APIs for logging and monitoring are enabled in the project." \
            "All required APIs are enabled." \
            "Continue to maintain these API enablements."
    fi
}

# Function to assess audit logging configuration (Requirement 10.2)
assess_audit_logging() {
    log "Assessing audit logging configuration (Requirement 10.2)..."
    
    # Check if Cloud Audit Logging is configured
    local audit_configs
    audit_configs=$(gcloud projects get-iam-policy "$PROJECT_ID" --format=json 2>/dev/null | jq '.auditConfigs // []')
    
    if [[ $(echo "$audit_configs" | jq 'length') -eq 0 ]]; then
        add_finding "CRITICAL" "10.2.1" "Cloud Audit Logging not configured" \
            "Cloud Audit Logging is not configured for the project. PCI DSS requires audit logs to be enabled for all system components." \
            "No audit configurations found in the project IAM policy." \
            "Enable Cloud Audit Logging for Admin Activity, Data Access, and System Events using the Google Cloud Console or gcloud CLI."
    else
        # Check for Data Access logs
        local data_access_logs
        data_access_logs=$(echo "$audit_configs" | jq '[.[] | select(.service == "allServices" and (.auditLogConfigs // []) | map(select(.logType == "DATA_READ" or .logType == "DATA_WRITE")) | length > 0)] | length')
        
        if [[ "$data_access_logs" -eq 0 ]]; then
            add_finding "WARNING" "10.2.1" "Data Access audit logs not enabled" \
                "Data Access audit logs are not enabled for all services. These logs are essential for tracking access to cardholder data." \
                "$(echo "$audit_configs" | jq -r '.')" \
                "Enable Data Access audit logs for all services or at minimum for services that store or process cardholder data."
        else
            add_finding "PASS" "10.2.1" "Data Access audit logs enabled" \
                "Data Access audit logs are enabled, which helps track access to cardholder data." \
                "$(echo "$audit_configs" | jq -r '.')" \
                "Regularly review the audit log configuration to ensure it remains appropriate."
        fi
        
        # Check for Admin Activity logs
        local admin_logs
        admin_logs=$(echo "$audit_configs" | jq '[.[] | select(.service == "allServices" and (.auditLogConfigs // []) | map(select(.logType == "ADMIN_READ" or .logType == "ADMIN_WRITE")) | length > 0)] | length')
        
        if [[ "$admin_logs" -eq 0 ]]; then
            add_finding "CRITICAL" "10.2.1.2" "Admin Activity audit logs not enabled" \
                "Admin Activity audit logs are not enabled for all services. PCI DSS requires logging all actions taken by individuals with administrative access." \
                "$(echo "$audit_configs" | jq -r '.')" \
                "Enable Admin Activity audit logs for all services to track administrative actions."
        else
            add_finding "PASS" "10.2.1.2" "Admin Activity audit logs enabled" \
                "Admin Activity audit logs are enabled, which helps track administrative actions." \
                "$(echo "$audit_configs" | jq -r '.')" \
                "Regularly review the audit log configuration to ensure it remains appropriate."
        fi
    fi
    
    # Check for exempted users/services
    local exempted_principals
    exempted_principals=$(echo "$audit_configs" | jq '[.[] | .auditLogConfigs[] | select(.exemptedMembers != null) | .exemptedMembers[]] | unique')
    
    if [[ "$exempted_principals" != "[]" ]]; then
        add_finding "WARNING" "10.2.1" "Exempted principals in audit logging" \
            "Some principals are exempted from audit logging. This may create gaps in the audit trail." \
            "Exempted principals: $(echo "$exempted_principals" | jq -r '.')" \
            "Review exempted principals and remove exemptions where possible, especially for accounts with access to cardholder data."
    fi
    
    # Check log sinks for exporting logs
    local log_sinks
    log_sinks=$(gcloud logging sinks list --project="$PROJECT_ID" --format=json 2>/dev/null || echo "[]")
    
    if [[ $(echo "$log_sinks" | jq 'length') -eq 0 ]]; then
        add_finding "WARNING" "10.3.3" "No log export sinks configured" \
            "No log export sinks are configured. PCI DSS requires audit logs to be promptly backed up to a secure, central location." \
            "No log sinks found." \
            "Configure log sinks to export logs to a secure destination such as Cloud Storage, BigQuery, or another GCP project."
    else
        add_finding "PASS" "10.3.3" "Log export sinks configured" \
            "Log export sinks are configured, which helps ensure logs are backed up to a secure location." \
            "$(echo "$log_sinks" | jq -r '.')" \
            "Regularly verify that log sinks are functioning correctly and logs are being exported as expected."
    fi
}

# Function to assess log protection (Requirement 10.3)
assess_log_protection() {
    log "Assessing log protection mechanisms (Requirement 10.3)..."
    
    # Check log bucket retention policies
    local log_buckets=()
    local log_sinks
    log_sinks=$(gcloud logging sinks list --project="$PROJECT_ID" --format=json 2>/dev/null || echo "[]")
    
    # Extract storage buckets from log sinks
    for sink in $(echo "$log_sinks" | jq -r '.[] | select(.destination | startswith("storage.googleapis.com")) | .destination'); do
        bucket_name=$(echo "$sink" | sed 's|storage.googleapis.com/||')
        log_buckets+=("$bucket_name")
    done
    
    if [[ ${#log_buckets[@]} -gt 0 ]]; then
        for bucket in "${log_buckets[@]}"; do
            local retention_policy
            retention_policy=$(gcloud storage buckets describe "gs://$bucket" --format=json 2>/dev/null | jq '.retentionPolicy // {}')
            
            if [[ $(echo "$retention_policy" | jq 'length') -eq 0 ]]; then
                add_finding "WARNING" "10.5.1" "Log bucket without retention policy" \
                    "The log storage bucket does not have a retention policy. PCI DSS requires audit logs to be retained for at least 12 months." \
                    "Bucket: $bucket\nNo retention policy configured." \
                    "Configure a retention policy of at least 12 months on the log storage bucket."
            else
                local retention_period
                retention_period=$(echo "$retention_policy" | jq -r '.retentionPeriod // 0')
                # Convert to days (retention period is in seconds)
                local retention_days=$((retention_period / 86400))
                
                if [[ $retention_days -lt 365 ]]; then
                    add_finding "WARNING" "10.5.1" "Insufficient log retention period" \
                        "The log storage bucket has a retention period less than 12 months. PCI DSS requires audit logs to be retained for at least 12 months." \
                        "Bucket: $bucket\nRetention period: $retention_days days" \
                        "Increase the retention period to at least 365 days (31536000 seconds)."
                else
                    add_finding "PASS" "10.5.1" "Sufficient log retention period" \
                        "The log storage bucket has a retention period of at least 12 months, which meets PCI DSS requirements." \
                        "Bucket: $bucket\nRetention period: $retention_days days" \
                        "Continue to maintain this retention policy."
                fi
            fi
            
            # Check bucket access controls
            local bucket_iam
            bucket_iam=$(gcloud storage buckets get-iam-policy "gs://$bucket" --format=json 2>/dev/null || echo "{}")
            
            local public_access
            public_access=$(echo "$bucket_iam" | jq '.bindings[] | select(.members[] | contains("allUsers") or contains("allAuthenticatedUsers")) | .role' 2>/dev/null || echo "")
            
            if [[ -n "$public_access" ]]; then
                add_finding "CRITICAL" "10.3.1" "Public access to log storage" \
                    "The log storage bucket has public access enabled. PCI DSS requires that access to audit logs is limited to those with a job-related need." \
                    "Bucket: $bucket\nPublic roles: $public_access" \
                    "Remove public access from the log storage bucket immediately."
            else
                add_finding "PASS" "10.3.1" "No public access to log storage" \
                    "The log storage bucket does not have public access, which helps protect audit logs from unauthorized access." \
                    "Bucket: $bucket\nNo public access detected." \
                    "Continue to monitor access controls to ensure they remain appropriate."
            fi
        done
    fi
    
    # Check for log-based metrics (can be used for alerting on log tampering)
    local log_metrics
    log_metrics=$(gcloud logging metrics list --project="$PROJECT_ID" --format=json 2>/dev/null || echo "[]")
    
    local security_metrics
    security_metrics=$(echo "$log_metrics" | jq '[.[] | select(.filter | contains("protoPayload.methodName") or contains("principalEmail") or contains("admin"))] | length')
    
    if [[ "$security_metrics" -eq 0 ]]; then
        add_finding "WARNING" "10.3.4" "No security-related log metrics" \
            "No security-related log metrics are configured. Log metrics can be used with alerting to detect unauthorized modifications to logs." \
            "No security-related log metrics found." \
            "Create log-based metrics for security events such as changes to IAM policies, audit configurations, and log settings."
    else
        add_finding "PASS" "10.3.4" "Security-related log metrics configured" \
            "Security-related log metrics are configured, which can be used with alerting to detect unauthorized modifications to logs." \
            "$(echo "$log_metrics" | jq -r '.')" \
            "Ensure these metrics are connected to appropriate alerting policies."
    fi
}

# Function to assess log review processes (Requirement 10.4)
assess_log_review() {
    log "Assessing log review processes (Requirement 10.4)..."
    
    # Check for alerting policies
    local alerting_policies
    alerting_policies=$(gcloud alpha monitoring policies list --project="$PROJECT_ID" --format=json 2>/dev/null || echo "[]")
    
    local security_alerts
    security_alerts=$(echo "$alerting_policies" | jq '[.[] | select(.displayName | test("security|audit|log|alert|incident|unauthorized|suspicious|anomaly"; "i"))] | length')
    
    if [[ "$security_alerts" -eq 0 ]]; then
        add_finding "WARNING" "10.4.1.1" "No security-related alerting policies" \
            "No security-related alerting policies are configured. PCI DSS requires automated mechanisms for log review." \
            "No security-related alerting policies found." \
            "Create alerting policies for security events such as unauthorized access attempts, privilege escalations, and configuration changes."
    else
        add_finding "PASS" "10.4.1.1" "Security-related alerting policies configured" \
            "Security-related alerting policies are configured, which helps automate log review processes." \
            "$(echo "$alerting_policies" | jq -r '.')" \
            "Regularly review and update alerting policies to ensure they remain effective."
    fi
    
    # Check for log-based metrics with alerting
    local log_metrics
    log_metrics=$(gcloud logging metrics list --project="$PROJECT_ID" --format=json 2>/dev/null || echo "[]")
    
    for metric in $(echo "$log_metrics" | jq -r '.[] | select(.filter | contains("protoPayload.methodName") or contains("principalEmail") or contains("admin")) | .metricDescriptor.type'); do
        local metric_alerts
        metric_alerts=$(echo "$alerting_policies" | jq --arg metric "$metric" '[.[] | select(.conditions[] | .conditionThreshold.filter | contains($metric))] | length')
        
        if [[ "$metric_alerts" -eq 0 ]]; then
            add_finding "WARNING" "10.4.3" "Security metric without alerting" \
                "A security-related log metric does not have associated alerting policies. This may prevent timely detection of security events." \
                "Metric: $metric\nNo associated alerting policies found." \
                "Create alerting policies for this metric to ensure security events are promptly detected and addressed."
        fi
    done
    
    # Check for Security Command Center
    local scc_status
    scc_status=$(gcloud services list --project="$PROJECT_ID" --filter="config.name:securitycenter.googleapis.com" --format="value(state)" 2>/dev/null || echo "DISABLED")
    
    if [[ "$scc_status" != "ENABLED" ]]; then
        add_finding "WARNING" "10.4.1" "Security Command Center not enabled" \
            "Security Command Center is not enabled. SCC provides automated detection of security issues and can help with log review requirements." \
            "Security Command Center API status: $scc_status" \
            "Consider enabling Security Command Center to enhance security monitoring capabilities."
    else
        add_finding "PASS" "10.4.1" "Security Command Center enabled" \
            "Security Command Center is enabled, which provides automated detection of security issues." \
            "Security Command Center API status: $scc_status" \
            "Ensure SCC is properly configured and findings are regularly reviewed."
    fi
    
    # Manual check reminder for daily log review
    add_finding "MANUAL" "10.4.1" "Daily log review process" \
        "PCI DSS requires daily review of security events and logs from critical systems. This cannot be fully automated and requires manual verification." \
        "This check requires manual verification of operational procedures." \
        "Implement and document a process for daily review of security event logs, including all security events, logs from systems that store/process/transmit CHD, and logs from critical system components."
}

# Function to assess time synchronization (Requirement 10.6)
assess_time_synchronization() {
    log "Assessing time synchronization mechanisms (Requirement 10.6)..."
    
    # This is primarily a manual check as GCP handles time synchronization for most services
    add_finding "MANUAL" "10.6.1" "Time synchronization for GCP services" \
        "PCI DSS requires time synchronization technology to be used. GCP services automatically use Google's internal time synchronization, but custom VMs may need additional configuration." \
        "GCP automatically synchronizes time for managed services. For Compute Engine VMs, additional configuration may be needed." \
        "For Compute Engine VMs, verify that NTP is properly configured to use Google's NTP servers (metadata.google.internal) or other approved time sources."
    
    # Check for custom VMs that might need time sync configuration
    local compute_instances
    compute_instances=$(gcloud compute instances list --project="$PROJECT_ID" --format=json 2>/dev/null || echo "[]")
    
    if [[ $(echo "$compute_instances" | jq 'length') -gt 0 ]]; then
        add_finding "MANUAL" "10.6.2" "Time synchronization for Compute Engine VMs" \
            "Compute Engine VMs are present in the environment. These may require explicit time synchronization configuration." \
            "$(echo "$compute_instances" | jq -r '.[].name')" \
            "Verify that all VMs are configured to use appropriate time sources and that time settings are protected from unauthorized changes."
    fi
}

# Function to assess critical security control monitoring (Requirement 10.7)
assess_critical_security_controls() {
    log "Assessing critical security control monitoring (Requirement 10.7)..."
    
    # Check for monitoring of network security controls
    local fw_log_config
    fw_log_config=$(gcloud compute firewall-rules list --project="$PROJECT_ID" --format=json 2>/dev/null | jq '[.[] | select(.logConfig.enable == true)] | length')
    local total_fw_rules
    total_fw_rules=$(gcloud compute firewall-rules list --project="$PROJECT_ID" --format=json 2>/dev/null | jq 'length')
    
    if [[ "$fw_log_config" -eq 0 ]]; then
        add_finding "CRITICAL" "10.7.2" "Firewall logging not enabled" \
            "Firewall logging is not enabled for any firewall rules. PCI DSS requires monitoring of network security controls." \
            "No firewall rules with logging enabled out of $total_fw_rules total rules." \
            "Enable logging for firewall rules, especially for rules that control access to the CDE."
    elif [[ "$fw_log_config" -lt "$total_fw_rules" ]]; then
        add_finding "WARNING" "10.7.2" "Firewall logging partially enabled" \
            "Firewall logging is only enabled for some firewall rules. PCI DSS requires comprehensive monitoring of network security controls." \
            "$fw_log_config out of $total_fw_rules firewall rules have logging enabled." \
            "Review firewall rules and enable logging for all rules that control access to the CDE."
    else
        add_finding "PASS" "10.7.2" "Firewall logging fully enabled" \
            "Firewall logging is enabled for all firewall rules, which helps monitor network security controls." \
            "All $total_fw_rules firewall rules have logging enabled." \
            "Continue to maintain this configuration."
    fi
    
    # Check for Cloud IDS
    local cloud_ids
    cloud_ids=$(gcloud ids endpoints list --project="$PROJECT_ID" --format=json 2>/dev/null || echo "[]")
    
    if [[ $(echo "$cloud_ids" | jq 'length') -eq 0 ]]; then
        add_finding "WARNING" "10.7.2" "Cloud IDS not deployed" \
            "Google Cloud IDS is not deployed. PCI DSS requires monitoring of intrusion-detection systems." \
            "No Cloud IDS endpoints found." \
            "Consider deploying Cloud IDS to monitor for malicious activity and network-based attacks."
    else
        add_finding "PASS" "10.7.2" "Cloud IDS deployed" \
            "Google Cloud IDS is deployed, which provides network-based intrusion detection capabilities." \
            "$(echo "$cloud_ids" | jq -r '.')" \
            "Ensure IDS alerts are monitored and responded to promptly."
    fi
    
    # Check for monitoring of IAM policy changes
    local iam_metrics
    iam_metrics=$(gcloud logging metrics list --project="$PROJECT_ID" --format=json 2>/dev/null | jq '[.[] | select(.filter | contains("SetIamPolicy") or contains("iam.googleapis.com"))] | length')
    
    if [[ "$iam_metrics" -eq 0 ]]; then
        add_finding "WARNING" "10.7.2" "No IAM change monitoring" \
            "No log metrics for IAM policy changes are configured. PCI DSS requires monitoring of logical access controls." \
            "No log metrics for IAM changes found." \
            "Create log metrics and alerting policies for IAM policy changes to detect unauthorized modifications to access controls."
    else
        add_finding "PASS" "10.7.2" "IAM change monitoring configured" \
            "Log metrics for IAM policy changes are configured, which helps monitor logical access controls." \
            "Found $iam_metrics log metrics related to IAM changes." \
            "Ensure these metrics are connected to appropriate alerting policies."
    fi
    
    # Check for monitoring of audit configuration changes
    local audit_metrics
    audit_metrics=$(gcloud logging metrics list --project="$PROJECT_ID" --format=json 2>/dev/null | jq '[.[] | select(.filter | contains("SetIamPolicy") and contains("auditConfigs"))] | length')
    
    if [[ "$audit_metrics" -eq 0 ]]; then
        add_finding "WARNING" "10.7.2" "No audit configuration monitoring" \
            "No log metrics for audit configuration changes are configured. PCI DSS requires monitoring of audit logging mechanisms." \
            "No log metrics for audit configuration changes found." \
            "Create log metrics and alerting policies for audit configuration changes to detect tampering with logging settings."
    else
        add_finding "PASS" "10.7.2" "Audit configuration monitoring configured" \
            "Log metrics for audit configuration changes are configured, which helps monitor audit logging mechanisms." \
            "Found $audit_metrics log metrics related to audit configuration changes." \
            "Ensure these metrics are connected to appropriate alerting policies."
    fi
    
    # Check for incident response procedures
    add_finding "MANUAL" "10.7.3" "Incident response procedures for security control failures" \
        "PCI DSS requires documented procedures for responding to failures of critical security controls." \
        "This check requires manual verification of operational procedures." \
        "Develop and document incident response procedures that address failures of critical security controls, including steps to restore security functions, document the duration and cause of failures, and implement controls to prevent recurrence."
}

# Main function
main() {
    log "Starting PCI DSS Requirement 10 assessment for GCP project..."
    
    # Check if project ID is provided as an argument
    if [[ $# -gt 0 ]]; then
        PROJECT_ID="$1"
    fi
    
    # Check gcloud installation and authentication
    check_gcloud
    
    # Initialize HTML report
    initialize_report
    
    # Perform assessments
    check_required_apis
    assess_audit_logging
    assess_log_protection
    assess_log_review
    assess_time_synchronization
    assess_critical_security_controls
    
    # Finalize HTML report
    finalize_report
    
    # Clean up temporary files
    rm -rf "$TEMP_DIR"
    
    log "Assessment completed successfully."
    echo "Report generated: $REPORT_FILE"
}

# Run the main function with all arguments
main "$@"
