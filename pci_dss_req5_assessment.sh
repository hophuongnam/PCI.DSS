#!/bin/bash
#
# PCI DSS 4.0 Requirement 5 Assessment Script
# This script assesses GCP environments for compliance with PCI DSS 4.0 Requirement 5
# (Protect All Systems and Networks from Malicious Software)
#
# Version: 1.0
# For use with Bash 3.2+ on MacOS

# Set strict error handling
set -o errexit
set -o pipefail
set -o nounset

# Global variables
PROJECT_ID=""
REPORT_FILE="pci_dss_req5_report_$(date +%Y%m%d_%H%M%S).html"
TEMP_DIR=$(mktemp -d)
LOG_FILE="${TEMP_DIR}/assessment_log.txt"
ERROR_COUNT=0
WARNING_COUNT=0
PASS_COUNT=0
TOTAL_CHECKS=0

# Color codes for terminal output
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Cleanup function to remove temporary files
cleanup() {
  echo "Cleaning up temporary files..."
  rm -rf "${TEMP_DIR}"
}

# Register the cleanup function to be called on exit
trap cleanup EXIT

# Logging functions
log_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
  echo "[INFO] $1" >> "${LOG_FILE}"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
  echo "[ERROR] $1" >> "${LOG_FILE}"
  ((ERROR_COUNT++))
}

log_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
  echo "[WARNING] $1" >> "${LOG_FILE}"
  ((WARNING_COUNT++))
}

log_success() {
  echo -e "${GREEN}[PASS]${NC} $1"
  echo "[PASS] $1" >> "${LOG_FILE}"
  ((PASS_COUNT++))
}

# Function to check if jq is installed
check_dependencies() {
  log_info "Checking dependencies..."
  
  if ! command -v jq &> /dev/null; then
    log_error "jq is not installed. Please install jq to continue."
    echo "On MacOS, you can install jq using: brew install jq"
    exit 1
  fi
  
  if ! command -v gcloud &> /dev/null; then
    log_error "gcloud CLI is not installed. Please install Google Cloud SDK to continue."
    echo "Visit https://cloud.google.com/sdk/docs/install for installation instructions."
    exit 1
  fi
  
  log_success "All dependencies are installed."
}

# Function to validate GCP authentication
validate_gcp_auth() {
  log_info "Validating GCP authentication..."
  
  if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
    log_error "Not authenticated to GCP. Please run 'gcloud auth login' first."
    exit 1
  fi
  
  # Get the active account
  local active_account
  active_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
  
  if [[ -z "${active_account}" ]]; then
    log_error "No active GCP account found. Please run 'gcloud auth login' first."
    exit 1
  fi
  
  log_success "Authenticated to GCP as ${active_account}"
}

# Function to validate and set the project ID
validate_project() {
  log_info "Validating project access..."
  
  # If PROJECT_ID is not provided, try to get the default project
  if [[ -z "${PROJECT_ID}" ]]; then
    PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
    
    if [[ -z "${PROJECT_ID}" ]]; then
      log_error "No project ID provided and no default project set. Please specify a project ID."
      exit 1
    fi
  fi
  
  # Verify the project exists and is accessible
  if ! gcloud projects describe "${PROJECT_ID}" &>/dev/null; then
    log_error "Project ${PROJECT_ID} does not exist or you don't have access to it."
    exit 1
  fi
  
  log_success "Using project: ${PROJECT_ID}"
}

# Function to safely parse JSON and handle errors
parse_json() {
  local json_file=$1
  local jq_filter=$2
  local default_value=${3:-"[]"}
  
  if [[ ! -f "${json_file}" ]]; then
    echo "${default_value}"
    return
  }
  
  # Check if the file contains valid JSON
  if ! jq empty "${json_file}" 2>/dev/null; then
    log_warning "Invalid JSON in ${json_file}"
    echo "${default_value}"
    return
  }
  
  # Apply the jq filter with a default value if the result is null or empty
  jq -r "${jq_filter} // ${default_value}" "${json_file}" 2>/dev/null || echo "${default_value}"
}

# Function to check if a service is enabled
is_service_enabled() {
  local service=$1
  
  gcloud services list --project="${PROJECT_ID}" --format="value(NAME)" 2>/dev/null | grep -q "^${service}$"
  return $?
}

# Function to get all compute instances
get_compute_instances() {
  local output_file="${TEMP_DIR}/compute_instances.json"
  
  log_info "Retrieving compute instances..."
  
  if ! is_service_enabled "compute.googleapis.com"; then
    log_info "Compute Engine API is not enabled. Skipping compute instance checks."
    echo "[]" > "${output_file}"
    return
  }
  
  # Get all instances across all zones
  if ! gcloud compute instances list --project="${PROJECT_ID}" --format=json > "${output_file}" 2>/dev/null; then
    log_warning "Failed to retrieve compute instances. Check permissions."
    echo "[]" > "${output_file}"
  }
  
  # Validate JSON output
  if ! jq empty "${output_file}" 2>/dev/null; then
    log_warning "Invalid JSON response for compute instances."
    echo "[]" > "${output_file}"
  }
}

# Function to get all GKE clusters
get_gke_clusters() {
  local output_file="${TEMP_DIR}/gke_clusters.json"
  
  log_info "Retrieving GKE clusters..."
  
  if ! is_service_enabled "container.googleapis.com"; then
    log_info "GKE API is not enabled. Skipping GKE cluster checks."
    echo "[]" > "${output_file}"
    return
  }
  
  # Get all GKE clusters
  if ! gcloud container clusters list --project="${PROJECT_ID}" --format=json > "${output_file}" 2>/dev/null; then
    log_warning "Failed to retrieve GKE clusters. Check permissions."
    echo "[]" > "${output_file}"
  }
  
  # Validate JSON output
  if ! jq empty "${output_file}" 2>/dev/null; then
    log_warning "Invalid JSON response for GKE clusters."
    echo "[]" > "${output_file}"
  }
}

# Function to get Security Command Center findings
get_scc_findings() {
  local output_file="${TEMP_DIR}/scc_findings.json"
  
  log_info "Retrieving Security Command Center findings..."
  
  if ! is_service_enabled "securitycenter.googleapis.com"; then
    log_info "Security Command Center API is not enabled. Skipping SCC findings."
    echo "[]" > "${output_file}"
    return
  }
  
  # Get SCC findings related to malware
  if ! gcloud scc findings list --project="${PROJECT_ID}" --filter="category=\"MALWARE\" OR category=\"ANTI_MALWARE\"" --format=json > "${output_file}" 2>/dev/null; then
    log_warning "Failed to retrieve Security Command Center findings. Check permissions."
    echo "[]" > "${output_file}"
  }
  
  # Validate JSON output
  if ! jq empty "${output_file}" 2>/dev/null; then
    log_warning "Invalid JSON response for SCC findings."
    echo "[]" > "${output_file}"
  }
}

# Function to get organization policies
get_org_policies() {
  local output_file="${TEMP_DIR}/org_policies.json"
  
  log_info "Retrieving organization policies..."
  
  # Get organization policies
  if ! gcloud resource-manager org-policies list --project="${PROJECT_ID}" --format=json > "${output_file}" 2>/dev/null; then
    log_warning "Failed to retrieve organization policies. Check permissions."
    echo "[]" > "${output_file}"
  }
  
  # Validate JSON output
  if ! jq empty "${output_file}" 2>/dev/null; then
    log_warning "Invalid JSON response for organization policies."
    echo "[]" > "${output_file}"
  }
}

# Function to get Cloud Logging information
get_logging_info() {
  local output_file="${TEMP_DIR}/logging_info.json"
  
  log_info "Retrieving logging information..."
  
  # Get logging sinks
  if ! gcloud logging sinks list --project="${PROJECT_ID}" --format=json > "${output_file}" 2>/dev/null; then
    log_warning "Failed to retrieve logging information. Check permissions."
    echo "[]" > "${output_file}"
  }
  
  # Validate JSON output
  if ! jq empty "${output_file}" 2>/dev/null; then
    log_warning "Invalid JSON response for logging information."
    echo "[]" > "${output_file}"
  }
}

# Function to get Cloud Monitoring information
get_monitoring_info() {
  local output_file="${TEMP_DIR}/monitoring_info.json"
  
  log_info "Retrieving monitoring information..."
  
  # Get alert policies
  if ! gcloud alpha monitoring policies list --project="${PROJECT_ID}" --format=json > "${output_file}" 2>/dev/null; then
    log_warning "Failed to retrieve monitoring information. Check permissions."
    echo "[]" > "${output_file}"
  }
  
  # Validate JSON output
  if ! jq empty "${output_file}" 2>/dev/null; then
    log_warning "Invalid JSON response for monitoring information."
    echo "[]" > "${output_file}"
  }
}

# Function to check Requirement 5.1 - Processes and mechanisms for protecting all systems and networks from malicious software
check_req_5_1() {
  local section_id="5.1"
  local section_title="Processes and mechanisms for protecting all systems and networks from malicious software are defined and understood"
  local findings=()
  
  log_info "Checking Requirement ${section_id}: ${section_title}"
  ((TOTAL_CHECKS++))
  
  # This is primarily a documentation/process check that can't be fully automated
  # We can check for indicators that suggest processes are in place
  
  # Check if Security Command Center is enabled
  if is_service_enabled "securitycenter.googleapis.com"; then
    findings+=("Security Command Center is enabled, which suggests security processes may be defined.")
    log_success "Security Command Center is enabled, which can help with security process implementation."
  else
    findings+=("Security Command Center is not enabled. Consider enabling it to help with security monitoring and process implementation.")
    log_warning "Security Command Center is not enabled. This service can help with security monitoring."
  fi
  
  # Check if Cloud Asset Inventory is enabled
  if is_service_enabled "cloudasset.googleapis.com"; then
    findings+=("Cloud Asset Inventory is enabled, which can help track security-relevant assets.")
    log_success "Cloud Asset Inventory is enabled, which can help track security-relevant assets."
  else
    findings+=("Cloud Asset Inventory is not enabled. Consider enabling it to help track security-relevant assets.")
    log_warning "Cloud Asset Inventory is not enabled. This service can help track security-relevant assets."
  fi
  
  # Return findings for the report
  echo "${section_id}|${section_title}|WARNING|${findings[*]}"
}

# Function to check Requirement 5.2 - Malicious software (malware) is prevented, or detected and addressed
check_req_5_2() {
  local section_id="5.2"
  local section_title="Malicious software (malware) is prevented, or detected and addressed"
  local findings=()
  
  log_info "Checking Requirement ${section_id}: ${section_title}"
  ((TOTAL_CHECKS++))
  
  # Check if Security Command Center is enabled with threat detection
  if is_service_enabled "securitycenter.googleapis.com"; then
    # Check if Event Threat Detection is enabled
    local scc_findings="${TEMP_DIR}/scc_findings.json"
    if [[ -f "${scc_findings}" ]]; then
      local malware_findings
      malware_findings=$(parse_json "${scc_findings}" "length")
      
      if [[ "${malware_findings}" != "0" ]]; then
        findings+=("Security Command Center has detected ${malware_findings} malware-related findings that need to be addressed.")
        log_warning "Security Command Center has detected ${malware_findings} malware-related findings."
      else
        findings+=("Security Command Center is monitoring for malware threats. No current malware findings detected.")
        log_success "Security Command Center is monitoring for malware threats. No current findings."
      fi
    fi
  else
    findings+=("Security Command Center is not enabled. Consider enabling it with Event Threat Detection for malware protection.")
    log_warning "Security Command Center is not enabled. Consider enabling it with Event Threat Detection."
  fi
  
  # Check GKE clusters for node auto-upgrade and GKE sandbox
  local gke_clusters="${TEMP_DIR}/gke_clusters.json"
  if [[ -f "${gke_clusters}" ]]; then
    local clusters_count
    clusters_count=$(parse_json "${gke_clusters}" "length")
    
    if [[ "${clusters_count}" != "0" ]]; then
      local non_autoupgrade_clusters
      non_autoupgrade_clusters=$(parse_json "${gke_clusters}" '[.[] | select(.nodeConfig.enableAutoUpgrade == false or .nodeConfig.enableAutoUpgrade == null) | .name] | join(", ")')
      
      if [[ -n "${non_autoupgrade_clusters}" ]]; then
        findings+=("The following GKE clusters do not have node auto-upgrade enabled, which may leave them vulnerable to malware: ${non_autoupgrade_clusters}")
        log_warning "GKE clusters without node auto-upgrade: ${non_autoupgrade_clusters}"
      else
        findings+=("All GKE clusters have node auto-upgrade enabled, which helps protect against vulnerabilities.")
        log_success "All GKE clusters have node auto-upgrade enabled."
      fi
      
      # Check for GKE Sandbox (gVisor)
      local non_sandbox_clusters
      non_sandbox_clusters=$(parse_json "${gke_clusters}" '[.[] | select(.nodeConfig.sandboxConfig.type != "gvisor" and .nodeConfig.sandboxConfig == null) | .name] | join(", ")')
      
      if [[ -n "${non_sandbox_clusters}" ]]; then
        findings+=("Consider enabling GKE Sandbox (gVisor) for additional protection on these clusters: ${non_sandbox_clusters}")
        log_warning "GKE clusters without GKE Sandbox: ${non_sandbox_clusters}"
      else
        findings+=("GKE Sandbox (gVisor) is enabled on applicable clusters, providing additional protection.")
        log_success "GKE Sandbox is enabled on applicable clusters."
      fi
    fi
  fi
  
  # Check Compute Engine instances for Shielded VM
  local compute_instances="${TEMP_DIR}/compute_instances.json"
  if [[ -f "${compute_instances}" ]]; then
    local instances_count
    instances_count=$(parse_json "${compute_instances}" "length")
    
    if [[ "${instances_count}" != "0" ]]; then
      local non_shielded_vms
      non_shielded_vms=$(parse_json "${compute_instances}" '[.[] | select(.shieldedInstanceConfig == null or .shieldedInstanceConfig.enableVtpm == false or .shieldedInstanceConfig.enableIntegrityMonitoring == false) | .name] | join(", ")')
      
      if [[ -n "${non_shielded_vms}" ]]; then
        findings+=("The following VMs are not configured as Shielded VMs or have incomplete protection: ${non_shielded_vms}")
        log_warning "VMs without Shielded VM protection: ${non_shielded_vms}"
      else
        findings+=("All VMs are configured as Shielded VMs with integrity monitoring, which helps protect against rootkits and bootkits.")
        log_success "All VMs are configured as Shielded VMs with integrity monitoring."
      fi
    fi
  fi
  
  # Return findings for the report
  echo "${section_id}|${section_title}|WARNING|${findings[*]}"
}

# Function to check Requirement 5.3 - Anti-malware mechanisms and processes are active, maintained, and monitored
check_req_5_3() {
  local section_id="5.3"
  local section_title="Anti-malware mechanisms and processes are active, maintained, and monitored"
  local findings=()
  
  log_info "Checking Requirement ${section_id}: ${section_title}"
  ((TOTAL_CHECKS++))
  
  # Check for OS Login which helps with account management
  local compute_instances="${TEMP_DIR}/compute_instances.json"
  if [[ -f "${compute_instances}" ]]; then
    local instances_count
    instances_count=$(parse_json "${compute_instances}" "length")
    
    if [[ "${instances_count}" != "0" ]]; then
      local non_oslogin_vms
      non_oslogin_vms=$(parse_json "${compute_instances}" '[.[] | select(.metadata.items == null or (.metadata.items | map(select(.key == "enable-oslogin" and .value == "TRUE")) | length == 0)) | .name] | join(", ")')
      
      if [[ -n "${non_oslogin_vms}" ]]; then
        findings+=("The following VMs do not have OS Login enabled, which may make user management more difficult: ${non_oslogin_vms}")
        log_warning "VMs without OS Login enabled: ${non_oslogin_vms}"
      else
        findings+=("OS Login is enabled on all VMs, which helps with centralized user management and security.")
        log_success "OS Login is enabled on all VMs."
      fi
    fi
  fi
  
  # Check for logging and monitoring
  local logging_info="${TEMP_DIR}/logging_info.json"
  if [[ -f "${logging_info}" ]]; then
    local sinks_count
    sinks_count=$(parse_json "${logging_info}" "length")
    
    if [[ "${sinks_count}" == "0" ]]; then
      findings+=("No logging sinks configured. Consider setting up logging exports for security analysis.")
      log_warning "No logging sinks configured."
    else
      findings+=("Logging sinks are configured, which can help with security monitoring and analysis.")
      log_success "Logging sinks are configured."
    fi
  fi
  
  # Check for monitoring alerts
  local monitoring_info="${TEMP_DIR}/monitoring_info.json"
  if [[ -f "${monitoring_info}" ]]; then
    local alerts_count
    alerts_count=$(parse_json "${monitoring_info}" "length")
    
    if [[ "${alerts_count}" == "0" ]]; then
      findings+=("No monitoring alert policies configured. Consider setting up alerts for security events.")
      log_warning "No monitoring alert policies configured."
    else
      findings+=("Monitoring alert policies are configured, which can help with security incident detection.")
      log_success "Monitoring alert policies are configured."
    fi
  fi
  
  # Check if Cloud Security Scanner is enabled
  if is_service_enabled "websecurityscanner.googleapis.com"; then
    findings+=("Cloud Security Scanner is enabled, which can help detect vulnerabilities in web applications.")
    log_success "Cloud Security Scanner is enabled."
  } else {
    findings+=("Cloud Security Scanner is not enabled. Consider enabling it to scan for vulnerabilities in web applications.")
    log_warning "Cloud Security Scanner is not enabled."
  }
  
  # Return findings for the report
  echo "${section_id}|${section_title}|WARNING|${findings[*]}"
}

# Function to check Requirement 5.4 - Anti-phishing mechanisms protect users against phishing attacks
check_req_5_4() {
  local section_id="5.4"
  local section_title="Anti-phishing mechanisms protect users against phishing attacks"
  local findings=()
  
  log_info "Checking Requirement ${section_id}: ${section_title}"
  ((TOTAL_CHECKS++))
  
  # Check if Gmail or Google Workspace integration is used (can't directly check via API)
  findings+=("This requirement primarily relates to email protection and user training. If using Gmail or Google Workspace, ensure advanced phishing and malware protection is enabled.")
  log_info "Requirement 5.4 primarily relates to email protection and user training."
  
  # Check if Security Command Center Premium is enabled (which includes Web Security Scanner)
  if is_service_enabled "securitycenter.googleapis.com"; then
    # We can't directly check the tier via gcloud, but we can check for premium features
    if is_service_enabled "websecurityscanner.googleapis.com"; then
      findings+=("Web Security Scanner is enabled, which can help detect some phishing-related vulnerabilities in web applications.")
      log_success "Web Security Scanner is enabled."
    } else {
      findings+=("Consider enabling Web Security Scanner to help detect some phishing-related vulnerabilities in web applications.")
      log_warning "Web Security Scanner is not enabled."
    }
  } else {
    findings+=("Security Command Center is not enabled. Consider enabling it with premium features for enhanced security protection.")
    log_warning "Security Command Center is not enabled."
  }
  
  # Check for IAP (Identity-Aware Proxy) which can help protect against phishing
  if is_service_enabled "iap.googleapis.com"; then
    findings+=("Identity-Aware Proxy (IAP) is enabled, which can help protect applications against phishing attacks.")
    log_success "Identity-Aware Proxy (IAP) is enabled."
  } else {
    findings+=("Consider enabling Identity-Aware Proxy (IAP) to help protect applications against phishing attacks.")
    log_warning "Identity-Aware Proxy (IAP) is not enabled."
  }
  
  # Return findings for the report
  echo "${section_id}|${section_title}|WARNING|${findings[*]}"
}

# Function to generate HTML report
generate_html_report() {
  local report_data=$1
  
  log_info "Generating HTML report..."
  
  # Create HTML header
  cat > "${REPORT_FILE}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PCI DSS 4.0 Requirement 5 Assessment Report</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      margin: 0;
      padding: 20px;
      color: #333;
    }
    h1, h2, h3 {
      color: #2c3e50;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    .header {
      background-color: #2c3e50;
      color: white;
      padding: 20px;
      margin-bottom: 20px;
      border-radius: 5px;
    }
    .summary {
      background-color: #f8f9fa;
      padding: 15px;
      margin-bottom: 20px;
      border-radius: 5px;
      border-left: 5px solid #2c3e50;
    }
    .requirement {
      margin-bottom: 30px;
      padding: 15px;
      border-radius: 5px;
      background-color: #f8f9fa;
    }
    .requirement-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }
    .requirement-id {
      font-weight: bold;
      min-width: 50px;
    }
    .requirement-title {
      flex-grow: 1;
      margin-left: 10px;
    }
    .status {
      padding: 5px 10px;
      border-radius: 3px;
      font-weight: bold;
      text-align: center;
      min-width: 80px;
    }
    .status-pass {
      background-color: #d4edda;
      color: #155724;
    }
    .status-warning {
      background-color: #fff3cd;
      color: #856404;
    }
    .status-fail {
      background-color: #f8d7da;
      color: #721c24;
    }
    .findings {
      margin-top: 10px;
      padding: 10px;
      background-color: white;
      border-radius: 3px;
    }
    .finding {
      margin-bottom: 5px;
      padding-left: 20px;
      position: relative;
    }
    .finding:before {
      content: "•";
      position: absolute;
      left: 5px;
    }
    .chart-container {
      display: flex;
      justify-content: space-around;
      margin-bottom: 30px;
    }
    .chart {
      width: 200px;
      height: 200px;
      position: relative;
    }
    .recommendations {
      background-color: #e2f0d9;
      padding: 15px;
      border-radius: 5px;
      margin-top: 20px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 20px;
    }
    th, td {
      padding: 12px 15px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }
    th {
      background-color: #2c3e50;
      color: white;
    }
    tr:hover {
      background-color: #f5f5f5;
    }
    .footer {
      margin-top: 30px;
      text-align: center;
      font-size: 0.8em;
      color: #777;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>PCI DSS 4.0 Requirement 5 Assessment Report</h1>
      <p>Project ID: ${PROJECT_ID}</p>
      <p>Date: $(date '+%Y-%m-%d %H:%M:%S')</p>
    </div>
    
    <div class="summary">
      <h2>Executive Summary</h2>
      <p>This report presents the findings of an automated assessment of Google Cloud Platform (GCP) environment against PCI DSS 4.0 Requirement 5: Protect All Systems and Networks from Malicious Software.</p>
      <p>The assessment evaluated the configuration and security controls in place to prevent, detect, and address malicious software in the GCP environment.</p>
      
      <div class="chart-container">
        <div>
          <h3>Assessment Results</h3>
          <table>
            <tr>
              <th>Status</th>
              <th>Count</th>
              <th>Percentage</th>
            </tr>
            <tr>
              <td>Pass</td>
              <td>${PASS_COUNT}</td>
              <td>$(( TOTAL_CHECKS > 0 ? PASS_COUNT * 100 / TOTAL_CHECKS : 0 ))%</td>
            </tr>
            <tr>
              <td>Warning</td>
              <td>${WARNING_COUNT}</td>
              <td>$(( TOTAL_CHECKS > 0 ? WARNING_COUNT * 100 / TOTAL_CHECKS : 0 ))%</td>
            </tr>
            <tr>
              <td>Fail</td>
              <td>${ERROR_COUNT}</td>
              <td>$(( TOTAL_CHECKS > 0 ? ERROR_COUNT * 100 / TOTAL_CHECKS : 0 ))%</td>
            </tr>
            <tr>
              <td><strong>Total</strong></td>
              <td><strong>${TOTAL_CHECKS}</strong></td>
              <td><strong>100%</strong></td>
            </tr>
          </table>
        </div>
      </div>
    </div>
    
    <h2>Detailed Findings</h2>
EOF

  # Process each requirement section
  echo "${report_data}" | while IFS='|' read -r req_id req_title status findings; do
    local status_class="status-warning"
    if [[ "${status}" == "PASS" ]]; then
      status_class="status-pass"
    elif [[ "${status}" == "FAIL" ]]; then
      status_class="status-fail"
    fi
    
    # Add requirement section to the report
    cat >> "${REPORT_FILE}" << EOF
    <div class="requirement">
      <div class="requirement-header">
        <div class="requirement-id">${req_id}</div>
        <div class="requirement-title">${req_title}</div>
        <div class="status ${status_class}">${status}</div>
      </div>
      <div class="findings">
EOF

    # Add each finding as a bullet point
    IFS='. ' read -ra FINDINGS_ARRAY <<< "${findings}"
    for finding in "${FINDINGS_ARRAY[@]}"; do
      if [[ -n "${finding}" ]]; then
        echo "        <div class=\"finding\">${finding}.</div>" >> "${REPORT_FILE}"
      fi
    done

    # Add recommendations based on the requirement
    cat >> "${REPORT_FILE}" << EOF
      </div>
      <div class="recommendations">
        <h4>Recommendations for PCI DSS Requirement ${req_id}</h4>
EOF

    # Add specific recommendations based on the requirement ID
    case "${req_id}" in
      "5.1")
        cat >> "${REPORT_FILE}" << EOF
        <ul>
          <li>Document all security policies and operational procedures for anti-malware controls.</li>
          <li>Ensure policies are kept up to date and known to all affected parties.</li>
          <li>Enable Security Command Center for enhanced security monitoring.</li>
          <li>Clearly define roles and responsibilities for anti-malware management.</li>
        </ul>
EOF
        ;;
      "5.2")
        cat >> "${REPORT_FILE}" << EOF
        <ul>
          <li>Deploy anti-malware solutions on all system components, or document why certain components don't need it.</li>
          <li>Enable Security Command Center with Event Threat Detection.</li>
          <li>Enable Shielded VMs for all Compute Engine instances.</li>
          <li>Enable GKE node auto-upgrades and consider using GKE Sandbox for additional protection.</li>
          <li>Periodically evaluate systems not at risk for malware and document the evaluation.</li>
        </ul>
EOF
        ;;
      "5.3")
        cat >> "${REPORT_FILE}" << EOF
        <ul>
          <li>Ensure anti-malware solutions are kept current via automatic updates.</li>
          <li>Configure periodic scans and real-time protection.</li>
          <li>Set up logging and monitoring for anti-malware activities.</li>
          <li>Ensure users cannot disable or alter anti-malware protections.</li>
          <li>Enable OS Login for centralized user management.</li>
          <li>Configure logging exports and monitoring alerts for security events.</li>
        </ul>
EOF
        ;;
      "5.4")
        cat >> "${REPORT_FILE}" << EOF
        <ul>
          <li>Implement anti-phishing mechanisms to protect users.</li>
          <li>If using Gmail or Google Workspace, enable advanced phishing and malware protection.</li>
          <li>Enable Identity-Aware Proxy (IAP) to protect applications.</li>
          <li>Implement security awareness training for personnel about phishing attacks.</li>
          <li>Enable Web Security Scanner to detect vulnerabilities in web applications.</li>
        </ul>
EOF
        ;;
    esac

    # Close the requirement section
    cat >> "${REPORT_FILE}" << EOF
      </div>
    </div>
EOF
  done

  # Add footer to the report
  cat >> "${REPORT_FILE}" << EOF
    <div class="footer">
      <p>This report was generated automatically and should be reviewed by a qualified security professional.</p>
      <p>PCI DSS 4.0 Requirement 5 Assessment Tool - Generated on $(date '+%Y-%m-%d %H:%M:%S')</p>
    </div>
  </div>
</body>
</html>
EOF

  log_success "HTML report generated: ${REPORT_FILE}"
}

# Main function
main() {
  echo "PCI DSS 4.0 Requirement 5 Assessment Tool"
  echo "=========================================="
  
  # Parse command line arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --project=*)
        PROJECT_ID="${1#*=}"
        shift
        ;;
      --output=*)
        REPORT_FILE="${1#*=}"
        shift
        ;;
      --help)
        echo "Usage: $0 [--project=PROJECT_ID] [--output=REPORT_FILE]"
        echo ""
        echo "Options:"
        echo "  --project=PROJECT_ID    GCP project ID to assess (default: current gcloud config)"
        echo "  --output=REPORT_FILE    Output HTML report file (default: pci_dss_req5_report_YYYYMMDD_HHMMSS.html)"
        echo "  --help                  Show this help message"
        exit 0
        ;;
      *)
        echo "Unknown option: $1"
        echo "Use --help for usage information."
        exit 1
        ;;
    esac
  done
  
  # Check dependencies
  check_dependencies
  
  # Validate GCP authentication
  validate_gcp_auth
  
  # Validate and set project
  validate_project
  
  # Collect data
  get_compute_instances
  get_gke_clusters
  get_scc_findings
  get_org_policies
  get_logging_info
  get_monitoring_info
  
  # Run checks and collect results
  local report_data=""
  report_data+="$(check_req_5_1)\n"
  report_data+="$(check_req_5_2)\n"
  report_data+="$(check_req_5_3)\n"
  report_data+="$(check_req_5_4)\n"
  
  # Generate HTML report
  generate_html_report "${report_data}"
  
  # Print summary
  echo ""
  echo "Assessment Summary:"
  echo "-------------------"
  echo "Total checks: ${TOTAL_CHECKS}"
  echo "Passed: ${PASS_COUNT}"
  echo "Warnings: ${WARNING_COUNT}"
  echo "Failed: ${ERROR_COUNT}"
  echo ""
  echo "Report generated: ${REPORT_FILE}"
  
  # Open the report if on macOS
  if [[ "$(uname)" == "Darwin" ]]; then
    open "${REPORT_FILE}"
  else
    echo "You can view the report by opening ${REPORT_FILE} in a web browser."
  fi
}

# Run the main function
main "$@"
