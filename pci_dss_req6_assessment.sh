#!/bin/bash
#
# PCI DSS v4.0 Requirement 6 Assessment Script for Google Cloud Platform
# This script assesses GCP environments for compliance with PCI DSS v4.0 Requirement 6:
# "Develop and Maintain Secure Systems and Software"
#

# Set strict error handling
set -o pipefail

# Global variables
PROJECT_ID=""
REPORT_FILE="pci_dss_req6_report.html"
TEMP_DIR=$(mktemp -d)
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
TOTAL_PASS=0
TOTAL_WARN=0
TOTAL_FAIL=0

# Color codes for terminal output
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to display usage information
usage() {
  echo "Usage: $0 -p PROJECT_ID [-o OUTPUT_FILE]"
  echo "  -p PROJECT_ID    GCP Project ID to assess"
  echo "  -o OUTPUT_FILE   Output HTML report file (default: pci_dss_req6_report.html)"
  echo "  -h               Display this help message"
  exit 1
}

# Function to log messages
log() {
  local level=$1
  local message=$2
  
  case $level in
    "INFO")
      echo -e "[INFO] $message"
      ;;
    "WARN")
      echo -e "${YELLOW}[WARN] $message${NC}"
      ;;
    "ERROR")
      echo -e "${RED}[ERROR] $message${NC}" >&2
      ;;
    "SUCCESS")
      echo -e "${GREEN}[SUCCESS] $message${NC}"
      ;;
    *)
      echo -e "$message"
      ;;
  esac
}

# Function to clean up temporary files
cleanup() {
  log "INFO" "Cleaning up temporary files..."
  rm -rf "$TEMP_DIR"
}

# Set trap for cleanup on exit
trap cleanup EXIT

# Function to validate JSON
validate_json() {
  local json_file=$1
  local default_value=${2:-"[]"}
  
  if [[ ! -f "$json_file" ]]; then
    echo "$default_value"
    return 1
  fi
  
  # Check if file contains valid JSON
  if ! jq empty "$json_file" 2>/dev/null; then
    echo "$default_value"
    return 1
  fi
  
  # Return the content
  cat "$json_file"
  return 0
}

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to verify GCP authentication and project access
verify_gcp_access() {
  log "INFO" "Verifying GCP authentication and access to project $PROJECT_ID..."
  
  # Check if gcloud is installed
  if ! command_exists gcloud; then
    log "ERROR" "gcloud CLI is not installed. Please install it and try again."
    exit 1
  fi
  
  # Check if jq is installed
  if ! command_exists jq; then
    log "ERROR" "jq is not installed. Please install it and try again."
    exit 1
  fi
  
  # Verify authentication
  if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" > /dev/null 2>&1; then
    log "ERROR" "Not authenticated to GCP. Please run 'gcloud auth login' and try again."
    exit 1
  fi
  
  # Verify project access
  if ! gcloud projects describe "$PROJECT_ID" --format=json > "$TEMP_DIR/project_info.json" 2>/dev/null; then
    log "ERROR" "Cannot access project $PROJECT_ID. Please check if the project exists and you have sufficient permissions."
    exit 1
  fi
  
  PROJECT_NAME=$(jq -r '.name' "$TEMP_DIR/project_info.json")
  log "SUCCESS" "Successfully authenticated and verified access to project: $PROJECT_NAME ($PROJECT_ID)"
}

# Function to initialize HTML report
initialize_html_report() {
  cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PCI DSS v4.0 Requirement 6 Assessment Report - $PROJECT_ID</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      margin: 0;
      padding: 20px;
      color: #333;
    }
    h1, h2, h3, h4 {
      color: #2c3e50;
    }
    .header {
      background-color: #34495e;
      color: white;
      padding: 20px;
      margin-bottom: 20px;
    }
    .summary {
      display: flex;
      justify-content: space-between;
      margin-bottom: 30px;
    }
    .summary-box {
      flex: 1;
      margin: 10px;
      padding: 15px;
      border-radius: 5px;
      text-align: center;
    }
    .pass {
      background-color: #e6ffe6;
      border: 1px solid #99cc99;
    }
    .warning {
      background-color: #ffffcc;
      border: 1px solid #ffcc66;
    }
    .fail {
      background-color: #ffe6e6;
      border: 1px solid #cc9999;
    }
    .finding {
      margin-bottom: 20px;
      padding: 15px;
      border-radius: 5px;
    }
    .finding h3 {
      margin-top: 0;
    }
    .finding-critical {
      background-color: #ffe6e6;
      border-left: 5px solid #cc0000;
    }
    .finding-warning {
      background-color: #ffffcc;
      border-left: 5px solid #ffcc00;
    }
    .finding-pass {
      background-color: #e6ffe6;
      border-left: 5px solid #00cc00;
    }
    .details {
      margin-top: 10px;
      padding: 10px;
      background-color: #f9f9f9;
      border-radius: 3px;
    }
    .recommendation {
      margin-top: 10px;
      font-style: italic;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
    }
    table, th, td {
      border: 1px solid #ddd;
    }
    th, td {
      padding: 12px;
      text-align: left;
    }
    th {
      background-color: #f2f2f2;
    }
    tr:nth-child(even) {
      background-color: #f9f9f9;
    }
    .footer {
      margin-top: 30px;
      padding-top: 10px;
      border-top: 1px solid #ddd;
      font-size: 0.8em;
      color: #777;
    }
    pre {
      background-color: #f5f5f5;
      padding: 10px;
      border-radius: 3px;
      overflow-x: auto;
    }
    code {
      font-family: monospace;
      background-color: #f5f5f5;
      padding: 2px 4px;
      border-radius: 3px;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>PCI DSS v4.0 Requirement 6 Assessment Report</h1>
    <p>Project: $PROJECT_NAME ($PROJECT_ID)</p>
    <p>Assessment Date: $TIMESTAMP</p>
  </div>
  
  <h2>Executive Summary</h2>
  <p>This report presents the findings of an automated assessment of Google Cloud Platform configurations against PCI DSS v4.0 Requirement 6: "Develop and Maintain Secure Systems and Software". The assessment evaluates the security posture of cloud resources and identifies potential compliance gaps.</p>
  
  <div id="summary-placeholder"></div>
  
  <h2>Detailed Findings</h2>
EOF
}

# Function to add a finding to the HTML report
add_finding() {
  local severity=$1
  local requirement=$2
  local title=$3
  local details=$4
  local recommendation=$5
  
  # Update counters
  case $severity in
    "PASS")
      ((TOTAL_PASS++))
      ;;
    "WARNING")
      ((TOTAL_WARN++))
      ;;
    "CRITICAL")
      ((TOTAL_FAIL++))
      ;;
  esac
  
  # Map severity to CSS class
  local severity_class
  case $severity in
    "PASS")
      severity_class="finding-pass"
      ;;
    "WARNING")
      severity_class="finding-warning"
      ;;
    "CRITICAL")
      severity_class="finding-critical"
      ;;
  esac
  
  # Escape HTML special characters in details
  details=$(echo "$details" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g')
  
  # Add finding to report
  cat >> "$REPORT_FILE" << EOF
  <div class="finding $severity_class">
    <h3>$title</h3>
    <p><strong>PCI DSS Requirement:</strong> $requirement</p>
    <p><strong>Severity:</strong> $severity</p>
    <div class="details">
      <p>$details</p>
    </div>
    <div class="recommendation">
      <strong>Recommendation:</strong> $recommendation
    </div>
  </div>
EOF
}

# Function to finalize HTML report
finalize_html_report() {
  # Add summary statistics
  local summary=$(cat << EOF
  <div class="summary">
    <div class="summary-box pass">
      <h3>Pass</h3>
      <p>$TOTAL_PASS</p>
    </div>
    <div class="summary-box warning">
      <h3>Warning</h3>
      <p>$TOTAL_WARN</p>
    </div>
    <div class="summary-box fail">
      <h3>Critical</h3>
      <p>$TOTAL_FAIL</p>
    </div>
  </div>
EOF
)

  # Add footer
  cat >> "$REPORT_FILE" << EOF
  <div class="footer">
    <p>This report was generated automatically by the PCI DSS v4.0 GCP Assessment Tool.</p>
    <p>Assessment completed on $TIMESTAMP</p>
  </div>
</body>
</html>
EOF

  # Insert summary after placeholder
  sed -i.bak "s|<div id=\"summary-placeholder\"></div>|$summary|" "$REPORT_FILE"
  rm "${REPORT_FILE}.bak"
  
  log "SUCCESS" "Assessment complete. Report generated: $REPORT_FILE"
  log "INFO" "Summary: $TOTAL_PASS Pass, $TOTAL_WARN Warning, $TOTAL_FAIL Critical"
}

# Function to check for secure development practices (Requirement 6.2)
check_secure_development() {
  log "INFO" "Checking for secure development practices (Requirement 6.2)..."
  
  # Check for Cloud Source Repositories
  gcloud source repos list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/source_repos.json" 2>/dev/null
  local repos=$(validate_json "$TEMP_DIR/source_repos.json")
  
  if [[ $(echo "$repos" | jq 'length') -gt 0 ]]; then
    add_finding "WARNING" "6.2.1" "Source Code Repositories Found" \
      "Cloud Source Repositories are in use. Ensure these repositories follow secure development practices according to PCI DSS requirements." \
      "Implement secure coding guidelines, code reviews, and security testing for all code in these repositories. Document your secure development lifecycle and ensure it addresses all points in Requirement 6.2.1."
  else
    add_finding "PASS" "6.2.1" "No Source Code Repositories Found" \
      "No Cloud Source Repositories were found in this project. If you're using external repositories, ensure they follow secure development practices." \
      "If you use external code repositories, implement secure coding guidelines, code reviews, and security testing for all code in those repositories."
  fi
  
  # Check for Cloud Build configurations
  gcloud builds triggers list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/build_triggers.json" 2>/dev/null
  local triggers=$(validate_json "$TEMP_DIR/build_triggers.json")
  
  if [[ $(echo "$triggers" | jq 'length') -gt 0 ]]; then
    # Check for security scanning steps in build configs
    local security_scan_count=$(echo "$triggers" | jq '[.[] | select(.filename != null and (.filename | contains("security") or .filename | contains("scan") or .filename | contains("test")))] | length')
    
    if [[ $security_scan_count -gt 0 ]]; then
      add_finding "PASS" "6.2.3" "Security Testing in CI/CD Pipeline" \
        "Cloud Build triggers with potential security testing steps were found. Verify these steps include proper code reviews and security testing." \
        "Ensure your CI/CD pipeline includes automated security testing, vulnerability scanning, and code quality checks before deployment to production."
    else
      add_finding "WARNING" "6.2.3" "No Security Testing in CI/CD Pipeline" \
        "Cloud Build triggers were found, but no evidence of security testing steps was detected in the build configurations." \
        "Implement security testing steps in your CI/CD pipeline, including vulnerability scanning, SAST/DAST, and code quality checks before deployment to production."
    fi
  else
    add_finding "WARNING" "6.2.3" "No CI/CD Pipeline Detected" \
      "No Cloud Build triggers were found. If you're using CI/CD, ensure it includes security testing steps." \
      "If you use CI/CD pipelines (either in GCP or external), implement security testing steps including vulnerability scanning, SAST/DAST, and code quality checks."
  fi
}

# Function to check for vulnerability management (Requirement 6.3)
check_vulnerability_management() {
  log "INFO" "Checking for vulnerability management (Requirement 6.3)..."
  
  # Check if Security Command Center is enabled
  gcloud services list --project="$PROJECT_ID" --format="json" | jq '.[] | select(.config.name | contains("securitycenter"))' > "$TEMP_DIR/scc_enabled.json" 2>/dev/null
  local scc_enabled=$(validate_json "$TEMP_DIR/scc_enabled.json" "{}")
  
  if [[ $(echo "$scc_enabled" | jq 'length') -gt 0 ]]; then
    add_finding "PASS" "6.3.1" "Security Command Center Enabled" \
      "Security Command Center is enabled, which can help identify security vulnerabilities in your GCP environment." \
      "Ensure you regularly review Security Command Center findings and have a process to address identified vulnerabilities based on risk ranking."
  else
    add_finding "WARNING" "6.3.1" "Security Command Center Not Enabled" \
      "Security Command Center does not appear to be enabled. This service helps identify security vulnerabilities in your GCP environment." \
      "Enable Security Command Center to automatically identify vulnerabilities in your GCP resources. Implement a process to regularly review findings and address vulnerabilities based on risk ranking."
  fi
  
  # Check for Container Registry vulnerability scanning
  gcloud services list --project="$PROJECT_ID" --format="json" | jq '.[] | select(.config.name | contains("containeranalysis"))' > "$TEMP_DIR/container_analysis.json" 2>/dev/null
  local container_analysis=$(validate_json "$TEMP_DIR/container_analysis.json" "{}")
  
  if [[ $(echo "$container_analysis" | jq 'length') -gt 0 ]]; then
    # Check if Artifact Analysis is configured
    gcloud container images list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/container_images.json" 2>/dev/null
    local container_images=$(validate_json "$TEMP_DIR/container_images.json")
    
    if [[ $(echo "$container_images" | jq 'length') -gt 0 ]]; then
      add_finding "PASS" "6.3.2" "Container Vulnerability Scanning Available" \
        "Container Analysis API is enabled and container images are present. Ensure vulnerability scanning is enabled for these images." \
        "Configure Artifact Analysis to automatically scan container images for vulnerabilities and ensure findings are addressed before deployment."
    else
      add_finding "PASS" "6.3.2" "Container Analysis API Enabled" \
        "Container Analysis API is enabled, but no container images were found in this project." \
        "If you use container images in other projects or registries, ensure vulnerability scanning is enabled for those images."
    fi
  else
    add_finding "WARNING" "6.3.2" "Container Vulnerability Scanning Not Configured" \
      "Container Analysis API does not appear to be enabled. This service helps identify vulnerabilities in container images." \
      "Enable Container Analysis API and configure vulnerability scanning for your container images to identify and address security issues before deployment."
  fi
  
  # Check for OS patch management
  gcloud compute instances list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/compute_instances.json" 2>/dev/null
  local compute_instances=$(validate_json "$TEMP_DIR/compute_instances.json")
  
  if [[ $(echo "$compute_instances" | jq 'length') -gt 0 ]]; then
    # Check for OS Config API
    gcloud services list --project="$PROJECT_ID" --format="json" | jq '.[] | select(.config.name | contains("osconfig"))' > "$TEMP_DIR/osconfig.json" 2>/dev/null
    local osconfig=$(validate_json "$TEMP_DIR/osconfig.json" "{}")
    
    if [[ $(echo "$osconfig" | jq 'length') -gt 0 ]]; then
      # Check for patch deployment jobs
      gcloud compute os-config patch-jobs list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/patch_jobs.json" 2>/dev/null
      local patch_jobs=$(validate_json "$TEMP_DIR/patch_jobs.json")
      
      if [[ $(echo "$patch_jobs" | jq 'length') -gt 0 ]]; then
        add_finding "PASS" "6.3.3" "OS Patch Management Configured" \
          "OS Config API is enabled and patch jobs are configured for VM instances." \
          "Ensure patch jobs are scheduled regularly and critical security patches are applied within one month of release as required by PCI DSS."
      else
        add_finding "WARNING" "6.3.3" "OS Patch Management Not Fully Configured" \
          "OS Config API is enabled, but no patch jobs were found. Patch management is required for PCI DSS compliance." \
          "Configure OS Config patch jobs to automatically apply security patches to your VM instances. Critical patches must be applied within one month of release."
      fi
    else
      add_finding "CRITICAL" "6.3.3" "OS Patch Management Not Configured" \
        "VM instances exist but OS Config API is not enabled. Patch management is required for PCI DSS compliance." \
        "Enable OS Config API and configure patch jobs to automatically apply security patches to your VM instances. Critical patches must be applied within one month of release."
    fi
  else
    add_finding "PASS" "6.3.3" "No VM Instances Found" \
      "No VM instances were found in this project. If you use VMs in other projects, ensure patch management is configured for those instances." \
      "If you use VM instances in other projects, enable OS Config API and configure patch jobs to automatically apply security patches."
  fi
}

# Function to check for web application security (Requirement 6.4)
check_web_application_security() {
  log "INFO" "Checking for web application security (Requirement 6.4)..."
  
  # Check for Cloud Armor
  gcloud compute security-policies list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/security_policies.json" 2>/dev/null
  local security_policies=$(validate_json "$TEMP_DIR/security_policies.json")
  
  if [[ $(echo "$security_policies" | jq 'length') -gt 0 ]]; then
    # Check for WAF rules
    local waf_rules=$(echo "$security_policies" | jq '[.[] | select(.rules[] | select(.match.expr.expression | contains("xss") or contains("sqli") or contains("owasp")))] | length')
    
    if [[ $waf_rules -gt 0 ]]; then
      add_finding "PASS" "6.4.1" "Web Application Firewall Configured" \
        "Cloud Armor security policies with WAF rules are configured, which can help protect web applications from common attacks." \
        "Ensure Cloud Armor policies are applied to all public-facing web applications and include protection against all common attack types listed in Requirement 6.2.4."
    else
      add_finding "WARNING" "6.4.1" "Web Application Firewall Missing Attack Signatures" \
        "Cloud Armor security policies exist but may not include rules for common web application attacks." \
        "Configure Cloud Armor security policies with predefined rules to protect against common web application attacks like XSS, SQL injection, and other OWASP Top 10 vulnerabilities."
    fi
  else
    # Check if there are load balancers that might need protection
    gcloud compute forwarding-rules list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/forwarding_rules.json" 2>/dev/null
    local forwarding_rules=$(validate_json "$TEMP_DIR/forwarding_rules.json")
    
    if [[ $(echo "$forwarding_rules" | jq 'length') -gt 0 ]]; then
      add_finding "CRITICAL" "6.4.1" "Web Application Firewall Not Configured" \
        "Load balancers exist but no Cloud Armor security policies were found. Public-facing web applications require protection against common attacks." \
        "Implement Cloud Armor security policies with WAF rules to protect public-facing web applications from common attacks like XSS, SQL injection, and other OWASP Top 10 vulnerabilities."
    else
      add_finding "WARNING" "6.4.1" "No Web Application Firewall or Load Balancers Detected" \
        "No Cloud Armor security policies or load balancers were found. If you have public-facing web applications, they require protection against common attacks." \
        "If you have public-facing web applications, implement Cloud Armor security policies with WAF rules to protect them from common attacks."
    fi
  fi
  
  # Check for Cloud CDN with security headers
  gcloud compute backend-services list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/backend_services.json" 2>/dev/null
  local backend_services=$(validate_json "$TEMP_DIR/backend_services.json")
  
  local cdn_enabled=$(echo "$backend_services" | jq '[.[] | select(.enableCDN == true)] | length')
  
  if [[ $cdn_enabled -gt 0 ]]; then
    add_finding "WARNING" "6.4.3" "Content Delivery Network Enabled" \
      "Cloud CDN is enabled for some backend services. Ensure security headers and content integrity checks are configured." \
      "Configure security headers (Content-Security-Policy, X-Content-Type-Options, etc.) and implement subresource integrity checks for scripts loaded through CDN to prevent unauthorized modifications."
  else
    add_finding "INFO" "6.4.3" "Content Delivery Network Not Detected" \
      "Cloud CDN does not appear to be enabled. If you use external CDNs or serve payment pages, ensure security measures are in place." \
      "If you serve payment pages or use external CDNs, implement security headers and subresource integrity checks to prevent unauthorized script modifications."
  fi
}

# Function to check for change management (Requirement 6.5)
check_change_management() {
  log "INFO" "Checking for change management (Requirement 6.5)..."
  
  # Check for Deployment Manager configurations
  gcloud deployment-manager deployments list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/deployments.json" 2>/dev/null
  local deployments=$(validate_json "$TEMP_DIR/deployments.json")
  
  if [[ $(echo "$deployments" | jq 'length') -gt 0 ]]; then
    add_finding "PASS" "6.5.1" "Infrastructure as Code Implemented" \
      "Deployment Manager deployments were found, indicating infrastructure as code practices which can support change management." \
      "Ensure your Deployment Manager templates are version-controlled, reviewed for security impacts, and tested before deployment to production."
  else
    # Check for Terraform state in GCS
    gcloud storage ls --project="$PROJECT_ID" --format=json | jq '.[] | select(.name | contains("terraform"))' > "$TEMP_DIR/terraform_buckets.json" 2>/dev/null
    local terraform_buckets=$(validate_json "$TEMP_DIR/terraform_buckets.json" "[]")
    
    if [[ $(echo "$terraform_buckets" | jq 'length') -gt 0 ]]; then
      add_finding "PASS" "6.5.1" "Infrastructure as Code Likely Implemented" \
        "Storage buckets with 'terraform' in the name were found, suggesting infrastructure as code practices which can support change management." \
        "Ensure your Terraform configurations are version-controlled, reviewed for security impacts, and tested before deployment to production."
    else
      add_finding "WARNING" "6.5.1" "No Infrastructure as Code Detected" \
        "No Deployment Manager deployments or Terraform state storage were detected. Implement infrastructure as code to support change management." \
        "Implement infrastructure as code using Deployment Manager or Terraform to ensure changes are documented, reviewed, tested, and approved before deployment."
    fi
  fi
  
  # Check for Cloud Build with approval steps
  gcloud builds triggers list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/build_triggers.json" 2>/dev/null
  local triggers=$(validate_json "$TEMP_DIR/build_triggers.json")
  
  if [[ $(echo "$triggers" | jq 'length') -gt 0 ]]; then
    # Check for approval steps
    local approval_steps=$(echo "$triggers" | jq '[.[] | select(.filename != null and (.filename | contains("approval") or .filename | contains("review")))] | length')
    
    if [[ $approval_steps -gt 0 ]]; then
      add_finding "PASS" "6.5.1" "Change Approval Process Likely Implemented" \
        "Cloud Build triggers with potential approval steps were found, suggesting a change management process." \
        "Ensure your change management process includes security impact analysis, testing, and documented approvals before changes are deployed to production."
    else
      add_finding "WARNING" "6.5.1" "Change Approval Process Not Detected" \
        "Cloud Build triggers were found, but no evidence of approval steps was detected." \
        "Implement approval steps in your CI/CD pipeline to ensure changes are reviewed and approved before deployment to production."
    fi
  fi
  
  # Check for separate environments
  gcloud compute networks list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/networks.json" 2>/dev/null
  local networks=$(validate_json "$TEMP_DIR/networks.json")
  
  local dev_networks=$(echo "$networks" | jq '[.[] | select(.name | test("dev|test|stage|qa"; "i"))] | length')
  local prod_networks=$(echo "$networks" | jq '[.[] | select(.name | test("prod|prd"; "i"))] | length')
  
  if [[ $dev_networks -gt 0 && $prod_networks -gt 0 ]]; then
    add_finding "PASS" "6.5.3" "Separate Development and Production Environments" \
      "Separate networks for development/testing and production were detected, indicating environment separation." \
      "Ensure these environments are properly isolated with appropriate access controls to prevent unauthorized access to production environments."
  else
    add_finding "WARNING" "6.5.3" "Separate Environments Not Clearly Defined" \
      "Could not clearly identify separate networks for development/testing and production environments." \
      "Implement separate environments for development, testing, and production with appropriate network isolation and access controls."
  fi
}

# Main function
main() {
  # Parse command line arguments
  while getopts ":p:o:h" opt; do
    case $opt in
      p)
        PROJECT_ID="$OPTARG"
        ;;
      o)
        REPORT_FILE="$OPTARG"
        ;;
      h)
        usage
        ;;
      \?)
        log "ERROR" "Invalid option: -$OPTARG"
        usage
        ;;
      :)
        log "ERROR" "Option -$OPTARG requires an argument."
        usage
        ;;
    esac
  done
  
  # Check if required parameters are provided
  if [[ -z "$PROJECT_ID" ]]; then
    log "ERROR" "Project ID is required."
    usage
  fi
  
  # Verify GCP access
  verify_gcp_access
  
  # Initialize HTML report
  initialize_html_report
  
  # Perform checks for each section of Requirement 6
  check_secure_development
  check_vulnerability_management
  check_web_application_security
  check_change_management
  
  # Finalize HTML report
  finalize_html_report
}

# Run the main function
main "$@"
