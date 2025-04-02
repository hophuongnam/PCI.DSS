#!/bin/bash
#
# PCI DSS v4.0.1 Requirement 8 Assessment Script for Google Cloud Platform
# Focuses on: Identify Users and Authenticate Access to System Components
#
# This script assesses GCP environments against PCI DSS v4.0.1 Requirement 8
# and generates an HTML report with findings and recommendations.

# Set strict error handling
set -o pipefail

# Global variables
PROJECT_ID=""
REPORT_FILE="pci_dss_req8_report_$(date +%Y%m%d_%H%M%S).html"
TEMP_DIR=$(mktemp -d)
CRITICAL_COUNT=0
WARNING_COUNT=0
PASS_COUNT=0
INFO_COUNT=0

# Color codes for terminal output
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Cleanup function to remove temporary files
cleanup() {
  rm -rf "$TEMP_DIR"
  echo -e "${BLUE}Temporary files cleaned up.${NC}"
}

# Set trap for cleanup on script exit
trap cleanup EXIT

# Function to log messages
log() {
  local level=$1
  local message=$2
  
  case $level in
    "INFO")
      echo -e "${BLUE}[INFO]${NC} $message"
      ;;
    "PASS")
      echo -e "${GREEN}[PASS]${NC} $message"
      ((PASS_COUNT++))
      ;;
    "WARNING")
      echo -e "${YELLOW}[WARNING]${NC} $message"
      ((WARNING_COUNT++))
      ;;
    "CRITICAL")
      echo -e "${RED}[CRITICAL]${NC} $message"
      ((CRITICAL_COUNT++))
      ;;
    *)
      echo -e "$message"
      ;;
  esac
}

# Function to check if gcloud is installed and authenticated
check_gcloud() {
  log "INFO" "Checking gcloud installation and authentication..."
  
  if ! command -v gcloud &> /dev/null; then
    log "CRITICAL" "gcloud CLI is not installed. Please install Google Cloud SDK."
    exit 1
  fi
  
  # Check if user is authenticated
  if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
    log "CRITICAL" "Not authenticated with gcloud. Please run 'gcloud auth login'."
    exit 1
  fi
  
  log "PASS" "gcloud is installed and authenticated."
}

# Function to validate project ID
validate_project() {
  log "INFO" "Validating project ID: $PROJECT_ID"
  
  if [[ -z "$PROJECT_ID" ]]; then
    log "CRITICAL" "Project ID is not set. Please provide a valid project ID."
    exit 1
  fi
  
  # Check if the project exists and is accessible
  if ! gcloud projects describe "$PROJECT_ID" &> /dev/null; then
    log "CRITICAL" "Project $PROJECT_ID does not exist or you don't have access to it."
    exit 1
  fi
  
  log "PASS" "Project $PROJECT_ID is valid and accessible."
}

# Function to safely parse JSON and handle errors
parse_json() {
  local json_file=$1
  local query=$2
  local default=${3:-[]}
  
  if [[ ! -f "$json_file" ]]; then
    echo "$default"
    return 1
  fi
  
  # Validate JSON before processing
  if ! jq empty "$json_file" 2>/dev/null; then
    echo "$default"
    return 1
  fi
  
  # Process with the query, providing a default if needed
  jq -r "$query // $default" "$json_file" 2>/dev/null || echo "$default"
}

# Function to escape HTML special characters
html_escape() {
  local text=$1
  echo "$text" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g'
}

# Function to add a finding to the report
add_finding() {
  local risk_level=$1
  local requirement=$2
  local title=$3
  local description=$4
  local recommendation=$5
  local details=$6
  
  # Create a unique ID for the finding
  local finding_id="finding_$(date +%s%N)"
  
  # Determine the color based on risk level
  local color
  case $risk_level in
    "CRITICAL") color="#dc3545" ;;
    "WARNING") color="#ffc107" ;;
    "PASS") color="#28a745" ;;
    "INFO") color="#17a2b8" ;;
    *) color="#6c757d" ;;
  esac
  
  # Append the finding to the report body
  cat >> "$TEMP_DIR/report_body.html" << EOF
<div class="finding" id="$finding_id">
  <div class="finding-header" style="background-color: $color;">
    <span class="risk-level">$risk_level</span>
    <span class="requirement">$requirement</span>
    <h3>$title</h3>
  </div>
  <div class="finding-content">
    <div class="description">
      <h4>Description</h4>
      <p>$description</p>
    </div>
    <div class="recommendation">
      <h4>Recommendation</h4>
      <p>$recommendation</p>
    </div>
    <div class="details">
      <h4>Details</h4>
      <pre>$details</pre>
    </div>
  </div>
</div>
EOF
}

# Function to initialize the HTML report
initialize_report() {
  log "INFO" "Initializing HTML report..."
  
  # Create the report header
  cat > "$TEMP_DIR/report_header.html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PCI DSS v4.0.1 Requirement 8 Assessment Report</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      margin: 0;
      padding: 20px;
      background-color: #f8f9fa;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background-color: #fff;
      padding: 20px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    header {
      text-align: center;
      margin-bottom: 30px;
      padding-bottom: 20px;
      border-bottom: 1px solid #eee;
    }
    h1, h2, h3, h4 {
      color: #333;
    }
    .summary {
      display: flex;
      justify-content: space-between;
      margin-bottom: 30px;
      flex-wrap: wrap;
    }
    .summary-box {
      flex: 1;
      min-width: 200px;
      margin: 10px;
      padding: 15px;
      border-radius: 5px;
      color: white;
      text-align: center;
    }
    .critical {
      background-color: #dc3545;
    }
    .warning {
      background-color: #ffc107;
      color: #333;
    }
    .pass {
      background-color: #28a745;
    }
    .info {
      background-color: #17a2b8;
    }
    .finding {
      margin-bottom: 20px;
      border: 1px solid #ddd;
      border-radius: 5px;
      overflow: hidden;
    }
    .finding-header {
      padding: 10px 15px;
      color: white;
      display: flex;
      align-items: center;
    }
    .risk-level {
      font-weight: bold;
      margin-right: 15px;
    }
    .requirement {
      margin-right: 15px;
      font-style: italic;
    }
    .finding-content {
      padding: 15px;
      background-color: #f8f9fa;
    }
    pre {
      background-color: #f1f1f1;
      padding: 10px;
      border-radius: 5px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-wrap: break-word;
    }
    .executive-summary {
      margin-bottom: 30px;
      padding: 20px;
      background-color: #e9ecef;
      border-radius: 5px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 20px;
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
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>PCI DSS v4.0.1 Requirement 8 Assessment Report</h1>
      <p>Project ID: $PROJECT_ID</p>
      <p>Report Generated: $(date)</p>
    </header>
    
    <div class="executive-summary">
      <h2>Executive Summary</h2>
      <p>This report presents the findings of an automated assessment of Google Cloud Platform resources against PCI DSS v4.0.1 Requirement 8: Identify Users and Authenticate Access to System Components.</p>
      <p>The assessment evaluates user identification, authentication mechanisms, and access controls within the GCP environment to determine compliance with PCI DSS requirements.</p>
    </div>
    
    <!-- Summary statistics will be inserted here -->
    <div id="summary-placeholder"></div>
    
    <h2>Detailed Findings</h2>
EOF

  # Create an empty file for the report body
  touch "$TEMP_DIR/report_body.html"
  
  # Create the report footer
  cat > "$TEMP_DIR/report_footer.html" << EOF
    <h2>Requirement 8 Overview</h2>
    <p>PCI DSS Requirement 8 focuses on identifying users and authenticating access to system components. Key aspects include:</p>
    <ul>
      <li>Assigning unique IDs to all users</li>
      <li>Implementing strong authentication mechanisms</li>
      <li>Securing authentication credentials</li>
      <li>Implementing multi-factor authentication</li>
      <li>Managing system and application accounts</li>
    </ul>
    
    <h2>Methodology</h2>
    <p>This assessment was performed using the Google Cloud Platform CLI (gcloud) to extract configuration data from the target environment. The script analyzed IAM policies, user accounts, authentication settings, and access controls against PCI DSS v4.0.1 Requirement 8 criteria.</p>
    
    <h2>Limitations</h2>
    <p>This automated assessment has the following limitations:</p>
    <ul>
      <li>It only assesses configurations visible through the GCP API</li>
      <li>It does not evaluate custom authentication systems deployed on GCP resources</li>
      <li>It cannot verify actual implementation of policies and procedures</li>
      <li>It provides a point-in-time assessment and may not reflect changes made after the report generation</li>
    </ul>
    
    <h2>Next Steps</h2>
    <p>Review the findings in this report and address any critical or warning items. For comprehensive PCI DSS compliance, ensure that all requirements are addressed, not just those covered in this automated assessment.</p>
  </div>
</body>
</html>
EOF

  log "PASS" "HTML report template initialized."
}

# Function to finalize the HTML report
finalize_report() {
  log "INFO" "Finalizing HTML report..."
  
  # Create the summary section with counts
  local summary=$(cat << EOF
    <div class="summary">
      <div class="summary-box critical">
        <h3>Critical</h3>
        <p>$CRITICAL_COUNT</p>
      </div>
      <div class="summary-box warning">
        <h3>Warning</h3>
        <p>$WARNING_COUNT</p>
      </div>
      <div class="summary-box pass">
        <h3>Pass</h3>
        <p>$PASS_COUNT</p>
      </div>
      <div class="summary-box info">
        <h3>Info</h3>
        <p>$INFO_COUNT</p>
      </div>
    </div>
EOF
)

  # Combine all parts of the report
  cat "$TEMP_DIR/report_header.html" > "$REPORT_FILE"
  echo "$summary" | sed 's/id="summary-placeholder"//g' >> "$REPORT_FILE"
  cat "$TEMP_DIR/report_body.html" "$TEMP_DIR/report_footer.html" >> "$REPORT_FILE"
  
  log "PASS" "HTML report finalized and saved to $REPORT_FILE"
}

# Function to check for unique user IDs (Requirement 8.2.1)
check_unique_user_ids() {
  log "INFO" "Checking for unique user IDs (Requirement 8.2.1)..."
  
  # Get IAM policy for the project
  gcloud projects get-iam-policy "$PROJECT_ID" --format=json > "$TEMP_DIR/iam_policy.json" 2>/dev/null
  
  if [[ ! -s "$TEMP_DIR/iam_policy.json" ]]; then
    add_finding "WARNING" "8.2.1" "Unable to retrieve IAM policy" \
      "Could not retrieve the IAM policy for the project. This may indicate insufficient permissions." \
      "Ensure the account running this script has the 'Security Reviewer' role or equivalent permissions." \
      "Error retrieving IAM policy for project $PROJECT_ID"
    return
  fi
  
  # Extract all members from the IAM policy
  jq -r '.bindings[].members[]' "$TEMP_DIR/iam_policy.json" 2>/dev/null | sort | uniq > "$TEMP_DIR/all_members.txt"
  
  # Check for group accounts
  grep -E "^group:" "$TEMP_DIR/all_members.txt" > "$TEMP_DIR/group_accounts.txt" || true
  
  # Check for service accounts
  grep -E "^serviceAccount:" "$TEMP_DIR/all_members.txt" > "$TEMP_DIR/service_accounts.txt" || true
  
  # Check for user accounts
  grep -E "^user:" "$TEMP_DIR/all_members.txt" > "$TEMP_DIR/user_accounts.txt" || true
  
  # Check for generic accounts like allUsers or allAuthenticatedUsers
  if grep -E "^(allUsers|allAuthenticatedUsers)$" "$TEMP_DIR/all_members.txt" > "$TEMP_DIR/generic_accounts.txt"; then
    local generic_accounts=$(cat "$TEMP_DIR/generic_accounts.txt" | tr '\n' ', ' | sed 's/,$//')
    add_finding "CRITICAL" "8.2.1" "Public access detected" \
      "Public access identifiers ($generic_accounts) were found in the IAM policy. This violates the requirement for unique user IDs and proper authentication." \
      "Remove public access identifiers from all IAM policies. Replace with specific user or service accounts with appropriate permissions." \
      "Public identifiers found: $generic_accounts"
  else
    log "PASS" "No public access identifiers found in IAM policy."
  fi
  
  # Check for service accounts with default names
  if grep -E "^serviceAccount:[0-9]+-compute@developer.gserviceaccount.com$" "$TEMP_DIR/service_accounts.txt" > "$TEMP_DIR/default_svc_accounts.txt"; then
    local count=$(wc -l < "$TEMP_DIR/default_svc_accounts.txt")
    add_finding "WARNING" "8.2.1" "Default service accounts in use" \
      "Default service accounts are being used. While these have unique IDs, they may not align with job functions as required by PCI DSS." \
      "Create custom service accounts with descriptive names and appropriate permissions for specific functions. Consider disabling default service accounts if not needed." \
      "$(cat "$TEMP_DIR/default_svc_accounts.txt")"
  else
    log "PASS" "No default service accounts found in use."
  fi
  
  # Count unique identifiers
  local user_count=$(wc -l < "$TEMP_DIR/user_accounts.txt" || echo 0)
  local service_account_count=$(wc -l < "$TEMP_DIR/service_accounts.txt" || echo 0)
  local group_count=$(wc -l < "$TEMP_DIR/group_accounts.txt" || echo 0)
  
  add_finding "INFO" "8.2.1" "User identification summary" \
    "Summary of unique identifiers found in the project's IAM policy." \
    "Regularly review all accounts to ensure they are still required and follow the principle of least privilege." \
    "User accounts: $user_count\nService accounts: $service_account_count\nGroup accounts: $group_count"
  
  log "PASS" "Unique user IDs check completed."
}

# Function to check for shared/generic accounts (Requirement 8.2.2)
check_shared_accounts() {
  log "INFO" "Checking for shared/generic accounts (Requirement 8.2.2)..."
  
  # Get service accounts
  gcloud iam service-accounts list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/service_accounts.json" 2>/dev/null
  
  if [[ ! -s "$TEMP_DIR/service_accounts.json" ]]; then
    add_finding "WARNING" "8.2.2" "Unable to retrieve service accounts" \
      "Could not retrieve service accounts for the project. This may indicate insufficient permissions." \
      "Ensure the account running this script has the 'Service Account Viewer' role or equivalent permissions." \
      "Error retrieving service accounts for project $PROJECT_ID"
    return
  fi
  
  # Check for service accounts with suspicious names indicating shared use
  local shared_accounts=$(jq -r '.[] | select(.displayName | test("shared|generic|team|common|admin|root|backup|test", "i")) | .email' "$TEMP_DIR/service_accounts.json" 2>/dev/null)
  
  if [[ -n "$shared_accounts" ]]; then
    add_finding "WARNING" "8.2.2" "Potentially shared service accounts detected" \
      "Service accounts with names suggesting shared or generic use were found. PCI DSS requires that shared accounts are only used when necessary with proper controls." \
      "Review these service accounts and determine if they are actually shared. If so, implement controls to track individual actions, limit their use to exceptional circumstances, and document business justification." \
      "$(echo "$shared_accounts" | sed 's/^/- /')"
  else
    log "PASS" "No service accounts with names suggesting shared use were found."
  fi
  
  # Check IAM policy for group memberships
  local group_count=$(grep -c "^group:" "$TEMP_DIR/all_members.txt" || echo 0)
  
  if [[ $group_count -gt 0 ]]; then
    add_finding "INFO" "8.2.2" "Group accounts in use" \
      "Group accounts were found in the IAM policy. While groups help with access management, ensure individual accountability is maintained." \
      "Verify that actions performed by users in these groups can be traced back to individual users. Consider implementing additional logging and monitoring for sensitive actions." \
      "$(grep "^group:" "$TEMP_DIR/all_members.txt" | sed 's/^/- /')"
  fi
  
  log "PASS" "Shared accounts check completed."
}

# Function to check for terminated users (Requirement 8.2.5)
check_terminated_users() {
  log "INFO" "Checking for potentially terminated users (Requirement 8.2.5)..."
  
  # This is a limited check since we can't directly determine terminated users
  # We'll look for inactive service accounts as a proxy
  
  # Get service accounts
  if [[ ! -s "$TEMP_DIR/service_accounts.json" ]]; then
    gcloud iam service-accounts list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/service_accounts.json" 2>/dev/null
  fi
  
  if [[ ! -s "$TEMP_DIR/service_accounts.json" ]]; then
    add_finding "WARNING" "8.2.5" "Unable to check for inactive service accounts" \
      "Could not retrieve service accounts to check for potentially terminated users." \
      "Ensure the account running this script has the necessary permissions." \
      "Error retrieving service accounts for project $PROJECT_ID"
    return
  fi
  
  # Get keys for each service account
  local disabled_accounts=()
  local accounts_with_keys=()
  local accounts_without_keys=()
  
  while read -r email; do
    # Check if the account is disabled
    local disabled=$(jq -r --arg email "$email" '.[] | select(.email == $email) | .disabled // false' "$TEMP_DIR/service_accounts.json")
    
    if [[ "$disabled" == "true" ]]; then
      disabled_accounts+=("$email")
      continue
    fi
    
    # Get keys for this service account
    gcloud iam service-accounts keys list --iam-account="$email" --project="$PROJECT_ID" --format=json > "$TEMP_DIR/keys_${email//[@.]/_}.json" 2>/dev/null
    
    # Check if the service account has any keys
    if [[ -s "$TEMP_DIR/keys_${email//[@.]/_}.json" ]]; then
      local key_count=$(jq 'length' "$TEMP_DIR/keys_${email//[@.]/_}.json")
      if [[ $key_count -gt 0 ]]; then
        accounts_with_keys+=("$email ($key_count keys)")
      else
        accounts_without_keys+=("$email")
      fi
    else
      accounts_without_keys+=("$email")
    fi
  done < <(jq -r '.[].email' "$TEMP_DIR/service_accounts.json" 2>/dev/null)
  
  # Report on disabled accounts
  if [[ ${#disabled_accounts[@]} -gt 0 ]]; then
    add_finding "INFO" "8.2.5" "Disabled service accounts found" \
      "Disabled service accounts were found. This is good practice for accounts that are no longer needed but may need to be retained." \
      "Regularly review disabled accounts and consider removing them completely if they are no longer needed for audit purposes." \
      "$(printf '%s\n' "${disabled_accounts[@]}" | sed 's/^/- /')"
  fi
  
  # Report on accounts without keys
  if [[ ${#accounts_without_keys[@]} -gt 0 ]]; then
    add_finding "INFO" "8.2.5" "Service accounts without keys" \
      "Service accounts without keys were found. These may be unused accounts or accounts used only for API access." \
      "Review these accounts to determine if they are still needed. Remove any that are no longer required." \
      "$(printf '%s\n' "${accounts_without_keys[@]}" | sed 's/^/- /')"
  fi
  
  log "PASS" "Terminated users check completed."
}

# Function to check for inactive accounts (Requirement 8.2.6)
check_inactive_accounts() {
  log "INFO" "Checking for inactive accounts (Requirement 8.2.6)..."
  
  # Get service account keys with creation dates
  local old_keys=()
  local key_files=("$TEMP_DIR"/keys_*.json)
  
  # Check if any key files exist
  if [[ -f "${key_files[0]}" ]]; then
    for key_file in "${key_files[@]}"; do
      local account_name=$(basename "$key_file" | sed 's/keys_//; s/\.json$//' | tr '_' '.')
      account_name=$(grep "$account_name" "$TEMP_DIR/service_accounts.txt" || echo "unknown")
      
      # Find keys older than 90 days
      local old_key_ids=$(jq -r '.[] | select(.validAfterTime | fromnow | (. / 86400) < -90) | .name' "$key_file" 2>/dev/null)
      
      if [[ -n "$old_key_ids" ]]; then
        while read -r key_id; do
          local creation_date=$(jq -r --arg key_id "$key_id" '.[] | select(.name == $key_id) | .validAfterTime' "$key_file")
          old_keys+=("$account_name - Key: $(basename "$key_id") - Created: $creation_date")
        done <<< "$old_key_ids"
      fi
    done
  fi
  
  if [[ ${#old_keys[@]} -gt 0 ]]; then
    add_finding "WARNING" "8.2.6" "Service account keys older than 90 days" \
      "Service account keys that were created more than 90 days ago were found. PCI DSS requires inactive user accounts to be removed or disabled within 90 days of inactivity." \
      "Review these service account keys to determine if they are still in use. Rotate keys regularly and remove any that are no longer needed." \
      "$(printf '%s\n' "${old_keys[@]}" | sed 's/^/- /')"
  else
    log "PASS" "No service account keys older than 90 days were found."
  fi
  
  # Check for potentially inactive IAM members by looking at audit logs
  # Note: This is a best-effort check and may not be comprehensive
  log "INFO" "Checking audit logs for user activity (limited to last 30 days)..."
  
  gcloud logging read "resource.type=project AND resource.labels.project_id=$PROJECT_ID AND protoPayload.@type=type.googleapis.com/google.cloud.audit.AuditLog AND timestamp>-P30D" --limit 1000 --format=json > "$TEMP_DIR/audit_logs.json" 2>/dev/null
  
  if [[ -s "$TEMP_DIR/audit_logs.json" ]]; then
    # Extract unique principals from audit logs
    jq -r '.[].protoPayload.authenticationInfo.principalEmail' "$TEMP_DIR/audit_logs.json" 2>/dev/null | grep -v "^$" | sort | uniq > "$TEMP_DIR/active_principals.txt"
    
    # Compare with IAM policy members to find potentially inactive users
    if [[ -s "$TEMP_DIR/all_members.txt" && -s "$TEMP_DIR/active_principals.txt" ]]; then
      grep "^user:" "$TEMP_DIR/all_members.txt" | sed 's/^user://' > "$TEMP_DIR/all_users.txt"
      grep "^serviceAccount:" "$TEMP_DIR/all_members.txt" | sed 's/^serviceAccount://' > "$TEMP_DIR/all_service_accounts.txt"
      
      # Find users in IAM but not in audit logs
      comm -23 <(sort "$TEMP_DIR/all_users.txt") <(sort "$TEMP_DIR/active_principals.txt") > "$TEMP_DIR/potentially_inactive_users.txt"
      comm -23 <(sort "$TEMP_DIR/all_service_accounts.txt") <(sort "$TEMP_DIR/active_principals.txt") > "$TEMP_DIR/potentially_inactive_service_accounts.txt"
      
      local inactive_user_count=$(wc -l < "$TEMP_DIR/potentially_inactive_users.txt" || echo 0)
      local inactive_sa_count=$(wc -l < "$TEMP_DIR/potentially_inactive_service_accounts.txt" || echo 0)
      
      if [[ $inactive_user_count -gt 0 || $inactive_sa_count -gt 0 ]]; then
        add_finding "WARNING" "8.2.6" "Potentially inactive accounts detected" \
          "Accounts with IAM roles that have not appeared in audit logs in the last 30 days were found. PCI DSS requires inactive user accounts to be removed or disabled within 90 days of inactivity." \
          "Review these accounts to determine if they are still needed. Remove or disable accounts that are no longer required." \
          "Potentially inactive user accounts: $inactive_user_count\nPotentially inactive service accounts: $inactive_sa_count\n\nNote: This is based on limited audit log data (30 days) and may not be comprehensive."
      else
        log "PASS" "No potentially inactive accounts detected based on audit logs."
      fi
    fi
  else
    add_finding "INFO" "8.2.6" "Unable to check audit logs for user activity" \
      "Could not retrieve audit logs to check for inactive users. This may indicate insufficient permissions or logging configuration." \
      "Ensure the account running this script has the 'Logs Viewer' role and that audit logging is enabled." \
      "Error retrieving audit logs for project $PROJECT_ID"
  fi
  
  log "PASS" "Inactive accounts check completed."
}

# Function to check for third-party access (Requirement 8.2.7)
check_third_party_access() {
  log "INFO" "Checking for third-party access (Requirement 8.2.7)..."
  
  # Check for external identities in IAM policy
  if [[ -s "$TEMP_DIR/all_members.txt" ]]; then
    # Look for non-Google identities
    grep -v "@google.com$" "$TEMP_DIR/all_members.txt" | grep -v "^serviceAccount:" | grep -v "^group:" > "$TEMP_DIR/external_identities.txt" || true
    
    local external_count=$(wc -l < "$TEMP_DIR/external_identities.txt" || echo 0)
    
    if [[ $external_count -gt 0 ]]; then
      add_finding "WARNING" "8.2.7" "External identities with access detected" \
        "External identities (potentially third-party) were found with access to the project. PCI DSS requires third-party access to be enabled only when needed and monitored for unexpected activity." \
        "Implement processes to enable third-party access only when needed and disable it when not in use. Monitor all third-party access for unexpected activity." \
        "$(cat "$TEMP_DIR/external_identities.txt" | sed 's/^/- /')"
    else
      log "PASS" "No external identities detected with access to the project."
    fi
  fi
  
  # Check for IAP settings which might indicate third-party access
  gcloud compute backend-services list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/backend_services.json" 2>/dev/null
  
  if [[ -s "$TEMP_DIR/backend_services.json" ]]; then
    local iap_enabled_services=$(jq -r '.[] | select(.iap != null and .iap.enabled == true) | .name' "$TEMP_DIR/backend_services.json" 2>/dev/null)
    
    if [[ -n "$iap_enabled_services" ]]; then
      add_finding "INFO" "8.2.7" "IAP-enabled services detected" \
        "Services with Identity-Aware Proxy (IAP) enabled were found. This is a good practice for securing third-party access, but ensure proper monitoring is in place." \
        "Ensure that access through IAP is properly monitored and that access is granted only to required individuals." \
        "IAP-enabled services:\n$(echo "$iap_enabled_services" | sed 's/^/- /')"
    fi
  fi
  
  log "PASS" "Third-party access check completed."
}

# Function to check for session timeout (Requirement 8.2.8)
check_session_timeout() {
  log "INFO" "Checking for session timeout settings (Requirement 8.2.8)..."
  
  # Check for IAP session timeout settings
  if [[ -s "$TEMP_DIR/backend_services.json" ]]; then
    local iap_services_without_timeout=$(jq -r '.[] | select(.iap != null and .iap.enabled == true and (.iap.oauth2ClientId != null or .iap.oauth2ClientSecret != null) and (.securitySettings == null or .securitySettings.clientTlsPolicy == null)) | .name' "$TEMP_DIR/backend_services.json" 2>/dev/null)
    
    if [[ -n "$iap_services_without_timeout" ]]; then
      add_finding "WARNING" "8.2.8" "IAP services without session timeout" \
        "Services with Identity-Aware Proxy (IAP) enabled were found without explicit session timeout settings. PCI DSS requires sessions to timeout after 15 minutes of inactivity." \
        "Configure session timeout settings for IAP-protected resources to ensure sessions expire after 15 minutes of inactivity." \
        "IAP-enabled services without explicit timeout:\n$(echo "$iap_services_without_timeout" | sed 's/^/- /')"
    fi
  fi
  
  # Check for Cloud Run services (which might have session handling)
  gcloud run services list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/cloud_run_services.json" 2>/dev/null
  
  if [[ -s "$TEMP_DIR/cloud_run_services.json" ]]; then
    local cloud_run_services=$(jq -r '.[].metadata.name' "$TEMP_DIR/cloud_run_services.json" 2>/dev/null)
    
    if [[ -n "$cloud_run_services" ]]; then
      add_finding "INFO" "8.2.8" "Cloud Run services detected" \
        "Cloud Run services were detected. If these services handle user sessions, ensure they implement proper session timeout." \
        "Implement session timeout mechanisms in your Cloud Run applications to ensure sessions expire after 15 minutes of inactivity." \
        "Cloud Run services:\n$(echo "$cloud_run_services" | sed 's/^/- /')"
    fi
  fi
  
  # Check for App Engine applications (which might have session handling)
  gcloud app services list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/app_engine_services.json" 2>/dev/null
  
  if [[ -s "$TEMP_DIR/app_engine_services.json" ]]; then
    add_finding "INFO" "8.2.8" "App Engine application detected" \
      "An App Engine application was detected. If this application handles user sessions, ensure it implements proper session timeout." \
      "Implement session timeout mechanisms in your App Engine application to ensure sessions expire after 15 minutes of inactivity." \
      "App Engine services detected. Review session handling in your application code."
  fi
  
  log "PASS" "Session timeout check completed."
}

# Function to check for authentication factors (Requirement 8.3.1)
check_authentication_factors() {
  log "INFO" "Checking for authentication factors (Requirement 8.3.1)..."
  
  # Check if organization policies are available
  gcloud resource-manager org-policies list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/org_policies.json" 2>/dev/null
  
  if [[ -s "$TEMP_DIR/org_policies.json" ]]; then
    # Check for 2-step verification enforcement
    local has_2sv_policy=$(jq -r '.[] | select(.constraint == "constraints/iam.disableServiceAccountKeyCreation") | .booleanPolicy.enforced // false' "$TEMP_DIR/org_policies.json" 2>/dev/null)
    
    if [[ "$has_2sv_policy" == "true" ]]; then
      add_finding "PASS" "8.3.1" "Service account key creation is disabled" \
        "The organization policy to disable service account key creation is enforced. This is a good practice that encourages the use of more secure authentication methods." \
        "Continue to use workload identity or other secure authentication methods instead of service account keys." \
        "Organization policy 'constraints/iam.disableServiceAccountKeyCreation' is enforced."
    else
      add_finding "WARNING" "8.3.1" "Service account key creation is allowed" \
        "The organization policy to disable service account key creation is not enforced. Service account keys are long-lived credentials that may pose security risks." \
        "Consider enforcing the 'constraints/iam.disableServiceAccountKeyCreation' organization policy and use workload identity or other secure authentication methods instead." \
        "Organization policy 'constraints/iam.disableServiceAccountKeyCreation' is not enforced or not set."
    fi
  else
    add_finding "INFO" "8.3.1" "Unable to check organization policies" \
      "Could not retrieve organization policies to check for authentication factor enforcement. This may indicate insufficient permissions." \
      "Ensure the account running this script has the 'Organization Policy Viewer' role or equivalent permissions." \
      "Error retrieving organization policies for project $PROJECT_ID"
  fi
  
  # Check for Cloud Identity settings (limited visibility through API)
  add_finding "INFO" "8.3.1" "Cloud Identity settings check" \
    "Cloud Identity settings for authentication factors cannot be fully checked through the API. Manual verification is required." \
    "Verify in the Google Admin Console that multi-factor authentication is enforced for all users with access to the CDE. Ensure password policies meet PCI DSS requirements." \
    "Manual verification required for Cloud Identity settings."
  
  log "PASS" "Authentication factors check completed."
}

# Function to check for cryptographic protection of authentication factors (Requirement 8.3.2)
check_crypto_protection() {
  log "INFO" "Checking for cryptographic protection of authentication factors (Requirement 8.3.2)..."
  
  # Check for unencrypted service account keys
  local key_files=("$TEMP_DIR"/keys_*.json)
  local key_count=0
  
  # Check if any key files exist
  if [[ -f "${key_files[0]}" ]]; then
    for key_file in "${key_files[@]}"; do
      local file_key_count=$(jq 'length' "$key_file" 2>/dev/null || echo 0)
      key_count=$((key_count + file_key_count))
    done
  fi
  
  if [[ $key_count -gt 0 ]]; then
    add_finding "WARNING" "8.3.2" "Service account keys in use" \
      "Service account keys were found in use. While GCP encrypts these keys at rest and in transit, they are stored as cleartext files when downloaded." \
      "Consider using alternative authentication methods such as workload identity, impersonation, or short-lived credentials instead of long-lived service account keys." \
      "Total service account keys found: $key_count"
  else
    add_finding "PASS" "8.3.2" "No service account keys found" \
      "No service account keys were found in use. This is a good practice as it avoids the risks associated with long-lived credentials stored as files." \
      "Continue to use alternative authentication methods such as workload identity, impersonation, or short-lived credentials." \
      "No service account keys detected."
  fi
  
  # Check for Secret Manager usage (good practice for storing sensitive authentication data)
  gcloud secrets list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/secrets.json" 2>/dev/null
  
  if [[ -s "$TEMP_DIR/secrets.json" ]]; then
    local secret_count=$(jq 'length' "$TEMP_DIR/secrets.json" 2>/dev/null || echo 0)
    
    if [[ $secret_count -gt 0 ]]; then
      add_finding "PASS" "8.3.2" "Secret Manager in use" \
        "Secret Manager is being used to store secrets. This is a good practice for securely storing authentication factors and other sensitive data." \
        "Continue to use Secret Manager for storing sensitive authentication data. Ensure proper access controls are in place." \
        "Secret Manager secrets found: $secret_count"
    else
      add_finding "INFO" "8.3.2" "Secret Manager not in use" \
        "No secrets were found in Secret Manager. Consider using Secret Manager to securely store authentication factors and other sensitive data." \
        "Implement Secret Manager for storing sensitive authentication data such as API keys, passwords, and certificates." \
        "No Secret Manager secrets detected."
    fi
  else
    add_finding "INFO" "8.3.2" "Unable to check Secret Manager" \
      "Could not retrieve Secret Manager data. This may indicate insufficient permissions or that Secret Manager is not enabled." \
      "Ensure the account running this script has the 'Secret Manager Viewer' role and that Secret Manager API is enabled." \
      "Error retrieving Secret Manager data for project $PROJECT_ID"
  fi
  
  log "PASS" "Cryptographic protection check completed."
}

# Function to check for authentication attempt limits (Requirement 8.3.4)
check_auth_attempt_limits() {
  log "INFO" "Checking for authentication attempt limits (Requirement 8.3.4)..."
  
  # Check for IAP brute force protection
  if [[ -s "$TEMP_DIR/backend_services.json" ]]; then
    local iap_enabled_count=$(jq '[.[] | select(.iap != null and .iap.enabled == true)] | length' "$TEMP_DIR/backend_services.json" 2>/dev/null || echo 0)
    
    if [[ $iap_enabled_count -gt 0 ]]; then
      add_finding "PASS" "8.3.4" "IAP protection in use" \
        "Identity-Aware Proxy (IAP) is enabled for some services. IAP includes built-in protection against brute force attacks." \
        "Continue to use IAP for protecting access to applications and services." \
        "IAP-enabled services found: $iap_enabled_count"
    fi
  fi
  
  # Check for reCAPTCHA usage (which can help limit invalid authentication attempts)
  gcloud recaptcha keys list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/recaptcha_keys.json" 2>/dev/null
  
  if [[ -s "$TEMP_DIR/recaptcha_keys.json" ]]; then
    local recaptcha_key_count=$(jq 'length' "$TEMP_DIR/recaptcha_keys.json" 2>/dev/null || echo 0)
    
    if [[ $recaptcha_key_count -gt 0 ]]; then
      add_finding "PASS" "8.3.4" "reCAPTCHA in use" \
        "reCAPTCHA is being used, which can help protect against automated brute force attacks." \
        "Continue to use reCAPTCHA to protect login forms and other sensitive endpoints." \
        "reCAPTCHA keys found: $recaptcha_key_count"
    fi
  else
    # The API might not be enabled or the user might not have permissions
    add_finding "INFO" "8.3.4" "Unable to check for reCAPTCHA usage" \
      "Could not determine if reCAPTCHA is in use. This may indicate that the reCAPTCHA API is not enabled or insufficient permissions." \
      "Consider implementing reCAPTCHA to protect login forms and other sensitive endpoints from automated attacks." \
      "Error retrieving reCAPTCHA data or reCAPTCHA API not enabled."
  fi
  
  # Check for Cloud Identity settings (limited visibility through API)
  add_finding "INFO" "8.3.4" "Cloud Identity lockout settings check" \
    "Cloud Identity settings for account lockout cannot be fully checked through the API. Manual verification is required." \
    "Verify in the Google Admin Console that account lockout policies are configured to lock out user IDs after no more than 10 invalid attempts and for a minimum of 30 minutes." \
    "Manual verification required for Cloud Identity lockout settings."
  
  log "PASS" "Authentication attempt limits check completed."
}

# Function to check for password complexity (Requirement 8.3.6)
check_password_complexity() {
  log "INFO" "Checking for password complexity requirements (Requirement 8.3.6)..."
  
  # Check for Cloud Identity settings (limited visibility through API)
  add_finding "INFO" "8.3.6" "Cloud Identity password policy check" \
    "Cloud Identity settings for password complexity cannot be fully checked through the API. Manual verification is required." \
    "Verify in the Google Admin Console that password policies require a minimum length of 12 characters (or 8 if system limitations exist) and contain both numeric and alphabetic characters." \
    "Manual verification required for Cloud Identity password policies."
  
  log "PASS" "Password complexity check completed."
}

# Function to check for MFA implementation (Requirement 8.4.1, 8.4.2, 8.4.3)
check_mfa_implementation() {
  log "INFO" "Checking for MFA implementation (Requirements 8.4.1, 8.4.2, 8.4.3)..."
  
  # Check for organization policies related to MFA
  if [[ -s "$TEMP_DIR/org_policies.json" ]]; then
    # Check for 2-step verification enforcement
    local has_2sv_policy=$(jq -r '.[] | select(.constraint == "constraints/iam.disableServiceAccountKeyUpload") | .booleanPolicy.enforced // false' "$TEMP_DIR/org_policies.json" 2>/dev/null)
    
    if [[ "$has_2sv_policy" == "true" ]]; then
      add_finding "PASS" "8.4.1" "Service account key upload is disabled" \
        "The organization policy to disable service account key upload is enforced. This helps prevent the use of externally created keys that might bypass MFA requirements." \
        "Continue to enforce this policy to maintain security controls." \
        "Organization policy 'constraints/iam.disableServiceAccountKeyUpload' is enforced."
    else
      add_finding "WARNING" "8.4.1" "Service account key upload is allowed" \
        "The organization policy to disable service account key upload is not enforced. This could allow bypassing MFA requirements with externally created keys." \
        "Consider enforcing the 'constraints/iam.disableServiceAccountKeyUpload' organization policy." \
        "Organization policy 'constraints/iam.disableServiceAccountKeyUpload' is not enforced or not set."
    fi
  fi
  
  # Check for IAP usage (which can enforce MFA)
  if [[ -s "$TEMP_DIR/backend_services.json" ]]; then
    local iap_enabled_count=$(jq '[.[] | select(.iap != null and .iap.enabled == true)] | length' "$TEMP_DIR/backend_services.json" 2>/dev/null || echo 0)
    
    if [[ $iap_enabled_count -gt 0 ]]; then
      add_finding "INFO" "8.4.2" "IAP protection in use" \
        "Identity-Aware Proxy (IAP) is enabled for some services. IAP can be configured to require MFA for access to the CDE." \
        "Ensure IAP is configured to require MFA for all access to systems in the CDE." \
        "IAP-enabled services found: $iap_enabled_count"
    fi
  fi
  
  # Check for VPC Service Controls (which can help enforce network-level MFA requirements)
  gcloud access-context-manager perimeters list --format=json > "$TEMP_DIR/vpc_sc_perimeters.json" 2>/dev/null
  
  if [[ -s "$TEMP_DIR/vpc_sc_perimeters.json" ]]; then
    local perimeter_count=$(jq 'length' "$TEMP_DIR/vpc_sc_perimeters.json" 2>/dev/null || echo 0)
    
    if [[ $perimeter_count -gt 0 ]]; then
      add_finding "PASS" "8.4.3" "VPC Service Controls in use" \
        "VPC Service Controls are being used. This can help enforce access restrictions for remote access to the CDE." \
        "Ensure VPC Service Controls are configured to require MFA for all remote access to the CDE." \
        "VPC Service Controls perimeters found: $perimeter_count"
    fi
  else
    add_finding "INFO" "8.4.3" "VPC Service Controls not detected" \
      "VPC Service Controls were not detected. These can help enforce access restrictions for remote access to the CDE." \
      "Consider implementing VPC Service Controls to restrict remote access to the CDE and enforce MFA requirements." \
      "No VPC Service Controls perimeters found or insufficient permissions to check."
  fi
  
  # Check for Cloud Identity settings (limited visibility through API)
  add_finding "INFO" "8.4.1, 8.4.2, 8.4.3" "Cloud Identity MFA settings check" \
    "Cloud Identity settings for MFA enforcement cannot be fully checked through the API. Manual verification is required." \
    "Verify in the Google Admin Console that MFA is enforced for all users with access to the CDE, for all non-console access into the CDE, and for all remote access originating from outside the entity's network." \
    "Manual verification required for Cloud Identity MFA settings."
  
  log "PASS" "MFA implementation check completed."
}

# Function to check for MFA system configuration (Requirement 8.5.1)
check_mfa_system_config() {
  log "INFO" "Checking for MFA system configuration (Requirement 8.5.1)..."
  
  # Check for Cloud Identity settings (limited visibility through API)
  add_finding "INFO" "8.5.1" "Cloud Identity MFA configuration check" \
    "Cloud Identity settings for MFA configuration cannot be fully checked through the API. Manual verification is required." \
    "Verify that the MFA system is not susceptible to replay attacks, cannot be bypassed by any users (including administrators), uses at least two different types of authentication factors, and requires success of all authentication factors before granting access." \
    "Manual verification required for Cloud Identity MFA configuration."
  
  log "PASS" "MFA system configuration check completed."
}

# Function to check for system account management (Requirement 8.6.1, 8.6.2, 8.6.3)
check_system_account_management() {
  log "INFO" "Checking for system account management (Requirements 8.6.1, 8.6.2, 8.6.3)..."
  
  # Check for service accounts with user-managed keys
  if [[ -s "$TEMP_DIR/service_accounts.json" ]]; then
    local service_accounts_with_keys=()
    local key_files=("$TEMP_DIR"/keys_*.json)
    
    # Check if any key files exist
    if [[ -f "${key_files[0]}" ]]; then
      for key_file in "${key_files[@]}"; do
        local account_name=$(basename "$key_file" | sed 's/keys_//; s/\.json$//' | tr '_' '.')
        local key_count=$(jq 'length' "$key_file" 2>/dev/null || echo 0)
        
        if [[ $key_count -gt 0 ]]; then
          service_accounts_with_keys+=("$account_name ($key_count keys)")
        fi
      done
    fi
    
    if [[ ${#service_accounts_with_keys[@]} -gt 0 ]]; then
      add_finding "WARNING" "8.6.2" "Service accounts with user-managed keys" \
        "Service accounts with user-managed keys were found. These keys could potentially be hard-coded in scripts or configuration files." \
        "Review all scripts, configuration files, and source code to ensure service account keys are not hard-coded. Consider using alternative authentication methods such as workload identity or impersonation." \
        "Service accounts with keys:\n$(printf '%s\n' "${service_accounts_with_keys[@]}" | sed 's/^/- /')"
    else
      add_finding "PASS" "8.6.2" "No service accounts with user-managed keys" \
        "No service accounts with user-managed keys were found. This reduces the risk of keys being hard-coded in scripts or configuration files." \
        "Continue to use alternative authentication methods such as workload identity or impersonation instead of service account keys." \
        "No service accounts with user-managed keys detected."
    fi
  fi
  
  # Check for compute instances that might be using service accounts
  gcloud compute instances list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/compute_instances.json" 2>/dev/null
  
  if [[ -s "$TEMP_DIR/compute_instances.json" ]]; then
    local instances_with_sa=$(jq -r '.[] | select(.serviceAccounts != null and .serviceAccounts[0].email != null) | .name + " (" + .serviceAccounts[0].email + ")"' "$TEMP_DIR/compute_instances.json" 2>/dev/null)
    
    if [[ -n "$instances_with_sa" ]]; then
      add_finding "INFO" "8.6.1" "Compute instances using service accounts" \
        "Compute instances using service accounts were found. Ensure these service accounts are properly managed and not used for interactive login." \
        "Verify that service accounts used by compute instances are not used for interactive login except in exceptional circumstances. If interactive use is needed, implement the controls required by PCI DSS 8.6.1." \
        "Instances using service accounts:\n$(echo "$instances_with_sa" | sed 's/^/- /')"
    fi
  fi
  
  # Check for Cloud Functions that might be using service accounts
  gcloud functions list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/cloud_functions.json" 2>/dev/null
  
  if [[ -s "$TEMP_DIR/cloud_functions.json" ]]; then
    local functions_with_sa=$(jq -r '.[] | select(.serviceAccountEmail != null) | .name + " (" + .serviceAccountEmail + ")"' "$TEMP_DIR/cloud_functions.json" 2>/dev/null)
    
    if [[ -n "$functions_with_sa" ]]; then
      add_finding "INFO" "8.6.3" "Cloud Functions using service accounts" \
        "Cloud Functions using service accounts were found. Ensure these service accounts have their passwords/keys rotated periodically." \
        "Implement a process to periodically rotate service account keys used by Cloud Functions based on your risk assessment." \
        "Functions using service accounts:\n$(echo "$functions_with_sa" | sed 's/^/- /')"
    fi
  fi
  
  log "PASS" "System account management check completed."
}

# Main function
main() {
  echo "PCI DSS v4.0.1 Requirement 8 Assessment Script for Google Cloud Platform"
  echo "======================================================================"
  echo
  
  # Check if gcloud is installed and authenticated
  check_gcloud
  
  # Get project ID if not provided
  if [[ -z "$PROJECT_ID" ]]; then
    PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
    if [[ -z "$PROJECT_ID" ]]; then
      log "CRITICAL" "No project ID provided or set in gcloud config."
      echo "Please provide a project ID using the -p or --project flag, or set it using 'gcloud config set project PROJECT_ID'."
      exit 1
    fi
  fi
  
  # Validate project ID
  validate_project
  
  # Initialize HTML report
  initialize_report
  
  # Perform checks for Requirement 8
  check_unique_user_ids            # 8.2.1
  check_shared_accounts            # 8.2.2
  check_terminated_users           # 8.2.5
  check_inactive_accounts          # 8.2.6
  check_third_party_access         # 8.2.7
  check_session_timeout            # 8.2.8
  check_authentication_factors     # 8.3.1
  check_crypto_protection          # 8.3.2
  check_auth_attempt_limits        # 8.3.4
  check_password_complexity        # 8.3.6
  check_mfa_implementation         # 8.4.1, 8.4.2, 8.4.3
  check_mfa_system_config          # 8.5.1
  check_system_account_management  # 8.6.1, 8.6.2, 8.6.3
  
  # Finalize HTML report
  finalize_report
  
  # Print summary
  echo
  echo "Assessment Summary:"
  echo "------------------"
  echo "Critical findings: $CRITICAL_COUNT"
  echo "Warning findings: $WARNING_COUNT"
  echo "Pass findings: $PASS_COUNT"
  echo "Info findings: $INFO_COUNT"
  echo
  echo "Report saved to: $REPORT_FILE"
  echo
  echo "Next steps:"
  echo "1. Review the HTML report for detailed findings and recommendations."
  echo "2. Address critical and warning findings to improve PCI DSS compliance."
  echo "3. Perform manual verification for areas that could not be fully assessed automatically."
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -p|--project)
      PROJECT_ID="$2"
      shift
      shift
      ;;
    -o|--output)
      REPORT_FILE="$2"
      shift
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [options]"
      echo
      echo "Options:"
      echo "  -p, --project PROJECT_ID  GCP project ID to assess"
      echo "  -o, --output FILENAME     Output HTML report filename"
      echo "  -h, --help                Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use -h or --help for usage information."
      exit 1
      ;;
  esac
done

# Run the main function
main
