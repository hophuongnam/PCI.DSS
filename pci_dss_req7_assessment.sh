#!/bin/bash
#
# PCI DSS v4.0.1 Requirement 7 Assessment Script for Google Cloud Platform
# Focuses on: Restrict Access to System Components and Cardholder Data by Business Need to Know
#
# This script assesses GCP environments against PCI DSS v4.0.1 Requirement 7
# and generates an HTML report with findings and recommendations.

# Set strict error handling
set -o pipefail

# Global variables
PROJECT_ID=""
REPORT_FILE="pci_dss_req7_report_$(date +%Y%m%d_%H%M%S).html"
TEMP_DIR=$(mktemp -d)
FINDINGS=()
CRITICAL_COUNT=0
WARNING_COUNT=0
PASS_COUNT=0

# Color codes for terminal output
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# HTML report styling
HTML_STYLE="
<style>
    body { font-family: Arial, sans-serif; margin: 20px; color: #333; line-height: 1.6; }
    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
    h2 { color: #2c3e50; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
    h3 { color: #2c3e50; margin-top: 20px; }
    .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
    .finding { margin: 15px 0; padding: 15px; border-radius: 5px; border-left: 5px solid #ddd; }
    .critical { background-color: #ffebee; border-left-color: #e53935; }
    .warning { background-color: #fff8e1; border-left-color: #ffb300; }
    .pass { background-color: #e8f5e9; border-left-color: #43a047; }
    .requirement { font-weight: bold; }
    .details { margin-top: 10px; }
    .recommendation { margin-top: 10px; font-style: italic; }
    table { border-collapse: collapse; width: 100%; margin: 20px 0; }
    th, td { text-align: left; padding: 12px; }
    th { background-color: #3498db; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    .stats { display: flex; justify-content: space-around; margin: 30px 0; }
    .stat-box { text-align: center; padding: 20px; border-radius: 5px; width: 25%; }
    .critical-stat { background-color: #ffebee; }
    .warning-stat { background-color: #fff8e1; }
    .pass-stat { background-color: #e8f5e9; }
    pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }
    code { font-family: monospace; background-color: #f5f5f5; padding: 2px 4px; border-radius: 3px; }
</style>
"

# Function to log messages
log() {
    local level=$1
    local message=$2
    local color=$NC
    
    case $level in
        "INFO") color=$BLUE ;;
        "SUCCESS") color=$GREEN ;;
        "WARNING") color=$YELLOW ;;
        "ERROR") color=$RED ;;
    esac
    
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message${NC}"
}

# Function to check if jq is installed
check_dependencies() {
    if ! command -v jq &> /dev/null; then
        log "ERROR" "jq is not installed. Please install jq to continue."
        echo "On macOS, you can install it with: brew install jq"
        exit 1
    fi
    
    if ! command -v gcloud &> /dev/null; then
        log "ERROR" "gcloud CLI is not installed. Please install Google Cloud SDK to continue."
        echo "Visit https://cloud.google.com/sdk/docs/install for installation instructions."
        exit 1
    fi
}

# Function to validate GCP authentication and project access
validate_gcp_access() {
    log "INFO" "Validating GCP authentication and project access..."
    
    # Check if user is authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        log "ERROR" "Not authenticated to GCP. Please run 'gcloud auth login' first."
        exit 1
    fi
    
    # If project ID is not provided, try to get the default project
    if [[ -z "$PROJECT_ID" ]]; then
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
        if [[ -z "$PROJECT_ID" ]]; then
            log "ERROR" "No project ID specified and no default project set. Please specify a project with --project flag."
            exit 1
        fi
    fi
    
    # Verify project exists and is accessible
    if ! gcloud projects describe "$PROJECT_ID" &> /dev/null; then
        log "ERROR" "Project $PROJECT_ID not found or not accessible. Please check the project ID and your permissions."
        exit 1
    fi
    
    log "SUCCESS" "Successfully validated access to project: $PROJECT_ID"
}

# Function to safely parse JSON and handle errors
parse_json() {
    local json_file=$1
    local default_value=${2:-"[]"}
    
    if [[ ! -f "$json_file" ]]; then
        echo "$default_value"
        return 1
    fi
    
    # Validate JSON
    if ! jq empty "$json_file" 2>/dev/null; then
        log "WARNING" "Invalid JSON in $json_file, returning default value"
        echo "$default_value"
        return 1
    fi
    
    cat "$json_file"
    return 0
}

# Function to add a finding to the report
add_finding() {
    local severity=$1
    local requirement=$2
    local title=$3
    local details=$4
    local recommendation=$5
    
    # Update counters
    case $severity in
        "CRITICAL") ((CRITICAL_COUNT++)) ;;
        "WARNING") ((WARNING_COUNT++)) ;;
        "PASS") ((PASS_COUNT++)) ;;
    esac
    
    # Add to findings array
    FINDINGS+=("$severity|$requirement|$title|$details|$recommendation")
}

# Function to escape HTML special characters
escape_html() {
    local text="$1"
    text="${text//&/&amp;}"
    text="${text//</&lt;}"
    text="${text//>/&gt;}"
    text="${text//\"/&quot;}"
    text="${text//\'/&#39;}"
    echo "$text"
}

# Function to generate the HTML report
generate_html_report() {
    log "INFO" "Generating HTML report..."
    
    # Create HTML header
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS v4.0.1 Requirement 7 Assessment Report</title>
    $HTML_STYLE
</head>
<body>
    <h1>PCI DSS v4.0.1 Requirement 7 Assessment Report</h1>
    <p><strong>Project ID:</strong> $PROJECT_ID</p>
    <p><strong>Assessment Date:</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report presents the findings of an automated assessment of Google Cloud Platform resources against PCI DSS v4.0.1 Requirement 7: Restrict Access to System Components and Cardholder Data by Business Need to Know.</p>
        
        <div class="stats">
            <div class="stat-box critical-stat">
                <h3>Critical Findings</h3>
                <p style="font-size: 24px; font-weight: bold;">$CRITICAL_COUNT</p>
            </div>
            <div class="stat-box warning-stat">
                <h3>Warnings</h3>
                <p style="font-size: 24px; font-weight: bold;">$WARNING_COUNT</p>
            </div>
            <div class="stat-box pass-stat">
                <h3>Passed Checks</h3>
                <p style="font-size: 24px; font-weight: bold;">$PASS_COUNT</p>
            </div>
        </div>
    </div>
    
    <h2>Requirement 7 Overview</h2>
    <p>Requirement 7 focuses on restricting access to system components and cardholder data by business need to know. This includes implementing an access control model, assigning appropriate access, and managing access through a system that enforces permissions based on job classification and function.</p>
    
    <h2>Detailed Findings</h2>
EOF
    
    # Add each finding to the report
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r severity requirement title details recommendation <<< "$finding"
        
        # Determine CSS class based on severity
        css_class="finding"
        case $severity in
            "CRITICAL") css_class="finding critical" ;;
            "WARNING") css_class="finding warning" ;;
            "PASS") css_class="finding pass" ;;
        esac
        
        # Escape HTML in text fields
        title=$(escape_html "$title")
        details=$(escape_html "$details")
        recommendation=$(escape_html "$recommendation")
        
        # Add finding to HTML
        cat >> "$REPORT_FILE" << EOF
    <div class="$css_class">
        <h3>$title</h3>
        <p class="requirement">PCI DSS Requirement: $requirement</p>
        <p>Severity: $severity</p>
        <div class="details">
            <p><strong>Details:</strong></p>
            <pre>$details</pre>
        </div>
        <div class="recommendation">
            <p><strong>Recommendation:</strong></p>
            <p>$recommendation</p>
        </div>
    </div>
EOF
    done
    
    # Add HTML footer
    cat >> "$REPORT_FILE" << EOF
    <h2>Assessment Methodology</h2>
    <p>This assessment was performed using automated analysis of GCP resources via the Google Cloud CLI. The script examined IAM policies, service accounts, and access controls to evaluate compliance with PCI DSS Requirement 7.</p>
    
    <h2>Limitations</h2>
    <p>This automated assessment has the following limitations:</p>
    <ul>
        <li>It only assesses configurations visible through the GCP API with the current user's permissions.</li>
        <li>It does not assess custom applications or data access within applications.</li>
        <li>Manual verification is recommended to confirm findings and ensure complete coverage.</li>
        <li>The assessment represents a point-in-time evaluation and should be repeated regularly.</li>
    </ul>
    
    <h2>Next Steps</h2>
    <p>For each finding, review the recommendation and implement appropriate controls to address any issues. After remediation, run the assessment again to verify that issues have been resolved.</p>
    
    <footer>
        <p>Report generated on $(date '+%Y-%m-%d %H:%M:%S')</p>
    </footer>
</body>
</html>
EOF
    
    log "SUCCESS" "HTML report generated: $REPORT_FILE"
}

# Function to clean up temporary files
cleanup() {
    log "INFO" "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    log "SUCCESS" "Cleanup completed"
}

# Function to assess Requirement 7.1: Processes and mechanisms for restricting access
assess_req_7_1() {
    log "INFO" "Assessing Requirement 7.1: Processes and mechanisms for restricting access..."
    
    # This is primarily a documentation and process requirement
    # We can only check if there are IAM policies in place, not their documentation
    
    # Check if organization policies are configured
    local org_policies_file="$TEMP_DIR/org_policies.json"
    gcloud resource-manager org-policies list --project="$PROJECT_ID" --format=json > "$org_policies_file" 2>/dev/null
    
    local org_policies=$(parse_json "$org_policies_file")
    local policy_count=$(echo "$org_policies" | jq 'length')
    
    if [[ "$policy_count" -gt 0 ]]; then
        add_finding "PASS" "7.1.1, 7.1.2" "Organization policies are defined" \
            "Found $policy_count organization policies configured for the project." \
            "Continue to maintain documentation of security policies and operational procedures for access control. Ensure roles and responsibilities for performing access control activities are documented, assigned, and understood."
    else
        add_finding "WARNING" "7.1.1, 7.1.2" "Limited organization policies detected" \
            "No organization policies were found for the project. Organization policies help enforce security standards across your GCP resources." \
            "Implement organization policies to enforce security standards. Document security policies and operational procedures for access control. Ensure roles and responsibilities for performing access control activities are documented, assigned, and understood."
    fi
}

# Function to assess Requirement 7.2: Access to system components and data is appropriately defined and assigned
assess_req_7_2() {
    log "INFO" "Assessing Requirement 7.2: Access to system components and data is appropriately defined and assigned..."
    
    # Get project IAM policy
    local iam_policy_file="$TEMP_DIR/iam_policy.json"
    gcloud projects get-iam-policy "$PROJECT_ID" --format=json > "$iam_policy_file" 2>/dev/null
    
    local iam_policy=$(parse_json "$iam_policy_file")
    
    # Check for overly permissive roles (owner, editor)
    local high_privilege_bindings=$(echo "$iam_policy" | jq '.bindings[] | select(.role == "roles/owner" or .role == "roles/editor")')
    local high_privilege_count=$(echo "$high_privilege_bindings" | jq -s 'length')
    
    if [[ "$high_privilege_count" -gt 0 ]]; then
        local details=$(echo "$high_privilege_bindings" | jq -r '.role + ": " + (.members | join(", "))')
        add_finding "WARNING" "7.2.1, 7.2.2" "Overly permissive roles detected" \
            "Found $high_privilege_count high-privilege role bindings (owner/editor) which may violate least privilege principles:\n$details" \
            "Review these high-privilege roles and consider using more granular, custom roles that follow the principle of least privilege. Implement a formal access control model that grants access based on job classification and function."
    else
        add_finding "PASS" "7.2.1, 7.2.2" "No overly permissive roles detected" \
            "No high-privilege role bindings (owner/editor) were found, which is consistent with the principle of least privilege." \
            "Continue to maintain a proper access control model that grants access based on job classification and function with least privileges required."
    fi
    
    # Check for service accounts with excessive permissions
    local service_accounts_file="$TEMP_DIR/service_accounts.json"
    gcloud iam service-accounts list --project="$PROJECT_ID" --format=json > "$service_accounts_file" 2>/dev/null
    
    local service_accounts=$(parse_json "$service_accounts_file")
    local service_account_count=$(echo "$service_accounts" | jq 'length')
    
    if [[ "$service_account_count" -gt 0 ]]; then
        local high_privilege_sa=0
        local high_privilege_sa_details=""
        
        for email in $(echo "$service_accounts" | jq -r '.[].email'); do
            local sa_policy_file="$TEMP_DIR/sa_policy_${email//[@.]/_}.json"
            gcloud iam service-accounts get-iam-policy "$email" --format=json > "$sa_policy_file" 2>/dev/null
            
            local sa_project_policy=$(echo "$iam_policy" | jq -r --arg email "serviceAccount:$email" '.bindings[] | select(.members[] | contains($email)) | .role')
            
            if [[ "$sa_project_policy" == *"roles/owner"* || "$sa_project_policy" == *"roles/editor"* ]]; then
                ((high_privilege_sa++))
                high_privilege_sa_details+="$email has high-privilege role: $sa_project_policy\n"
            fi
        done
        
        if [[ "$high_privilege_sa" -gt 0 ]]; then
            add_finding "CRITICAL" "7.2.2, 7.2.3" "Service accounts with excessive permissions" \
                "Found $high_privilege_sa service accounts with high-privilege roles:\n$high_privilege_sa_details" \
                "Review service account permissions and remove excessive privileges. Service accounts should follow the principle of least privilege and have only the permissions necessary for their function."
        else
            add_finding "PASS" "7.2.2, 7.2.3" "Service accounts follow least privilege principle" \
                "No service accounts with high-privilege roles (owner/editor) were found." \
                "Continue to ensure service accounts follow the principle of least privilege and have only the permissions necessary for their function."
        fi
    fi
    
    # Check for custom roles to see if there's evidence of a structured access model
    local custom_roles_file="$TEMP_DIR/custom_roles.json"
    gcloud iam roles list --project="$PROJECT_ID" --format=json > "$custom_roles_file" 2>/dev/null
    
    local custom_roles=$(parse_json "$custom_roles_file")
    local custom_role_count=$(echo "$custom_roles" | jq 'length')
    
    if [[ "$custom_role_count" -gt 0 ]]; then
        add_finding "PASS" "7.2.1, 7.2.2" "Custom roles implemented" \
            "Found $custom_role_count custom IAM roles, which suggests a structured approach to access control." \
            "Continue to maintain custom roles that follow the principle of least privilege. Regularly review these roles to ensure they remain appropriate."
    else
        add_finding "WARNING" "7.2.1, 7.2.2" "No custom roles detected" \
            "No custom IAM roles were found. Custom roles help implement least privilege by providing granular permissions." \
            "Consider implementing custom IAM roles that provide only the permissions necessary for specific job functions, following the principle of least privilege."
    fi
    
    # Check for evidence of regular access reviews (audit logs)
    local audit_config=$(echo "$iam_policy" | jq '.auditConfigs')
    
    if [[ "$audit_config" != "null" && "$audit_config" != "[]" ]]; then
        add_finding "PASS" "7.2.4" "Audit logging is configured" \
            "Audit logging is configured, which can support regular access reviews." \
            "Ensure you have a process to review all user accounts and related access privileges at least once every six months."
    else
        add_finding "WARNING" "7.2.4" "Limited audit logging configuration" \
            "Audit logging configuration appears to be limited or not set up. Audit logs are essential for regular access reviews." \
            "Configure audit logging to track access changes. Implement a process to review all user accounts and related access privileges at least once every six months."
    fi
}

# Function to assess Requirement 7.3: Access to system components and data is managed via an access control system
assess_req_7_3() {
    log "INFO" "Assessing Requirement 7.3: Access to system components and data is managed via an access control system..."
    
    # Check if Cloud IAM is being used effectively
    local iam_policy_file="$TEMP_DIR/iam_policy.json"
    if [[ ! -f "$iam_policy_file" ]]; then
        gcloud projects get-iam-policy "$PROJECT_ID" --format=json > "$iam_policy_file" 2>/dev/null
    fi
    
    local iam_policy=$(parse_json "$iam_policy_file")
    local binding_count=$(echo "$iam_policy" | jq '.bindings | length')
    
    if [[ "$binding_count" -gt 0 ]]; then
        # Check for public access (allUsers or allAuthenticatedUsers)
        local public_access=$(echo "$iam_policy" | jq '.bindings[] | select(.members[] | contains("allUsers") or contains("allAuthenticatedUsers"))')
        
        if [[ -n "$public_access" && "$public_access" != "null" ]]; then
            add_finding "CRITICAL" "7.3.1, 7.3.3" "Public access detected in IAM policies" \
                "IAM policies contain public access grants (allUsers or allAuthenticatedUsers), which violates the principle of 'deny all' by default:\n$(echo "$public_access" | jq -r '.')" \
                "Remove public access grants from IAM policies. Access should be restricted based on the principle of 'deny all' by default, with explicit permissions granted only to authorized users based on business need."
        else
            add_finding "PASS" "7.3.1, 7.3.3" "No public access detected in IAM policies" \
                "No public access grants (allUsers or allAuthenticatedUsers) were found in IAM policies." \
                "Continue to maintain the principle of 'deny all' by default, with explicit permissions granted only to authorized users based on business need."
        fi
        
        # Check for role diversity (indication of job classification-based access)
        local unique_roles=$(echo "$iam_policy" | jq '.bindings[].role' | sort | uniq | wc -l)
        
        if [[ "$unique_roles" -lt 3 ]]; then
            add_finding "WARNING" "7.3.2" "Limited role diversity detected" \
                "Only $unique_roles unique roles found, which may indicate insufficient role separation based on job classification and function." \
                "Implement a more diverse set of roles based on job classification and function. Use custom roles to provide granular permissions that align with specific job responsibilities."
        else
            add_finding "PASS" "7.3.2" "Diverse roles implemented" \
                "Found $unique_roles unique roles, suggesting role separation based on job classification and function." \
                "Continue to maintain role diversity based on job classification and function. Regularly review roles to ensure they remain appropriate."
        fi
    else
        add_finding "WARNING" "7.3.1, 7.3.2, 7.3.3" "Limited IAM policy configuration" \
            "IAM policy appears to have limited configuration. A robust access control system is essential for PCI DSS compliance." \
            "Implement a comprehensive IAM policy that restricts access based on users' need to know, enforces permissions based on job classification, and is set to 'deny all' by default."
    fi
    
    # Check for VPC Service Controls (additional access control system)
    local vpc_sc_file="$TEMP_DIR/vpc_sc.json"
    gcloud access-context-manager perimeters list --format=json > "$vpc_sc_file" 2>/dev/null
    
    local vpc_sc=$(parse_json "$vpc_sc_file")
    local perimeter_count=$(echo "$vpc_sc" | jq 'length')
    
    if [[ "$perimeter_count" -gt 0 ]]; then
        add_finding "PASS" "7.3.1" "VPC Service Controls implemented" \
            "VPC Service Controls are implemented, providing additional access restrictions based on network boundaries." \
            "Continue to maintain VPC Service Controls to restrict access to sensitive resources based on network boundaries."
    else
        add_finding "WARNING" "7.3.1" "No VPC Service Controls detected" \
            "No VPC Service Controls were detected. VPC Service Controls provide additional access restrictions based on network boundaries." \
            "Consider implementing VPC Service Controls to provide additional access restrictions for sensitive resources based on network boundaries."
    fi
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --project)
                PROJECT_ID="$2"
                shift 2
                ;;
            --output)
                REPORT_FILE="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [--project PROJECT_ID] [--output REPORT_FILE]"
                echo "Assesses GCP environment against PCI DSS v4.0.1 Requirement 7"
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                echo "Usage: $0 [--project PROJECT_ID] [--output REPORT_FILE]"
                exit 1
                ;;
        esac
    done
    
    # Check dependencies
    check_dependencies
    
    # Validate GCP access
    validate_gcp_access
    
    # Run assessments
    assess_req_7_1
    assess_req_7_2
    assess_req_7_3
    
    # Generate HTML report
    generate_html_report
    
    # Clean up
    cleanup
    
    # Print summary
    log "INFO" "Assessment complete. Summary of findings:"
    log "INFO" "Critical: $CRITICAL_COUNT, Warning: $WARNING_COUNT, Pass: $PASS_COUNT"
    log "SUCCESS" "Report generated: $REPORT_FILE"
}

# Run the main function with all arguments
main "$@"
