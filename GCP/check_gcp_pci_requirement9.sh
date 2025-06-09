#!/usr/bin/env bash

# PCI DSS Requirement 9 Compliance Check Script for GCP
# Restrict Physical Access to Cardholder Data

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="9"

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
check_required_permissions "compute.instances.list" "storage.buckets.list" || exit 1

# Initialize HTML report using shared library
# Set output file path
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"

# Initialize HTML report using shared library
initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"

print_status "info" "============================================="
print_status "info" "  PCI DSS 4.0.1 - Requirement 9 (GCP)"
print_status "info" "============================================="
echo ""

# Display scope information using shared library
# Display scope information using shared library - now handled in print_status calls
print_status "info" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "info" "Organization ID: ${ORG_ID}"
else
    print_status "info" "Project ID: ${PROJECT_ID}"
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
    echo "GCP PCI DSS Requirement 9 Assessment Script (Framework Version)"
    echo "============================================================="
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

# Register required permissions for Requirement 9
register_required_permissions "$REQUIREMENT_NUMBER" \
    "cloudkms.keyRings.list" \
    "cloudkms.cryptoKeys.list" \
    "cloudkms.cryptoKeys.getIamPolicy" \
    "storage.buckets.list" \
    "storage.buckets.getIamPolicy" \
    "cloudasset.assets.searchAllResources" \
    "iam.serviceAccounts.list" \
    "logging.logEntries.list" \
    "compute.instances.list" \
    "compute.zones.list" \
    "resourcemanager.projects.get" \
    "resourcemanager.organizations.get" \
    "securitycenter.findings.list"

# Setup environment and parse command line arguments
setup_environment "requirement9_assessment.log"
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
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"
initialize_report "$OUTPUT_FILE" "PCI DSS Requirement $REQUIREMENT_NUMBER Assessment" "$REQUIREMENT_NUMBER"

# Add assessment introduction
add_section $OUTPUT_FILE "physical_security" "Physical Security Controls Assessment" "Assessment of cloud equivalents to physical access controls"

log_debug "Starting PCI DSS Requirement 9 assessment"

# Core Assessment Functions

# 9.1 - Processes and mechanisms for restricting physical access (Manual verification with documentation guidance)
assess_physical_access_processes() {
    local project_id="$1"
    log_debug "Assessing physical access processes for project: $project_id"
    
    # 9.1.1 - Security policies and operational procedures documentation
    add_check_result $OUTPUT_FILE "info" "9.1.1 - Security policies documentation" \
        "Verify documented security policies for Requirement 9 are maintained, up to date, in use, and known to affected parties"
    
    # 9.1.2 - Roles and responsibilities documentation
    add_check_result $OUTPUT_FILE "info" "9.1.2 - Roles and responsibilities" \
        "Verify roles and responsibilities for Requirement 9 activities are documented, assigned, and understood"
    
    # Check for any automated policy enforcement via Cloud Security Command Center or Organization Policy
    local policy_violations
    policy_violations=$(gcloud resource-manager org-policies list \
        --project="$project_id" \
        --filter="constraint:constraints/gcp.restrictVpcPeering OR constraint:constraints/compute.requireShieldedVm" \
        --format="value(constraint)" \
        2>/dev/null)
    
    if [[ -n "$policy_violations" ]]; then
        add_check_result $OUTPUT_FILE "pass" "Organization policy enforcement" \
            "Found organizational policies enforcing security controls in project $project_id"
    else
        add_check_result $OUTPUT_FILE "warning" "Organization policy enforcement" \
            "No organization-level security policies found for project $project_id - consider implementing policy constraints"
    fi
    
    # Check for Security Command Center findings related to physical security
    local security_findings
    security_findings=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND state:ACTIVE" \
        --format="value(category)" \
        2>/dev/null | head -5)
    
    if [[ -n "$security_findings" ]]; then
        local finding_count=$(echo "$security_findings" | wc -l)
        add_check_result "$OUTPUT_FILE" "Security Command Center findings" "warning" \
            "Found $finding_count active security findings for project $project_id - review for physical security implications"
    else
        add_check_result "$OUTPUT_FILE" "Security Command Center findings" "pass" \
            "No active security findings found for project $project_id"
    fi
}

# 9.2 - Physical access controls (Cloud-native IAM and access controls)
assess_iam_access_controls() {
    local project_id="$1"
    log_debug "Assessing IAM access controls for project: $project_id"
    
    # Check service accounts (equivalent to personnel access)
    local service_accounts
    service_accounts=$(gcloud iam service-accounts list \
        --project="$project_id" \
        --format="value(email,disabled)" \
        2>/dev/null)
    
    if [[ -z "$service_accounts" ]]; then
        add_check_result "$OUTPUT_FILE" "Service account assessment" "warning" "No service accounts found in project $project_id"
        return
    fi
    
    local total_accounts=0
    local disabled_accounts=0
    local active_accounts=0
    
    while IFS= read -r account; do
        [[ -z "$account" ]] && continue
        ((total_accounts++))
        
        local email=$(echo "$account" | cut -d$'\t' -f1)
        local disabled=$(echo "$account" | cut -d$'\t' -f2)
        
        if [[ "$disabled" == "True" ]]; then
            ((disabled_accounts++))
            add_check_result "$OUTPUT_FILE" "Disabled service account" "pass" \
                "Service account '$email' is properly disabled"
        else
            ((active_accounts++))
            
            # Check for overly permissive roles
            local roles
            roles=$(gcloud projects get-iam-policy "$project_id" \
                --flatten="bindings[].members" \
                --filter="bindings.members:serviceAccount:$email" \
                --format="value(bindings.role)" \
                2>/dev/null)
            
            local high_risk_roles=0
            while IFS= read -r role; do
                [[ -z "$role" ]] && continue
                
                if [[ "$role" == *"owner"* ]] || [[ "$role" == *"editor"* ]] || [[ "$role" == *"admin"* ]]; then
                    ((high_risk_roles++))
                fi
            done <<< "$roles"
            
            if [[ $high_risk_roles -gt 0 ]]; then
                add_check_result "$OUTPUT_FILE" "High-risk service account" "fail" \
                    "Service account '$email' has $high_risk_roles high-privilege roles"
            else
                add_check_result "$OUTPUT_FILE" "Service account privilege check" "pass" \
                    "Service account '$email' follows principle of least privilege"
            fi
        fi
        
    done <<< "$service_accounts"
    
    add_check_result "$OUTPUT_FILE" "Service account summary" "info" \
        "Found $total_accounts service accounts ($active_accounts active, $disabled_accounts disabled)"
}

# 9.3 - Personnel access authorization (KMS key management as cryptographic access control)
assess_kms_key_security() {
    local project_id="$1"
    log_debug "Assessing KMS key security for project: $project_id"
    
    # List key rings
    local key_rings
    key_rings=$(gcloud kms keyrings list \
        --location=global \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -z "$key_rings" ]]; then
        # Try common locations if global doesn't work
        local locations=("us-central1" "us-east1" "europe-west1")
        for location in "${locations[@]}"; do
            key_rings=$(gcloud kms keyrings list \
                --location="$location" \
                --project="$project_id" \
                --format="value(name)" \
                2>/dev/null)
            [[ -n "$key_rings" ]] && break
        done
    fi
    
    if [[ -z "$key_rings" ]]; then
        add_check_result "$OUTPUT_FILE" "KMS assessment" "info" "No KMS key rings found in project $project_id"
        return
    fi
    
    local total_keys=0
    local secure_keys=0
    
    while IFS= read -r keyring; do
        [[ -z "$keyring" ]] && continue
        
        local location=$(echo "$keyring" | cut -d'/' -f4)
        local keyring_name=$(echo "$keyring" | cut -d'/' -f6)
        
        # List keys in keyring
        local keys
        keys=$(gcloud kms keys list \
            --keyring="$keyring_name" \
            --location="$location" \
            --project="$project_id" \
            --format="value(name,purpose)" \
            2>/dev/null)
        
        while IFS= read -r key; do
            [[ -z "$key" ]] && continue
            ((total_keys++))
            
            local key_name=$(echo "$key" | cut -d$'\t' -f1)
            local purpose=$(echo "$key" | cut -d$'\t' -f2)
            
            # Check key IAM policy
            local key_policy
            key_policy=$(gcloud kms keys get-iam-policy "$key_name" \
                --project="$project_id" \
                --format="value(bindings[].members[])" \
                2>/dev/null)
            
            local external_access=0
            while IFS= read -r member; do
                [[ -z "$member" ]] && continue
                
                if [[ "$member" == "allUsers" ]] || [[ "$member" == "allAuthenticatedUsers" ]]; then
                    ((external_access++))
                fi
            done <<< "$key_policy"
            
            if [[ $external_access -eq 0 ]]; then
                ((secure_keys++))
                add_check_result "$OUTPUT_FILE" "KMS key access control" "pass" \
                    "Key '$(basename "$key_name")' has proper access restrictions"
            else
                add_check_result "$OUTPUT_FILE" "KMS key security issue" "fail" \
                    "Key '$(basename "$key_name")' allows external access ($external_access violations)"
            fi
            
        done <<< "$keys"
        
    done <<< "$key_rings"
    
    if [[ $total_keys -gt 0 ]]; then
        local security_percentage=$((secure_keys * 100 / total_keys))
        add_check_result "$OUTPUT_FILE" "KMS security summary" "info" \
            "$secure_keys out of $total_keys keys properly secured ($security_percentage%)"
    fi
}

# 9.4 - Media security (Cloud Storage encryption and lifecycle controls)
assess_storage_media_security() {
    local project_id="$1"
    log_debug "Assessing storage media security for project: $project_id"
    
    # List storage buckets
    local buckets
    buckets=$(gcloud storage buckets list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -z "$buckets" ]]; then
        add_check_result "$OUTPUT_FILE" "Storage assessment" "info" "No storage buckets found in project $project_id"
        return
    fi
    
    local total_buckets=0
    local encrypted_buckets=0
    local lifecycle_buckets=0
    local public_buckets=0
    
    while IFS= read -r bucket; do
        [[ -z "$bucket" ]] && continue
        ((total_buckets++))
        
        # Check encryption
        local encryption_info
        encryption_info=$(gcloud storage buckets describe "gs://$bucket" \
            --format="value(encryption.defaultKmsKeyName)" \
            2>/dev/null)
        
        if [[ -n "$encryption_info" ]]; then
            ((encrypted_buckets++))
            add_check_result "$OUTPUT_FILE" "Storage encryption" "pass" \
                "Bucket '$bucket' uses customer-managed encryption"
        else
            add_check_result "$OUTPUT_FILE" "Storage encryption" "warning" \
                "Bucket '$bucket' uses Google-managed encryption (consider CMEK)"
        fi
        
        # Check lifecycle policy
        local lifecycle_policy
        lifecycle_policy=$(gcloud storage buckets describe "gs://$bucket" \
            --format="value(lifecycle.rule[].action.type)" \
            2>/dev/null)
        
        if [[ -n "$lifecycle_policy" ]]; then
            ((lifecycle_buckets++))
            add_check_result "$OUTPUT_FILE" "Storage lifecycle policy" "pass" \
                "Bucket '$bucket' has lifecycle policies configured"
        else
            add_check_result "$OUTPUT_FILE" "Storage lifecycle policy" "warning" \
                "Bucket '$bucket' lacks lifecycle policies for data retention"
        fi
        
        # Check public access
        local public_access
        public_access=$(gcloud storage buckets describe "gs://$bucket" \
            --format="value(iamConfiguration.publicAccessPrevention)" \
            2>/dev/null)
        
        if [[ "$public_access" == "enforced" ]]; then
            add_check_result "$OUTPUT_FILE" "Storage public access" "pass" \
                "Bucket '$bucket' has public access prevention enforced"
        else
            ((public_buckets++))
            add_check_result "$OUTPUT_FILE" "Storage public access" "fail" \
                "Bucket '$bucket' allows public access - security risk"
        fi
        
    done <<< "$buckets"
    
    # Summary assessment
    add_check_result "$OUTPUT_FILE" "Storage security summary" "info" \
        "Buckets: $total_buckets total, $encrypted_buckets with CMEK, $lifecycle_buckets with lifecycle, $public_buckets allow public access"
}

# 9.4.5 - Electronic media inventory (Cloud Asset Inventory)
assess_asset_inventory() {
    local project_id="$1"
    log_debug "Assessing asset inventory for project: $project_id"
    
    # Use Cloud Asset Inventory to list resources
    local assets
    assets=$(gcloud asset search-all-resources \
        --scope="projects/$project_id" \
        --asset-types="compute.googleapis.com/Instance,storage.googleapis.com/Bucket,cloudkms.googleapis.com/CryptoKey" \
        --format="value(assetType,name,location)" \
        2>/dev/null)
    
    if [[ -z "$assets" ]]; then
        add_check_result "$OUTPUT_FILE" "Asset inventory" "warning" "No assets found in inventory for project $project_id"
        return
    fi
    
    local compute_instances=0
    local storage_buckets=0
    local kms_keys=0
    local total_assets=0
    
    while IFS= read -r asset; do
        [[ -z "$asset" ]] && continue
        ((total_assets++))
        
        local asset_type=$(echo "$asset" | cut -d$'\t' -f1)
        local asset_name=$(echo "$asset" | cut -d$'\t' -f2)
        local location=$(echo "$asset" | cut -d$'\t' -f3)
        
        case "$asset_type" in
            "compute.googleapis.com/Instance")
                ((compute_instances++))
                ;;
            "storage.googleapis.com/Bucket")
                ((storage_buckets++))
                ;;
            "cloudkms.googleapis.com/CryptoKey")
                ((kms_keys++))
                ;;
        esac
        
    done <<< "$assets"
    
    add_check_result "$OUTPUT_FILE" "Asset inventory summary" "pass" \
        "Cloud Asset Inventory tracking $total_assets assets: $compute_instances instances, $storage_buckets buckets, $kms_keys keys"
    
    # Check for logging of asset changes
    local audit_logs
    audit_logs=$(gcloud logging read \
        'protoPayload.serviceName="cloudasset.googleapis.com"' \
        --project="$project_id" \
        --limit=10 \
        --format="value(timestamp)" \
        2>/dev/null)
    
    if [[ -n "$audit_logs" ]]; then
        add_check_result "$OUTPUT_FILE" "Asset inventory logging" "pass" \
            "Cloud Asset Inventory changes are being logged"
    else
        add_check_result "$OUTPUT_FILE" "Asset inventory logging" "warning" \
            "No recent Cloud Asset Inventory audit logs found"
    fi
}

# 9.5 - POI devices (IoT Core device management if applicable)
assess_iot_device_security() {
    local project_id="$1"
    log_debug "Assessing IoT device security for project: $project_id"
    
    # Check if IoT Core is being used
    local iot_registries
    iot_registries=$(gcloud iot registries list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -z "$iot_registries" ]]; then
        add_check_result "$OUTPUT_FILE" "IoT device assessment" "info" "No IoT Core registries found - POI device controls not applicable"
        return
    fi
    
    local total_devices=0
    local secure_devices=0
    
    while IFS= read -r registry; do
        [[ -z "$registry" ]] && continue
        
        local registry_name=$(basename "$registry")
        local region=$(echo "$registry" | cut -d'/' -f4)
        
        # List devices in registry
        local devices
        devices=$(gcloud iot devices list \
            --registry="$registry_name" \
            --region="$region" \
            --project="$project_id" \
            --format="value(id,blocked)" \
            2>/dev/null)
        
        while IFS= read -r device; do
            [[ -z "$device" ]] && continue
            ((total_devices++))
            
            local device_id=$(echo "$device" | cut -d$'\t' -f1)
            local blocked=$(echo "$device" | cut -d$'\t' -f2)
            
            if [[ "$blocked" == "false" ]]; then
                ((secure_devices++))
                add_check_result "$OUTPUT_FILE" "IoT device status" "pass" \
                    "Device '$device_id' is active and properly managed"
            else
                add_check_result "$OUTPUT_FILE" "IoT device blocked" "warning" \
                    "Device '$device_id' is blocked - verify if intentional"
            fi
            
        done <<< "$devices"
        
    done <<< "$iot_registries"
    
    if [[ $total_devices -gt 0 ]]; then
        add_check_result "$OUTPUT_FILE" "IoT device summary" "info" \
            "Found $total_devices IoT devices ($secure_devices active, $((total_devices - secure_devices)) blocked)"
    fi
}

# Manual verification guidance
add_manual_verification_guidance() {
    log_debug "Adding manual verification guidance"
    
    add_section "$OUTPUT_FILE" "manual_verification" "Manual Verification Required" "Physical security controls requiring manual assessment"
    
    add_check_result "$OUTPUT_FILE" "9.1 - Physical security policy" "info" \
        "Verify documented processes for restricting physical access to cardholder data environment"
    
    add_check_result "$OUTPUT_FILE" "9.2.1 - Facility access controls" "info" \
        "Verify physical access controls at data center facilities used by cloud provider"
    
    add_check_result "$OUTPUT_FILE" "9.2.2 - Network jack controls" "info" \
        "Verify controls for publicly accessible network jacks in office environments"
    
    add_check_result "$OUTPUT_FILE" "9.3.1 - Personnel access procedures" "info" \
        "Verify procedures for authorizing physical access to sensitive areas"
    
    add_check_result "$OUTPUT_FILE" "9.3.2 - Visitor authorization" "info" \
        "Verify visitor authorization and escort procedures for sensitive areas"
    
    add_check_result "$OUTPUT_FILE" "Physical data center security" "info" \
        "Review Google Cloud's SOC 2 Type II and ISO 27001 certifications for data center physical security"
}

# Main assessment function
assess_project() {
    local project_id="$1"
    
    info_log "Assessing project: $project_id"
    
    # Add project section to report
    add_section "$OUTPUT_FILE" "project_$project_id" "Project: $project_id" "Assessment results for project $project_id"
    
    # Perform assessments
    assess_physical_access_processes "$project_id"
    assess_iam_access_controls "$project_id"
    assess_kms_key_security "$project_id"
    assess_storage_media_security "$project_id"
    assess_asset_inventory "$project_id"
    assess_iot_device_security "$project_id"
    
    log_debug "Completed assessment for project: $project_id"
}

# Main execution
main() {
    info_log "Starting PCI DSS Requirement 9 assessment"
    
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
    local output_file="pci_requirement9_assessment_$(date +%Y%m%d_%H%M%S).html"
    finalize_report "$output_file" "$REQUIREMENT_NUMBER"
    
    success_log "Assessment complete! Report saved to: $output_file"
    success_log "Projects assessed: $project_count"
    
    return 0
}

# Execute main function
main "$@"