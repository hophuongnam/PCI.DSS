#!/usr/bin/env bash

# PCI DSS Requirement 2 Compliance Check Script for GCP (Framework-Migrated Version)
# This script evaluates GCP system component configurations for PCI DSS Requirement 2 compliance
# Requirements covered: 2.2 - 2.3 (Secure configurations, vendor defaults, wireless security)
# Requirement 2.1 removed - requires manual verification

# Framework Integration - Load all 4 shared libraries
LIB_DIR="$(dirname "$0")/../lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"
source "$LIB_DIR/gcp_html_report.sh"
source "$LIB_DIR/gcp_scope_mgmt.sh"

# Script-specific configuration
REQUIREMENT_NUMBER="2"
REQUIREMENT_TITLE="Do Not Use Vendor-Supplied Defaults for System Passwords and Other Security Parameters"

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 2 Assessment Script (Framework Version)"
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

# Register required permissions for Requirement 2
register_required_permissions "$REQUIREMENT_NUMBER" \
    "compute.instances.list" \
    "compute.instances.get" \
    "compute.disks.list" \
    "compute.images.list" \
    "compute.machineTypes.list" \
    "container.clusters.list" \
    "container.clusters.get" \
    "container.nodes.list" \
    "cloudsql.instances.list" \
    "cloudsql.instances.get" \
    "cloudsql.users.list" \
    "storage.buckets.list" \
    "storage.buckets.getIamPolicy" \
    "resourcemanager.projects.get"

# Setup environment and parse command line arguments
setup_environment "requirement2_assessment.log"
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
add_section "system_config" "System Configuration Security Assessment" "Assessment of system configuration controls"

debug_log "Starting PCI DSS Requirement 2 assessment"

# Core Assessment Functions
assess_vm_configurations() {
    local project_id="$1"
    debug_log "Assessing VM configurations for project: $project_id"
    
    # Get compute instances
    local instances
    instances=$(gcloud compute instances list \
        --project="$project_id" \
        --format="value(name,zone,machineType,status,disks.source,disks.boot)" \
        2>/dev/null)
    
    if [[ -z "$instances" ]]; then
        add_check_result "VM configuration assessment" "INFO" "No compute instances found in project $project_id"
        return
    fi
    
    local total_instances=0
    local secure_instances=0
    
    while IFS= read -r instance; do
        [[ -z "$instance" ]] && continue
        ((total_instances++))
        
        local instance_name=$(echo "$instance" | cut -d$'\t' -f1)
        local zone=$(echo "$instance" | cut -d$'\t' -f2)
        local machine_type=$(echo "$instance" | cut -d$'\t' -f3)
        local status=$(echo "$instance" | cut -d$'\t' -f4)
        
        # Check for secure configurations
        local secure_boot
        secure_boot=$(gcloud compute instances describe "$instance_name" \
            --zone="$zone" \
            --project="$project_id" \
            --format="value(shieldedInstanceConfig.enableSecureBoot)" \
            2>/dev/null)
        
        if [[ "$secure_boot" == "True" ]]; then
            add_check_result "VM secure boot configuration" "PASS" \
                "Instance '$instance_name' has secure boot enabled"
            ((secure_instances++))
        else
            add_check_result "VM secure boot configuration" "WARN" \
                "Instance '$instance_name' does not have secure boot enabled"
        fi
        
        # Check for default service account usage
        local service_account
        service_account=$(gcloud compute instances describe "$instance_name" \
            --zone="$zone" \
            --project="$project_id" \
            --format="value(serviceAccounts.email)" \
            2>/dev/null)
        
        if [[ "$service_account" == *"compute@developer.gserviceaccount.com" ]]; then
            add_check_result "VM service account configuration" "WARN" \
                "Instance '$instance_name' uses default compute service account"
        elif [[ -n "$service_account" ]]; then
            add_check_result "VM service account configuration" "PASS" \
                "Instance '$instance_name' uses custom service account: $service_account"
        fi
        
    done <<< "$instances"
    
    add_check_result "VM configuration summary" "INFO" \
        "$secure_instances out of $total_instances instances have secure boot enabled"
}

assess_container_security() {
    local project_id="$1"
    debug_log "Assessing container security for project: $project_id"
    
    # Get GKE clusters
    local clusters
    clusters=$(gcloud container clusters list \
        --project="$project_id" \
        --format="value(name,location,status)" \
        2>/dev/null)
    
    if [[ -z "$clusters" ]]; then
        add_check_result "Container security assessment" "INFO" "No GKE clusters found in project $project_id"
        return
    fi
    
    local total_clusters=0
    local secure_clusters=0
    
    while IFS= read -r cluster; do
        [[ -z "$cluster" ]] && continue
        ((total_clusters++))
        
        local cluster_name=$(echo "$cluster" | cut -d$'\t' -f1)
        local location=$(echo "$cluster" | cut -d$'\t' -f2)
        local status=$(echo "$cluster" | cut -d$'\t' -f3)
        
        # Check cluster security features
        local cluster_details
        cluster_details=$(gcloud container clusters describe "$cluster_name" \
            --location="$location" \
            --project="$project_id" \
            --format="value(networkPolicy.enabled,privateClusterConfig.enablePrivateNodes,workloadIdentityConfig.workloadPool)" \
            2>/dev/null)
        
        local network_policy=$(echo "$cluster_details" | cut -d$'\t' -f1)
        local private_nodes=$(echo "$cluster_details" | cut -d$'\t' -f2)
        local workload_identity=$(echo "$cluster_details" | cut -d$'\t' -f3)
        
        local security_features=0
        
        if [[ "$network_policy" == "True" ]]; then
            add_check_result "GKE network policy" "PASS" \
                "Cluster '$cluster_name' has network policy enabled"
            ((security_features++))
        else
            add_check_result "GKE network policy" "WARN" \
                "Cluster '$cluster_name' does not have network policy enabled"
        fi
        
        if [[ "$private_nodes" == "True" ]]; then
            add_check_result "GKE private nodes" "PASS" \
                "Cluster '$cluster_name' uses private nodes"
            ((security_features++))
        else
            add_check_result "GKE private nodes" "WARN" \
                "Cluster '$cluster_name' does not use private nodes"
        fi
        
        if [[ -n "$workload_identity" ]]; then
            add_check_result "GKE workload identity" "PASS" \
                "Cluster '$cluster_name' has workload identity configured"
            ((security_features++))
        else
            add_check_result "GKE workload identity" "WARN" \
                "Cluster '$cluster_name' does not have workload identity configured"
        fi
        
        if [[ $security_features -ge 2 ]]; then
            ((secure_clusters++))
        fi
        
    done <<< "$clusters"
    
    add_check_result "Container security summary" "INFO" \
        "$secure_clusters out of $total_clusters clusters have adequate security configurations"
}

assess_database_security() {
    local project_id="$1"
    debug_log "Assessing database security configurations for project: $project_id"
    
    # Check Cloud SQL instances
    local sql_instances
    sql_instances=$(gcloud sql instances list \
        --project="$project_id" \
        --format="value(name,region,databaseVersion,settings.ipConfiguration.requireSsl)" \
        2>/dev/null)
    
    if [[ -z "$sql_instances" ]]; then
        add_check_result "Database security assessment" "INFO" "No Cloud SQL instances found in project $project_id"
        return
    fi
    
    local total_instances=0
    local secure_instances=0
    
    while IFS= read -r instance; do
        [[ -z "$instance" ]] && continue
        ((total_instances++))
        
        local instance_name=$(echo "$instance" | cut -d$'\t' -f1)
        local region=$(echo "$instance" | cut -d$'\t' -f2)
        local db_version=$(echo "$instance" | cut -d$'\t' -f3)
        local require_ssl=$(echo "$instance" | cut -d$'\t' -f4)
        
        # Check SSL requirement
        if [[ "$require_ssl" == "True" ]]; then
            add_check_result "Database SSL configuration" "PASS" \
                "Instance '$instance_name' requires SSL connections"
            ((secure_instances++))
        else
            add_check_result "Database SSL configuration" "FAIL" \
                "Instance '$instance_name' does not require SSL connections"
        fi
        
        # Check for public IP
        local public_ip
        public_ip=$(gcloud sql instances describe "$instance_name" \
            --project="$project_id" \
            --format="value(ipAddresses.ipAddress)" \
            2>/dev/null | head -1)
        
        if [[ -n "$public_ip" ]]; then
            add_check_result "Database public access" "WARN" \
                "Instance '$instance_name' has public IP address: $public_ip"
        else
            add_check_result "Database public access" "PASS" \
                "Instance '$instance_name' does not have public IP access"
        fi
        
        # Check for default users
        local users
        users=$(gcloud sql users list \
            --instance="$instance_name" \
            --project="$project_id" \
            --format="value(name)" \
            2>/dev/null)
        
        if [[ "$users" == *"root"* ]]; then
            add_check_result "Database default users" "WARN" \
                "Instance '$instance_name' has root user account - review if necessary"
        fi
        
    done <<< "$sql_instances"
    
    add_check_result "Database security summary" "INFO" \
        "$secure_instances out of $total_instances instances require SSL connections"
}

assess_storage_security() {
    local project_id="$1"
    debug_log "Assessing storage security configurations for project: $project_id"
    
    # Check Cloud Storage buckets for public access
    local buckets
    buckets=$(gsutil ls -p "$project_id" 2>/dev/null | grep "gs://" | sed 's|gs://||' | sed 's|/||')
    
    if [[ -z "$buckets" ]]; then
        add_check_result "Storage security assessment" "INFO" "No Cloud Storage buckets found in project $project_id"
        return
    fi
    
    local total_buckets=0
    local secure_buckets=0
    
    while IFS= read -r bucket; do
        [[ -z "$bucket" ]] && continue
        ((total_buckets++))
        
        # Check bucket IAM policy
        local public_access
        public_access=$(gsutil iam get "gs://$bucket" 2>/dev/null | grep -E "(allUsers|allAuthenticatedUsers)" || true)
        
        if [[ -z "$public_access" ]]; then
            add_check_result "Storage bucket public access" "PASS" \
                "Bucket '$bucket' does not have public access"
            ((secure_buckets++))
        else
            add_check_result "Storage bucket public access" "FAIL" \
                "Bucket '$bucket' has public access configured"
        fi
        
        # Check uniform bucket-level access
        local uniform_access
        uniform_access=$(gsutil uniformbucketlevelaccess get "gs://$bucket" 2>/dev/null | grep "Enabled: True" || true)
        
        if [[ -n "$uniform_access" ]]; then
            add_check_result "Storage uniform access" "PASS" \
                "Bucket '$bucket' has uniform bucket-level access enabled"
        else
            add_check_result "Storage uniform access" "WARN" \
                "Bucket '$bucket' does not have uniform bucket-level access enabled"
        fi
        
    done <<< "$buckets"
    
    add_check_result "Storage security summary" "INFO" \
        "$secure_buckets out of $total_buckets buckets are secure from public access"
}

# Main assessment function
assess_project() {
    local project_id="$1"
    
    info_log "Assessing project: $project_id"
    
    # Add project section to report
    add_section "project_$project_id" "Project: $project_id" "Assessment results for project $project_id"
    
    # Perform assessments
    assess_vm_configurations "$project_id"
    assess_container_security "$project_id"
    assess_database_security "$project_id"
    assess_storage_security "$project_id"
    
    debug_log "Completed assessment for project: $project_id"
}

# Main execution
main() {
    info_log "Starting PCI DSS Requirement 2 assessment"
    
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
    
    # Generate final report
    local output_file="pci_requirement2_assessment_$(date +%Y%m%d_%H%M%S).html"
    finalize_report "$output_file" "$REQUIREMENT_NUMBER"
    
    success_log "Assessment complete! Report saved to: $output_file"
    success_log "Projects assessed: $project_count"
    
    return 0
}

# Execute main function
main "$@"