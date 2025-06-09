#!/usr/bin/env bash

# PCI DSS Requirement 1 Compliance Check Script for GCP (Framework-Migrated Version)
# This script evaluates GCP network security controls for PCI DSS Requirement 1 compliance
# Requirements covered: 1.2 - 1.5 (Network Security Controls, CDE isolation, etc.)
# Requirement 1.1 removed - requires manual verification

# Framework Integration - Load all 4 shared libraries
LIB_DIR="$(dirname "$0")/../lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"
source "$LIB_DIR/gcp_html_report.sh"
source "$LIB_DIR/gcp_scope_mgmt.sh"

# Script-specific configuration
REQUIREMENT_NUMBER="1"
REQUIREMENT_TITLE="Install and Maintain a Firewall Configuration to Protect Cardholder Data"

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 1 Assessment Script (Framework Version)"
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

# Register required permissions for Requirement 1
register_required_permissions "$REQUIREMENT_NUMBER" \
    "compute.firewalls.list" \
    "compute.networks.list" \
    "compute.subnetworks.list" \
    "compute.instances.list" \
    "compute.backendServices.list" \
    "compute.forwardingRules.list" \
    "compute.routers.list" \
    "compute.routes.list" \
    "resourcemanager.projects.get"

# Setup environment and parse command line arguments
setup_environment "requirement1_assessment.log"
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
add_section "network_security" "Network Security Controls Assessment" "Assessment of firewall rules and network security"

debug_log "Starting PCI DSS Requirement 1 assessment"

# Core Assessment Functions
assess_firewall_rules() {
    local project_id="$1"
    debug_log "Assessing firewall rules for project: $project_id"
    
    # Get all firewall rules
    local firewall_rules
    firewall_rules=$(gcloud compute firewall-rules list \
        --project="$project_id" \
        --format="value(name,direction,priority,sourceRanges.list():label=SOURCE_RANGES,allowed[].map().firewall_rule().list():label=ALLOWED_RULES,targetTags.list():label=TARGET_TAGS)" \
        2>/dev/null)
    
    if [[ -z "$firewall_rules" ]]; then
        add_check_result "No firewall rules found" "WARN" "No firewall rules configured in project $project_id"
        return
    fi
    
    # Analyze firewall rules
    local high_risk_rules=0
    local total_rules=0
    
    while IFS= read -r rule; do
        ((total_rules++))
        local rule_name=$(echo "$rule" | cut -d$'\t' -f1)
        local direction=$(echo "$rule" | cut -d$'\t' -f2)
        local priority=$(echo "$rule" | cut -d$'\t' -f3)
        local source_ranges=$(echo "$rule" | cut -d$'\t' -f4)
        local allowed_rules=$(echo "$rule" | cut -d$'\t' -f5)
        local target_tags=$(echo "$rule" | cut -d$'\t' -f6)
        
        # Check for overly permissive rules
        if [[ "$source_ranges" == *"0.0.0.0/0"* ]] && [[ "$direction" == "INGRESS" ]]; then
            if [[ "$allowed_rules" == *"tcp:22"* ]] || [[ "$allowed_rules" == *"tcp:3389"* ]] || [[ "$allowed_rules" == *"tcp:1-65535"* ]]; then
                add_check_result "High-risk firewall rule detected" "FAIL" \
                    "Rule '$rule_name' allows broad access from internet. Source: $source_ranges, Allowed: $allowed_rules"
                ((high_risk_rules++))
            fi
        fi
        
        # Check for default deny rules
        if [[ "$rule_name" == *"default-deny"* ]] || [[ "$priority" -gt 65000 ]]; then
            add_check_result "Default deny rule found" "PASS" \
                "Rule '$rule_name' provides default deny behavior (Priority: $priority)"
        fi
        
    done <<< "$firewall_rules"
    
    # Summary assessment
    if [[ $high_risk_rules -eq 0 ]]; then
        add_check_result "Firewall rules security assessment" "PASS" \
            "No high-risk firewall rules detected out of $total_rules rules analyzed"
    else
        add_check_result "Firewall rules security assessment" "FAIL" \
            "$high_risk_rules high-risk rules found out of $total_rules total rules"
    fi
}

assess_network_segmentation() {
    local project_id="$1"
    debug_log "Assessing network segmentation for project: $project_id"
    
    # Get VPC networks
    local networks
    networks=$(gcloud compute networks list \
        --project="$project_id" \
        --format="value(name,IPv4Range,gatewayIPv4)" \
        2>/dev/null)
    
    if [[ -z "$networks" ]]; then
        add_check_result "Network segmentation" "FAIL" "No VPC networks found in project $project_id"
        return
    fi
    
    local network_count=0
    while IFS= read -r network; do
        ((network_count++))
        local network_name=$(echo "$network" | cut -d$'\t' -f1)
        
        # Check for subnets in each network
        local subnets
        subnets=$(gcloud compute networks subnets list \
            --network="$network_name" \
            --project="$project_id" \
            --format="value(name,range)" \
            2>/dev/null)
        
        local subnet_count=0
        while IFS= read -r subnet; do
            [[ -n "$subnet" ]] && ((subnet_count++))
        done <<< "$subnets"
        
        if [[ $subnet_count -gt 1 ]]; then
            add_check_result "Network segmentation in $network_name" "PASS" \
                "Network has $subnet_count subnets enabling proper segmentation"
        else
            add_check_result "Network segmentation in $network_name" "WARN" \
                "Network has only $subnet_count subnet - consider additional segmentation"
        fi
        
    done <<< "$networks"
    
    add_check_result "VPC networks assessment" "INFO" \
        "Found $network_count VPC networks in project $project_id"
}

assess_load_balancer_security() {
    local project_id="$1"
    debug_log "Assessing load balancer security for project: $project_id"
    
    # Check backend services
    local backend_services
    backend_services=$(gcloud compute backend-services list \
        --project="$project_id" \
        --format="value(name,protocol,loadBalancingScheme)" \
        2>/dev/null)
    
    if [[ -z "$backend_services" ]]; then
        add_check_result "Load balancer assessment" "INFO" "No backend services found in project $project_id"
        return
    fi
    
    local secure_services=0
    local total_services=0
    
    while IFS= read -r service; do
        [[ -z "$service" ]] && continue
        ((total_services++))
        
        local service_name=$(echo "$service" | cut -d$'\t' -f1)
        local protocol=$(echo "$service" | cut -d$'\t' -f2)
        local scheme=$(echo "$service" | cut -d$'\t' -f3)
        
        if [[ "$protocol" == "HTTPS" ]] || [[ "$protocol" == "SSL" ]]; then
            add_check_result "Secure load balancer protocol" "PASS" \
                "Service '$service_name' uses secure protocol: $protocol"
            ((secure_services++))
        else
            add_check_result "Insecure load balancer protocol" "WARN" \
                "Service '$service_name' uses potentially insecure protocol: $protocol"
        fi
        
    done <<< "$backend_services"
    
    if [[ $total_services -gt 0 ]]; then
        local security_percentage=$((secure_services * 100 / total_services))
        add_check_result "Load balancer security summary" "INFO" \
            "$secure_services out of $total_services services use secure protocols ($security_percentage%)"
    fi
}

# Main assessment function
assess_project() {
    local project_id="$1"
    
    info_log "Assessing project: $project_id"
    
    # Add project section to report
    add_section "project_$project_id" "Project: $project_id" "Assessment results for project $project_id"
    
    # Perform assessments
    assess_firewall_rules "$project_id"
    assess_network_segmentation "$project_id"
    assess_load_balancer_security "$project_id"
    
    debug_log "Completed assessment for project: $project_id"
}

# Main execution
main() {
    info_log "Starting PCI DSS Requirement 1 assessment"
    
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
    local output_file="pci_requirement1_assessment_$(date +%Y%m%d_%H%M%S).html"
    finalize_report "$output_file" "$REQUIREMENT_NUMBER"
    
    success_log "Assessment complete! Report saved to: $output_file"
    success_log "Projects assessed: $project_count"
    
    return 0
}

# Execute main function
main "$@"