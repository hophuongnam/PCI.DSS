#!/usr/bin/env bash

# PCI DSS Requirement 6 Compliance Check Script for GCP
# Develop and Maintain Secure Systems and Software

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="6"

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
check_required_permissions "container.clusters.list" "cloudbuild.builds.list" || exit 1

# Initialize HTML report using shared library
# Set output file path
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"

# Initialize HTML report using shared library
initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"











print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 6 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information using shared library
# Display scope information using shared library - now handled in print_status calls
print_status "INFO" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "INFO" "Organization ID: ${ORG_ID}"
else
    print_status "INFO" "Project ID: ${PROJECT_ID}"
fi

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to check Cloud Build for secure CI/CD
check_cloud_build_security() {
    local details=""
    local found_issues=false
    
    details+="<p>Analyzing Cloud Build for secure CI/CD practices:</p>"
    
    # Get Cloud Build triggers
    local triggers
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        details+="<p><strong>Organization-wide CI/CD assessment:</strong></p>"
        triggers=$(run_gcp_command_across_projects "gcloud builds triggers list" "--format='value(name,github.name,substitutions)'")
    else
        triggers=$(gcloud builds triggers list --format="value(name,github.name,substitutions)" 2>/dev/null)
    fi
    
    if [ -z "$triggers" ]; then
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            details+="<p>No Cloud Build triggers found in organization $DEFAULT_ORG.</p>"
        else
            details+="<p>No Cloud Build triggers found in project $DEFAULT_PROJECT.</p>"
        fi
        echo "$details"
        return
    fi
    
    details+="<ul>"
    
    while IFS=$'\t' read -r trigger_info; do
        if [ -z "$trigger_info" ]; then
            continue
        fi
        
        # Parse trigger info for organization scope
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            local project_trigger=$(echo "$trigger_info" | cut -d'/' -f1)
            local trigger_data=$(echo "$trigger_info" | cut -d'/' -f2-)
            trigger_name=$(echo "$trigger_data" | cut -d$'\t' -f1)
            repo_name=$(echo "$trigger_data" | cut -d$'\t' -f2)
            substitutions=$(echo "$trigger_data" | cut -d$'\t' -f3)
            
            details+="<li><strong>Project:</strong> $project_trigger, <strong>Trigger:</strong> $trigger_name"
        else
            trigger_name=$(echo "$trigger_info" | cut -d$'\t' -f1)
            repo_name=$(echo "$trigger_info" | cut -d$'\t' -f2)
            substitutions=$(echo "$trigger_info" | cut -d$'\t' -f3)
            
            details+="<li><strong>Trigger:</strong> $trigger_name"
        fi
        
        if [ -n "$repo_name" ]; then
            details+=" (Repository: $repo_name)"
        fi
        
        # Check for security-related build steps
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            trigger_config=$(gcloud builds triggers describe "$trigger_name" --project="$project_trigger" --format="value(build)" 2>/dev/null)
        else
            trigger_config=$(gcloud builds triggers describe "$trigger_name" --format="value(build)" 2>/dev/null)
        fi
        
        if echo "$trigger_config" | grep -i -E "security|scan|test|sast|dast|sonar|snyk|twistlock" > /dev/null; then
            details+=" - <span class='green'>Security scanning steps detected</span>"
        else
            details+=" - <span class='yellow'>No obvious security scanning steps found</span>"
            found_issues=true
        fi
        
        # Check for substitution variables with sensitive information
        if echo "$substitutions" | grep -i -E "key|secret|password|token" > /dev/null; then
            details+=" - <span class='red'>Sensitive substitution variables detected</span>"
            found_issues=true
        fi
        
        details+="</li>"
        
    done <<< "$triggers"
    
    details+="</ul>"
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 6 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information using shared library
# Display scope information using shared library - now handled in print_status calls
print_status "INFO" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "INFO" "Organization ID: ${ORG_ID}"
else
    print_status "INFO" "Project ID: ${PROJECT_ID}"
fi

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to check Container Registry/Artifact Registry for vulnerability scanning
check_container_security() {
    local details=""
    local found_issues=false
    
    details+="<p>Analyzing container repositories for vulnerability scanning:</p>"
    
    # Check Artifact Registry repositories
    local ar_repos
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        ar_repos=$(run_gcp_command_across_projects "gcloud artifacts repositories list" "--format='value(name,format)'")
    else
        ar_repos=$(gcloud artifacts repositories list --format="value(name,format)" 2>/dev/null)
    fi
    
    if [ -n "$ar_repos" ]; then
        details+="<p>Artifact Registry repositories found:</p><ul>"
        
        while IFS=$'\t' read -r repo_info; do
            if [ -z "$repo_info" ]; then
                continue
            fi
            
            # Parse repo info for organization scope
            if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                local project_repo=$(echo "$repo_info" | cut -d'/' -f1)
                local repo_data=$(echo "$repo_info" | cut -d'/' -f2-)
                repo_name=$(echo "$repo_data" | cut -d$'\t' -f1)
                format=$(echo "$repo_data" | cut -d$'\t' -f2)
                
                if [ "$format" == "DOCKER" ]; then
                    details+="<li><strong>Project:</strong> $project_repo, <strong>Docker repository:</strong> $repo_name"
                    
                    # Check for vulnerability scanning configuration
                    scan_config=$(gcloud artifacts repositories describe "$repo_name" --project="$project_repo" --format="value(vulnerabilityScanningConfig)" 2>/dev/null)
                    
                    if [ -n "$scan_config" ]; then
                        details+=" - <span class='green'>Vulnerability scanning configured</span>"
                    else
                        details+=" - <span class='yellow'>Vulnerability scanning not detected</span>"
                        found_issues=true
                    fi
                    
                    details+="</li>"
                fi
            else
                repo_name=$(echo "$repo_info" | cut -d$'\t' -f1)
                format=$(echo "$repo_info" | cut -d$'\t' -f2)
                
                if [ "$format" == "DOCKER" ]; then
                    details+="<li><strong>Docker repository:</strong> $repo_name"
                    
                    # Check for vulnerability scanning configuration
                    scan_config=$(gcloud artifacts repositories describe "$repo_name" --format="value(vulnerabilityScanningConfig)" 2>/dev/null)
                    
                    if [ -n "$scan_config" ]; then
                        details+=" - <span class='green'>Vulnerability scanning configured</span>"
                    else
                        details+=" - <span class='yellow'>Vulnerability scanning not detected</span>"
                        found_issues=true
                    fi
                    
                    details+="</li>"
                fi
            fi
            
        done <<< "$ar_repos"
        
        details+="</ul>"
    fi
    
    # Check legacy Container Registry
    local gcr_images
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        gcr_images=$(run_gcp_command_across_projects "gcloud container images list" "--format='value(name)'")
    else
        gcr_images=$(gcloud container images list --format="value(name)" 2>/dev/null)
    fi
    
    if [ -n "$gcr_images" ]; then
        details+="<p>Legacy Container Registry images found:</p><ul>"
        
        echo "$gcr_images" | while IFS= read -r image; do
            if [ -n "$image" ]; then
                if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                    project_image=$(echo "$image" | cut -d'/' -f1)
                    image_name=$(echo "$image" | cut -d'/' -f2-)
                    
                    # Check for vulnerability scanning
                    vulns=$(gcloud container images scan "$image_name" --project="$project_image" --format="value(vulnerabilities)" 2>/dev/null | grep -c "CRITICAL\|HIGH" || echo "0")
                    
                    if [ "$vulns" -gt 0 ]; then
                        details+="<li class='red'>$project_image/$image_name - $vulns high/critical vulnerabilities found</li>"
                        found_issues=true
                    else
                        details+="<li class='green'>$project_image/$image_name - No high/critical vulnerabilities detected</li>"
                    fi
                else
                    vulns=$(gcloud container images scan "$image" --format="value(vulnerabilities)" 2>/dev/null | grep -c "CRITICAL\|HIGH" || echo "0")
                    
                    if [ "$vulns" -gt 0 ]; then
                        details+="<li class='red'>$image - $vulns high/critical vulnerabilities found</li>"
                        found_issues=true
                    else
                        details+="<li class='green'>$image - No high/critical vulnerabilities detected</li>"
                    fi
                fi
            fi
        done
        
        details+="</ul>"
    fi
    
    if [ -z "$ar_repos" ] && [ -z "$gcr_images" ]; then
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            details+="<p>No container repositories found in organization $DEFAULT_ORG.</p>"
        else
            details+="<p>No container repositories found in project $DEFAULT_PROJECT.</p>"
        fi
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 6 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information using shared library
# Display scope information using shared library - now handled in print_status calls
print_status "INFO" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "INFO" "Organization ID: ${ORG_ID}"
else
    print_status "INFO" "Project ID: ${PROJECT_ID}"
fi

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to check web application protection
check_web_app_protection() {
    local details=""
    local found_issues=false
    
    details+="<p>Checking web application protection mechanisms:</p>"
    
    # Check for Cloud Armor security policies
    local armor_policies
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        armor_policies=$(run_gcp_command_across_projects "gcloud compute security-policies list" "--format='value(name,description)'")
    else
        armor_policies=$(gcloud compute security-policies list --format="value(name,description)" 2>/dev/null)
    fi
    
    if [ -z "$armor_policies" ]; then
        details+="<p class='red'>No Cloud Armor security policies found. Public-facing web applications should be protected by a web application firewall.</p>"
        found_issues=true
    else
        details+="<p>Cloud Armor security policies found:</p><ul>"
        
        echo "$armor_policies" | while IFS=$'\t' read -r policy_info; do
            if [ -n "$policy_info" ]; then
                if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                    project_policy=$(echo "$policy_info" | cut -d'/' -f1)
                    policy_data=$(echo "$policy_info" | cut -d'/' -f2-)
                    details+="<li><strong>Project:</strong> $project_policy, <strong>Policy:</strong> $policy_data</li>"
                else
                    details+="<li><strong>Policy:</strong> $policy_info</li>"
                fi
            fi
        done
        
        details+="</ul>"
    fi
    
    # Check for Load Balancer security configurations
    local load_balancers
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        load_balancers=$(run_gcp_command_across_projects "gcloud compute backend-services list" "--format='value(name,securityPolicy)'")
    else
        load_balancers=$(gcloud compute backend-services list --format="value(name,securityPolicy)" 2>/dev/null)
    fi
    
    if [ -n "$load_balancers" ]; then
        details+="<p>Load balancer security analysis:</p><ul>"
        
        echo "$load_balancers" | while IFS=$'\t' read -r lb_info; do
            if [ -n "$lb_info" ]; then
                if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                    project_lb=$(echo "$lb_info" | cut -d'/' -f1)
                    lb_data=$(echo "$lb_info" | cut -d'/' -f2-)
                    lb_name=$(echo "$lb_data" | cut -d$'\t' -f1)
                    security_policy=$(echo "$lb_data" | cut -d$'\t' -f2)
                    
                    if [ -n "$security_policy" ]; then
                        details+="<li class='green'>$project_lb/$lb_name has security policy: $security_policy</li>"
                    else
                        details+="<li class='yellow'>$project_lb/$lb_name has no security policy attached</li>"
                        found_issues=true
                    fi
                else
                    lb_name=$(echo "$lb_info" | cut -d$'\t' -f1)
                    security_policy=$(echo "$lb_info" | cut -d$'\t' -f2)
                    
                    if [ -n "$security_policy" ]; then
                        details+="<li class='green'>$lb_name has security policy: $security_policy</li>"
                    else
                        details+="<li class='yellow'>$lb_name has no security policy attached</li>"
                        found_issues=true
                    fi
                fi
            fi
        done
        
        details+="</ul>"
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 6 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information using shared library
# Display scope information using shared library - now handled in print_status calls
print_status "INFO" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "INFO" "Organization ID: ${ORG_ID}"
else
    print_status "INFO" "Project ID: ${PROJECT_ID}"
fi

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to check change management and environment separation
check_change_management() {
    local details=""
    local found_issues=false
    
    details+="<p>Analyzing change management and environment separation:</p>"
    
    # Check for Cloud Functions with environment indicators
    local functions
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        functions=$(run_gcp_command_across_projects "gcloud functions list" "--format='value(name,status)'")
    else
        functions=$(gcloud functions list --format="value(name,status)" 2>/dev/null)
    fi
    
    if [ -n "$functions" ]; then
        details+="<p>Cloud Functions environment analysis:</p>"
        
        # Analyze function names for environment patterns
        local env_patterns
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            env_patterns=$(echo "$functions" | cut -d'/' -f2 | cut -d$'\t' -f1 | grep -o -E '(dev|test|stage|staging|prod|production)' | sort | uniq -c)
        else
            env_patterns=$(echo "$functions" | cut -d$'\t' -f1 | grep -o -E '(dev|test|stage|staging|prod|production)' | sort | uniq -c)
        fi
        
        if [ -n "$env_patterns" ]; then
            details+="<ul>"
            while read -r count env; do
                details+="<li>$env environment: $count functions</li>"
            done <<< "$env_patterns"
            details+="</ul>"
        else
            details+="<p class='yellow'>No clear environment naming patterns detected in function names.</p>"
            found_issues=true
        fi
    fi
    
    # Check for App Engine services with versions (indicates change management)
    local app_versions
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        app_versions=$(run_gcp_command_across_projects "gcloud app versions list" "--format='value(service,version,traffic_split)'")
    else
        app_versions=$(gcloud app versions list --format="value(service,version,traffic_split)" 2>/dev/null)
    fi
    
    if [ -n "$app_versions" ]; then
        details+="<p>App Engine version management:</p><ul>"
        
        local services
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            services=$(echo "$app_versions" | cut -d'/' -f2 | cut -d$'\t' -f1 | sort | uniq)
        else
            services=$(echo "$app_versions" | cut -d$'\t' -f1 | sort | uniq)
        fi
        
        for service in $services; do
            if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                versions_count=$(echo "$app_versions" | grep "/$service" | wc -l)
            else
                versions_count=$(echo "$app_versions" | grep "^$service" | wc -l)
            fi
            details+="<li>Service $service: $versions_count versions deployed</li>"
        done
        
        details+="</ul>"
    else
        details+="<p>No App Engine services found.</p>"
    fi
    
    # Check for Cloud Source Repositories (code management)
    local repos
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        repos=$(run_gcp_command_across_projects "gcloud source repos list" "--format='value(name)'")
    else
        repos=$(gcloud source repos list --format="value(name)" 2>/dev/null)
    fi
    
    if [ -n "$repos" ]; then
        details+="<p class='green'>Cloud Source Repositories found for code management:</p><ul>"
        echo "$repos" | while IFS= read -r repo; do
            if [ -n "$repo" ]; then
                details+="<li>$repo</li>"
            fi
        done
        details+="</ul>"
    else
        details+="<p class='yellow'>No Cloud Source Repositories found. Consider using version control for change management.</p>"
        found_issues=true
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 6 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information using shared library
# Display scope information using shared library - now handled in print_status calls
print_status "INFO" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "INFO" "Organization ID: ${ORG_ID}"
else
    print_status "INFO" "Project ID: ${PROJECT_ID}"
fi

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to check for secure development practices
check_secure_development() {
    local details=""
    local found_issues=false
    
    details+="<p>Checking secure development practices in GCP:</p>"
    
    # Check for Secret Manager usage (secure secrets management)
    local secrets
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        secrets=$(run_gcp_command_across_projects "gcloud secrets list" "--format='value(name)'")
    else
        secrets=$(gcloud secrets list --format="value(name)" 2>/dev/null)
    fi
    
    if [ -n "$secrets" ]; then
        local secrets_count=$(echo "$secrets" | wc -l)
        details+="<p class='green'>Secret Manager is being used for secure secrets management: $secrets_count secrets managed</p>"
    else
        details+="<p class='yellow'>No secrets found in Secret Manager. Consider using it for secure credential management.</p>"
        found_issues=true
    fi
    
    # Check for Cloud KMS for encryption key management
    local kms_keys
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        # For organization scope, check across all projects
        details+="<p>Cloud KMS usage across organization (limited to checking global keyring):</p>"
        kms_keys=$(run_gcp_command_across_projects "gcloud kms keys list --location=global --keyring=default" "--format='value(name)'" || echo "")
    else
        kms_keys=$(gcloud kms keys list --location=global --keyring=projects/$DEFAULT_PROJECT/locations/global/keyRings/default --format="value(name)" 2>/dev/null || echo "")
    fi
    
    if [ -n "$kms_keys" ]; then
        details+="<p class='green'>Cloud KMS is being used for encryption key management.</p>"
    else
        details+="<p class='yellow'>No Cloud KMS keys found in default keyring. Consider using KMS for encryption key management.</p>"
        found_issues=true
    fi
    
    # Manual verification requirements
    details+="<p><strong>Manual verification required for:</strong></p><ul>"
    details+="<li>Developer security training (at least annually)</li>"
    details+="<li>Code review processes for security vulnerabilities</li>"
    details+="<li>Secure coding guidelines implementation</li>"
    details+="<li>Security testing integration in CI/CD pipelines</li>"
    details+="<li>Third-party component vulnerability management</li>"
    details+="</ul>"
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Validate scope and requirements
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    if [ -z "$DEFAULT_ORG" ]; then
        print_status "FAIL" "Error: Organization scope requires an organization ID."
        print_status "WARN" "Please provide organization ID with --org flag or ensure you have organization access."
        exit 1
    fi
else
    # Project scope validation
    if [ -z "$DEFAULT_PROJECT" ]; then
        print_status "FAIL" "Error: No project specified."
        print_status "WARN" "Please set a default project with: gcloud config set project PROJECT_ID"
        print_status "WARN" "Or specify a project with: --project PROJECT_ID"
        exit 1
    fi
fi

# Start script execution
print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER (GCP)"
print_status "INFO" "  (Develop and Maintain Secure Systems)"
print_status "INFO" "============================================="
echo ""

# Display scope information
print_status "INFO" "Assessment Scope: $ASSESSMENT_SCOPE"
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    print_status "INFO" "Organization: $DEFAULT_ORG"
    print_status "WARN" "Note: Organization-wide assessment may take longer and requires broader permissions"
else
    print_status "INFO" "Project: $DEFAULT_PROJECT"
fi
echo ""

# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE"

echo ""
echo "Starting assessment at $(date)"
echo ""

#----------------------------------------------------------------------
# SECTION 1: PERMISSIONS CHECK
#----------------------------------------------------------------------
add_html_section "$OUTPUT_FILE" "GCP Permissions Check" "<p>Verifying access to required GCP services for PCI Requirement $REQUIREMENT_NUMBER assessment...</p>" "info"

print_status "INFO" "=== CHECKING REQUIRED GCP PERMISSIONS ==="

# Check all required permissions based on scope
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    # Organization-wide permission checks
    check_gcp_permission "Projects" "list" "gcloud projects list --filter='parent.id:$DEFAULT_ORG' --limit=1"
    ((total_checks++))
    
    check_gcp_permission "Organizations" "access" "gcloud organizations list --filter='name:organizations/$DEFAULT_ORG' --limit=1"
    ((total_checks++))
fi

# Scope-aware permission checks
PROJECT_FLAG=""
if [ "$ASSESSMENT_SCOPE" == "project" ]; then
    PROJECT_FLAG="--project=$DEFAULT_PROJECT"
fi

# Requirement 6 specific permission checks
check_gcp_permission "Cloud Build" "triggers" "gcloud builds triggers list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Artifact Registry" "repositories" "gcloud artifacts repositories list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Container" "images" "gcloud container images list --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "security-policies" "gcloud compute security-policies list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Secret Manager" "secrets" "gcloud secrets list $PROJECT_FLAG --limit=1"
((total_checks++))

# Calculate permissions percentage
available_permissions=$((total_checks - access_denied_checks))
if [ $available_permissions -gt 0 ]; then
    permissions_percentage=$(( ((total_checks - access_denied_checks) * 100) / total_checks ))
else
    permissions_percentage=0
fi

if [ $permissions_percentage -lt 70 ]; then
    print_status "FAIL" "WARNING: Insufficient permissions to perform a complete PCI Requirement $REQUIREMENT_NUMBER assessment."
    add_html_section "$OUTPUT_FILE" "Permission Assessment" "<p class='red'>Insufficient permissions detected. Only $permissions_percentage% of required permissions are available.</p><p>Without these permissions, the assessment will be incomplete and may not accurately reflect your PCI DSS compliance status.</p>" "fail"
    read -p "Continue with limited assessment? (y/n): " CONTINUE
    if [[ ! $CONTINUE =~ ^[Yy]$ ]]; then
        echo "Assessment aborted."
        exit 1
    fi
else
    print_status "PASS" "Permission check complete: $permissions_percentage% permissions available"
    add_html_section "$OUTPUT_FILE" "Permission Assessment" "<p class='green'>Sufficient permissions detected. $permissions_percentage% of required permissions are available.</p>" "pass"
fi

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

#----------------------------------------------------------------------
# SECTION 2: REQUIREMENT 6 ASSESSMENT LOGIC
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT $REQUIREMENT_NUMBER: DEVELOP AND MAINTAIN SECURE SYSTEMS ==="

# Requirement 6.2: Bespoke and custom software are developed securely
add_html_section "$OUTPUT_FILE" "Requirement 6.2: Secure software development" "<p>Verifying secure development practices and CI/CD security...</p>" "info"

# Check 6.2.1 - Secure development practices
print_status "INFO" "Checking secure development practices..."
dev_details=$(check_secure_development)
if [[ "$dev_details" == *"class='red'"* ]] || [[ "$dev_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "6.2.1 - Secure software development" "$dev_details<p><strong>Remediation:</strong> Implement secure development practices using GCP security tools. Use Secret Manager for credentials, Cloud KMS for encryption, and security scanning in CI/CD pipelines.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "6.2.1 - Secure software development" "$dev_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Check CI/CD Pipeline Security
print_status "INFO" "Checking Cloud Build for secure CI/CD..."
cb_details=$(check_cloud_build_security)
if [[ "$cb_details" == *"class='red'"* ]] || [[ "$cb_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "6.2.1 - CI/CD Pipeline Security" "$cb_details<p><strong>Remediation:</strong> Enhance Cloud Build with security scanning steps, approval processes, and secure handling of sensitive data. Include SAST, DAST, and dependency scanning in build pipelines.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "6.2.1 - CI/CD Pipeline Security" "$cb_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Requirement 6.3: Security vulnerabilities are identified and addressed
add_html_section "$OUTPUT_FILE" "Requirement 6.3: Vulnerability management" "<p>Verifying vulnerability identification and management processes...</p>" "info"

# Check container vulnerability scanning
print_status "INFO" "Checking container security..."
container_details=$(check_container_security)
if [[ "$container_details" == *"class='red'"* ]] || [[ "$container_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "6.3.2 - Container vulnerability scanning" "$container_details<p><strong>Remediation:</strong> Enable vulnerability scanning for all container images in Artifact Registry and Container Registry. Address high and critical vulnerabilities promptly.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "6.3.2 - Container vulnerability scanning" "$container_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Requirement 6.4: Public-facing web applications are protected against attacks
add_html_section "$OUTPUT_FILE" "Requirement 6.4: Web application protection" "<p>Verifying protection mechanisms for public-facing web applications...</p>" "info"

# Check web application protection
print_status "INFO" "Checking web application protection..."
web_details=$(check_web_app_protection)
if [[ "$web_details" == *"class='red'"* ]]; then
    add_html_section "$OUTPUT_FILE" "6.4.1-6.4.2 - Web application protection" "$web_details<p><strong>Remediation:</strong> Implement Cloud Armor security policies for all public-facing web applications. Configure protection against OWASP Top 10 vulnerabilities and enable logging.</p>" "fail"
    ((failed_checks++))
elif [[ "$web_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "6.4.1-6.4.2 - Web application protection" "$web_details<p><strong>Remediation:</strong> Enhance web application protection with Cloud Armor. Include rate limiting, geo-blocking, and comprehensive security rules.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "6.4.1-6.4.2 - Web application protection" "$web_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Requirement 6.5: Changes to all system components are managed securely
add_html_section "$OUTPUT_FILE" "Requirement 6.5: Change management" "<p>Verifying secure change management processes...</p>" "info"

# Check change management and environment separation
print_status "INFO" "Checking change management and environment separation..."
change_details=$(check_change_management)
if [[ "$change_details" == *"class='red'"* ]] || [[ "$change_details" == *"class='yellow'"* ]]; then
    add_html_section "$OUTPUT_FILE" "6.5.1-6.5.6 - Change management and environment separation" "$change_details<p><strong>Remediation:</strong> Implement formal change management processes with proper environment separation. Use Infrastructure as Code, version control, and approval workflows.</p>" "warning"
    ((warning_checks++))
else
    add_html_section "$OUTPUT_FILE" "6.5.1-6.5.6 - Change management and environment separation" "$change_details" "pass"
    ((passed_checks++))
fi
((total_checks++))

# Manual verification requirements
manual_checks="<p>Manual verification required for complete PCI DSS Requirement 6 compliance:</p>
<ul>
<li><strong>6.1:</strong> Governance and documentation of development security policies and procedures</li>
<li><strong>6.2.2:</strong> Developer training on software security (at least annually)</li>
<li><strong>6.2.3:</strong> Code review processes before production release</li>
<li><strong>6.2.4:</strong> Protection against common software attacks (injection, XSS, etc.)</li>
<li><strong>6.3.1:</strong> Maintain inventory of software components and security vulnerabilities</li>
<li><strong>6.3.3:</strong> Patch management (critical vulnerabilities within one month)</li>
<li><strong>6.4.3:</strong> Payment page script management and integrity verification</li>
<li><strong>6.5:</strong> Change control procedures with proper documentation and approval</li>
</ul>
<p><strong>GCP Tools and Recommendations:</strong></p>
<ul>
<li>Use Cloud Code for secure development environments</li>
<li>Implement automated security testing in Cloud Build</li>
<li>Use Cloud Security Scanner for web application testing</li>
<li>Leverage Container Analysis for dependency scanning</li>
<li>Implement Binary Authorization for deployment security</li>
<li>Use separate GCP projects for different environments</li>
<li>Implement IAM policies for role separation</li>
<li>Use Deployment Manager for Infrastructure as Code</li>
</ul>"

add_html_section "$OUTPUT_FILE" "Manual Verification Requirements" "$manual_checks" "warning"
((warning_checks++))
((total_checks++))

#----------------------------------------------------------------------

#----------------------------------------------------------------------
# FINAL REPORT
#----------------------------------------------------------------------

# Finalize HTML report using shared library
# Add final summary metrics
add_summary_metrics "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"

# Finalize HTML report using shared library
finalize_report "$OUTPUT_FILE" "${REQUIREMENT_NUMBER}"

# Display final summary using shared library
# Display final summary using shared library
print_status "INFO" "=== ASSESSMENT SUMMARY ==="
print_status "INFO" "Total checks: $total_checks"
print_status "PASS" "Passed: $passed_checks"
print_status "FAIL" "Failed: $failed_checks"
print_status "WARN" "Warnings: $warning_checks"
print_status "INFO" "Report has been generated: $OUTPUT_FILE"
print_status "PASS" "=================================================================="
