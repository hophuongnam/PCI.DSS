#!/usr/bin/env bash
#
# PCI DSS v4.0 Compliance Assessment Script for Requirement 6 (GCP)
# Develop and Maintain Secure Systems and Software
#

# Variables
REQUIREMENT_NUMBER="6"
SCRIPT_DIR="$(dirname "$0")"
REPORT_DIR="$SCRIPT_DIR/reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="$REPORT_DIR/pci_req${REQUIREMENT_NUMBER}_gcp_report_${TIMESTAMP}.html"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report (GCP)"

# Initialize counters
total_checks=0
passed_checks=0
failed_checks=0
warning_checks=0

# Source the HTML report library (use the one from AWS directory if available)
if [ -f "$SCRIPT_DIR/../AWS/pci_html_report_lib.sh" ]; then
    source "$SCRIPT_DIR/../AWS/pci_html_report_lib.sh" || {
        echo "Error: Required library file pci_html_report_lib.sh not found."
        exit 1
    }
else
    echo "Error: HTML report library not found. Please ensure pci_html_report_lib.sh is available."
    exit 1
fi

# Set output colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to validate gcloud CLI is installed and configured
validate_gcloud_cli() {
    which gcloud > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: gcloud CLI is not installed or not in PATH. Please install gcloud CLI."
        exit 1
    fi
    
    gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -1 > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: gcloud CLI is not authenticated. Please run 'gcloud auth login'."
        exit 1
    fi
    
    # Check current project
    PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
    if [ -z "$PROJECT_ID" ]; then
        echo "Error: No GCP project configured. Please run 'gcloud config set project PROJECT_ID'."
        exit 1
    fi
    
    echo "Using GCP project: $PROJECT_ID"
}

# Function to check if a gcloud command is available
check_gcloud_command_access() {
    local output_file="$1"
    local service="$2"
    local command="$3"
    
    echo "Checking access to gcloud $service $command..."
    
    # Test basic access to the service
    gcloud $service --help > /dev/null 2>&1
    local service_available=$?
    
    if [ $service_available -ne 0 ]; then
        add_check_item "$output_file" "warning" "GCloud Service Not Available" \
            "<p>The gcloud service <code>$service</code> is not available. This may indicate missing APIs or permissions.</p>" \
            "Enable the required GCP APIs and ensure proper permissions."
        ((warning_checks++))
        ((total_checks++))
        return 1
    fi
    
    return 0
}

# Function to check Cloud Build for secure CI/CD
check_cloud_build_security() {
    local details=""
    local found_issues=false
    
    details+="<p>Analyzing Cloud Build for secure CI/CD practices:</p>"
    
    # Get Cloud Build triggers
    triggers=$(gcloud builds triggers list --format="value(name,github.name,substitutions)" 2>/dev/null)
    
    if [ -z "$triggers" ]; then
        details+="<p>No Cloud Build triggers found in project $PROJECT_ID.</p>"
        echo "$details"
        return
    fi
    
    details+="<ul>"
    
    while IFS=$'\t' read -r trigger_name repo_name substitutions; do
        details+="<li>Trigger: $trigger_name"
        if [ -n "$repo_name" ]; then
            details+=" (Repository: $repo_name)"
        fi
        details+="<ul>"
        
        # Check for security-related build steps
        trigger_config=$(gcloud builds triggers describe "$trigger_name" --format="value(build)" 2>/dev/null)
        
        if echo "$trigger_config" | grep -i -E "security|scan|test|sast|dast|sonar|snyk|twistlock" > /dev/null; then
            details+="<li class=\"green\">Build configuration includes security-related steps</li>"
        else
            details+="<li class=\"yellow\">No obvious security scanning steps found in build configuration</li>"
            found_issues=true
        fi
        
        # Check for substitution variables with sensitive information
        if echo "$substitutions" | grep -i -E "key|secret|password|token" > /dev/null; then
            details+="<li class=\"red\">Build trigger contains substitution variables that may include sensitive information</li>"
            found_issues=true
        fi
        
        # Check for manual approval requirements
        if echo "$trigger_config" | grep -i "approval" > /dev/null; then
            details+="<li class=\"green\">Build includes approval mechanisms</li>"
        else
            details+="<li class=\"yellow\">No manual approval mechanisms detected</li>"
            found_issues=true
        fi
        
        details+="</ul></li>"
        
    done <<< "$triggers"
    
    details+="</ul>"
    
    # Check for Cloud Build history with security focus
    recent_builds=$(gcloud builds list --limit=10 --format="value(id,status,createTime)" 2>/dev/null)
    
    if [ -n "$recent_builds" ]; then
        details+="<p>Recent build activity analysis:</p><ul>"
        
        failed_builds=$(echo "$recent_builds" | grep -c "FAILURE\|TIMEOUT\|CANCELLED")
        total_builds=$(echo "$recent_builds" | wc -l)
        
        if [ "$failed_builds" -gt $(($total_builds / 2)) ]; then
            details+="<li class=\"red\">High failure rate detected: $failed_builds out of $total_builds recent builds failed</li>"
            found_issues=true
        else
            details+="<li class=\"green\">Build success rate appears healthy: $(($total_builds - $failed_builds)) out of $total_builds builds successful</li>"
        fi
        
        details+="</ul>"
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check Container Registry/Artifact Registry for vulnerability scanning
check_container_security() {
    local details=""
    local found_issues=false
    
    details+="<p>Analyzing container repositories for vulnerability scanning:</p>"
    
    # Check Artifact Registry repositories
    ar_repos=$(gcloud artifacts repositories list --format="value(name,format)" 2>/dev/null)
    
    if [ -n "$ar_repos" ]; then
        details+="<p>Artifact Registry repositories found:</p><ul>"
        
        while IFS=$'\t' read -r repo_name format; do
            if [ "$format" == "DOCKER" ]; then
                details+="<li>Docker repository: $repo_name<ul>"
                
                # Check for vulnerability scanning configuration
                scan_config=$(gcloud artifacts repositories describe "$repo_name" --format="value(vulnerabilityScanningConfig)" 2>/dev/null)
                
                if [ -n "$scan_config" ]; then
                    details+="<li class=\"green\">Vulnerability scanning is configured</li>"
                else
                    details+="<li class=\"yellow\">Vulnerability scanning configuration not detected</li>"
                    found_issues=true
                fi
                
                # Get recent images and check for vulnerabilities
                images=$(gcloud artifacts docker images list "$repo_name" --limit=5 --format="value(IMAGE)" 2>/dev/null)
                
                if [ -n "$images" ]; then
                    details+="<li>Recent images with vulnerability analysis:</li><ul>"
                    
                    for image in $images; do
                        # Check for vulnerability scan results
                        vulns=$(gcloud artifacts docker images scan "$image" --format="value(vulnerabilities)" 2>/dev/null | grep -c "CRITICAL\|HIGH" 2>/dev/null || echo "0")
                        
                        if [ "$vulns" -gt 0 ]; then
                            details+="<li class=\"red\">$image: $vulns high/critical vulnerabilities found</li>"
                            found_issues=true
                        else
                            details+="<li class=\"green\">$image: No high/critical vulnerabilities detected</li>"
                        fi
                    done
                    
                    details+="</ul>"
                fi
                
                details+="</ul></li>"
            fi
        done <<< "$ar_repos"
        
        details+="</ul>"
    fi
    
    # Check legacy Container Registry
    gcr_images=$(gcloud container images list --format="value(name)" 2>/dev/null)
    
    if [ -n "$gcr_images" ]; then
        details+="<p>Legacy Container Registry images found:</p><ul>"
        
        for image in $gcr_images; do
            details+="<li>Image: $image<ul>"
            
            # Check for vulnerability scanning
            vulns=$(gcloud container images scan "$image" --format="value(vulnerabilities)" 2>/dev/null | grep -c "CRITICAL\|HIGH" 2>/dev/null || echo "0")
            
            if [ "$vulns" -gt 0 ]; then
                details+="<li class=\"red\">$vulns high/critical vulnerabilities found</li>"
                found_issues=true
            else
                details+="<li class=\"green\">No high/critical vulnerabilities detected</li>"
            fi
            
            details+="</ul></li>"
        done
        
        details+="</ul>"
    fi
    
    if [ -z "$ar_repos" ] && [ -z "$gcr_images" ]; then
        details+="<p>No container repositories found in project $PROJECT_ID.</p>"
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check for vulnerability management
check_vulnerability_management() {
    local details=""
    local found_issues=false
    
    details+="<p>Checking vulnerability management capabilities in GCP:</p>"
    
    # Check Security Command Center for vulnerability findings
    if check_gcloud_command_access "$OUTPUT_FILE" "scc" "findings"; then
        scc_findings=$(gcloud scc findings list --organization=$(gcloud organizations list --format="value(name)" | head -1) --filter="state:ACTIVE AND (category:VULNERABILITY OR category:MALWARE)" --format="value(name,category,severity)" --limit=20 2>/dev/null)
        
        if [ -n "$scc_findings" ]; then
            details+="<p>Security Command Center vulnerability findings:</p><ul>"
            
            critical_count=$(echo "$scc_findings" | grep -c "CRITICAL")
            high_count=$(echo "$scc_findings" | grep -c "HIGH")
            
            if [ "$critical_count" -gt 0 ]; then
                details+="<li class=\"red\">Critical vulnerabilities: $critical_count</li>"
                found_issues=true
            fi
            
            if [ "$high_count" -gt 0 ]; then
                details+="<li class=\"red\">High vulnerabilities: $high_count</li>"
                found_issues=true
            fi
            
            details+="</ul>"
        else
            details+="<p class=\"green\">No active vulnerability findings in Security Command Center.</p>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Security Command Center due to permission restrictions or organization setup.</p>"
        found_issues=true
    fi
    
    # Check for Web Security Scanner
    if check_gcloud_command_access "$OUTPUT_FILE" "app" "scan"; then
        scan_configs=$(gcloud app scan-configs list --format="value(name)" 2>/dev/null)
        
        if [ -z "$scan_configs" ]; then
            details+="<p class=\"yellow\">No Web Security Scanner configurations found. Consider using it for web application vulnerability scanning.</p>"
            found_issues=true
        else
            details+="<p class=\"green\">Found Web Security Scanner configurations:</p><ul>"
            for config in $scan_configs; do
                details+="<li>$config</li>"
                
                # Check recent scan results
                scan_results=$(gcloud app scan-results list --scan-config="$config" --limit=1 --format="value(name,endTime)" 2>/dev/null)
                
                if [ -n "$scan_results" ]; then
                    details+="<ul><li>Recent scan completed: $scan_results</li></ul>"
                else
                    details+="<ul><li class=\"yellow\">No recent scan results found</li></ul>"
                    found_issues=true
                fi
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Web Security Scanner due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for Binary Authorization
    if check_gcloud_command_access "$OUTPUT_FILE" "container" "binauthz"; then
        binauthz_policy=$(gcloud container binauthz policy import --help 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            details+="<p class=\"green\">Binary Authorization is available for container security enforcement.</p>"
        else
            details+="<p class=\"yellow\">Binary Authorization may not be properly configured.</p>"
            found_issues=true
        fi
    else
        details+="<p class=\"yellow\">Unable to check Binary Authorization configuration.</p>"
        found_issues=true
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check web application protection
check_web_app_protection() {
    local details=""
    local found_issues=false
    
    details+="<p>Checking web application protection mechanisms:</p>"
    
    # Check for Cloud Armor security policies
    armor_policies=$(gcloud compute security-policies list --format="value(name,description)" 2>/dev/null)
    
    if [ -z "$armor_policies" ]; then
        details+="<p class=\"red\">No Cloud Armor security policies found. Public-facing web applications should be protected by a web application firewall.</p>"
        found_issues=true
    else
        details+="<p>Cloud Armor security policies found:</p><ul>"
        
        while IFS=$'\t' read -r policy_name description; do
            details+="<li>Policy: $policy_name ($description)<ul>"
            
            # Get policy details
            policy_details=$(gcloud compute security-policies describe "$policy_name" --format="value(rules,defaultAction)" 2>/dev/null)
            
            # Check default action
            default_action=$(echo "$policy_details" | grep -o 'action.*' | head -1)
            if echo "$default_action" | grep -q "deny"; then
                details+="<li class=\"green\">Default action is deny (secure default)</li>"
            else
                details+="<li class=\"yellow\">Default action is not deny - consider using deny-by-default with explicit allow rules</li>"
                found_issues=true
            fi
            
            # Check for OWASP rules
            rules_count=$(echo "$policy_details" | grep -o 'priority.*' | wc -l)
            details+="<li>Rules configured: $rules_count</li>"
            
            # Check for rate limiting
            if echo "$policy_details" | grep -i "rateLimitOptions" > /dev/null; then
                details+="<li class=\"green\">Rate limiting is configured</li>"
            else
                details+="<li class=\"yellow\">No rate limiting detected</li>"
                found_issues=true
            fi
            
            # Check for geo-blocking
            if echo "$policy_details" | grep -i "srcIpRanges\|country" > /dev/null; then
                details+="<li class=\"green\">Geographic or IP-based filtering configured</li>"
            else
                details+="<li class=\"yellow\">No geographic or IP-based filtering detected</li>"
                found_issues=true
            fi
            
            details+="</ul></li>"
            
        done <<< "$armor_policies"
        
        details+="</ul>"
    fi
    
    # Check for Load Balancer security configurations
    load_balancers=$(gcloud compute backend-services list --format="value(name,securityPolicy)" 2>/dev/null)
    
    if [ -n "$load_balancers" ]; then
        details+="<p>Load balancer security analysis:</p><ul>"
        
        while IFS=$'\t' read -r lb_name security_policy; do
            if [ -n "$security_policy" ]; then
                details+="<li class=\"green\">Load balancer $lb_name has security policy: $security_policy</li>"
            else
                details+="<li class=\"yellow\">Load balancer $lb_name has no security policy attached</li>"
                found_issues=true
            fi
        done <<< "$load_balancers"
        
        details+="</ul>"
    fi
    
    # Check for Identity-Aware Proxy
    if check_gcloud_command_access "$OUTPUT_FILE" "iap" "web"; then
        iap_resources=$(gcloud iap web list --format="value(name)" 2>/dev/null)
        
        if [ -n "$iap_resources" ]; then
            details+="<p class=\"green\">Identity-Aware Proxy is configured for additional application protection.</p>"
        else
            details+="<p class=\"yellow\">No Identity-Aware Proxy configuration found. Consider IAP for additional security layers.</p>"
            found_issues=true
        fi
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check change management and environment separation
check_change_management() {
    local details=""
    local found_issues=false
    
    details+="<p>Analyzing change management and environment separation:</p>"
    
    # Check for Cloud Functions with environment indicators
    functions=$(gcloud functions list --format="value(name,status)" 2>/dev/null)
    
    if [ -n "$functions" ]; then
        details+="<p>Cloud Functions environment analysis:</p>"
        
        # Analyze function names for environment patterns
        env_patterns=$(echo "$functions" | cut -d$'\t' -f1 | grep -o -E '(dev|test|stage|staging|prod|production)' | sort | uniq -c)
        
        if [ -n "$env_patterns" ]; then
            details+="<ul>"
            while read -r count env; do
                details+="<li>$env environment: $count functions</li>"
            done <<< "$env_patterns"
            details+="</ul>"
        else
            details+="<p class=\"yellow\">No clear environment naming patterns detected in function names.</p>"
            found_issues=true
        fi
    fi
    
    # Check for App Engine services with versions (indicates change management)
    if check_gcloud_command_access "$OUTPUT_FILE" "app" "versions"; then
        app_versions=$(gcloud app versions list --format="value(service,version,traffic_split)" 2>/dev/null)
        
        if [ -n "$app_versions" ]; then
            details+="<p>App Engine version management:</p><ul>"
            
            services=$(echo "$app_versions" | cut -d$'\t' -f1 | sort | uniq)
            
            for service in $services; do
                versions_count=$(echo "$app_versions" | grep "^$service" | wc -l)
                details+="<li>Service $service: $versions_count versions deployed</li>"
                
                # Check traffic split
                traffic_info=$(echo "$app_versions" | grep "^$service" | grep -v "0.00")
                if [ $(echo "$traffic_info" | wc -l) -gt 1 ]; then
                    details+="<ul><li class=\"green\">Traffic splitting detected (supports gradual rollouts)</li></ul>"
                else
                    details+="<ul><li class=\"yellow\">No traffic splitting detected</li></ul>"
                    found_issues=true
                fi
            done
            
            details+="</ul>"
        else
            details+="<p>No App Engine services found.</p>"
        fi
    fi
    
    # Check for Cloud Source Repositories (code management)
    if check_gcloud_command_access "$OUTPUT_FILE" "source" "repos"; then
        repos=$(gcloud source repos list --format="value(name)" 2>/dev/null)
        
        if [ -n "$repos" ]; then
            details+="<p class=\"green\">Cloud Source Repositories found for code management:</p><ul>"
            for repo in $repos; do
                details+="<li>$repo</li>"
            done
            details+="</ul>"
        else
            details+="<p class=\"yellow\">No Cloud Source Repositories found. Consider using version control for change management.</p>"
            found_issues=true
        fi
    fi
    
    # Check for Deployment Manager templates (Infrastructure as Code)
    deployments=$(gcloud deployment-manager deployments list --format="value(name)" 2>/dev/null)
    
    if [ -n "$deployments" ]; then
        details+="<p class=\"green\">Deployment Manager deployments found (Infrastructure as Code):</p><ul>"
        for deployment in $deployments; do
            details+="<li>$deployment</li>"
        done
        details+="</ul>"
    else
        details+="<p class=\"yellow\">No Deployment Manager deployments found. Consider using Infrastructure as Code for change control.</p>"
        found_issues=true
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check for secure development practices
check_secure_development() {
    local details=""
    local found_issues=false
    
    details+="<p>Checking secure development practices in GCP:</p>"
    
    # Check for Cloud Code and development tools
    details+="<p>Development environment security considerations:</p><ul>"
    details+="<li>Use Cloud Code IDE extensions for secure development</li>"
    details+="<li>Implement pre-commit hooks for security scanning</li>"
    details+="<li>Use Cloud Build for automated security testing</li>"
    details+="<li>Leverage Container Analysis for dependency scanning</li>"
    details+="<li>Implement Binary Authorization for deployment security</li>"
    details+="</ul>"
    
    # Check for Secret Manager usage (secure secrets management)
    if check_gcloud_command_access "$OUTPUT_FILE" "secrets" "list"; then
        secrets=$(gcloud secrets list --format="value(name)" 2>/dev/null)
        
        if [ -n "$secrets" ]; then
            details+="<p class=\"green\">Secret Manager is being used for secure secrets management:</p><ul>"
            secrets_count=$(echo "$secrets" | wc -l)
            details+="<li>$secrets_count secrets managed</li>"
            details+="</ul>"
        else
            details+="<p class=\"yellow\">No secrets found in Secret Manager. Consider using it for secure credential management.</p>"
            found_issues=true
        fi
    else
        details+="<p class=\"yellow\">Unable to check Secret Manager due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for Cloud KMS for encryption key management
    if check_gcloud_command_access "$OUTPUT_FILE" "kms" "keys"; then
        kms_keys=$(gcloud kms keys list --location=global --keyring=projects/$PROJECT_ID/locations/global/keyRings/default --format="value(name)" 2>/dev/null)
        
        if [ -n "$kms_keys" ]; then
            details+="<p class=\"green\">Cloud KMS is being used for encryption key management.</p>"
        else
            details+="<p class=\"yellow\">No Cloud KMS keys found. Consider using KMS for encryption key management.</p>"
            found_issues=true
        fi
    fi
    
    # Manual verification requirements
    details+="<p class=\"info\">Manual verification required for:</p><ul>"
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

# Main script

# Create report directory if it doesn't exist
mkdir -p "$REPORT_DIR"

# Validate gcloud CLI
validate_gcloud_cli

# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$PROJECT_ID"

# Ask for specific resources to assess
echo "============================================="
echo "  PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER GCP Report"
echo "  (Develop and Maintain Secure Systems and Software)"
echo "============================================="
echo ""

read -p "Enter resource names to assess (comma-separated or 'all' for all): " TARGET_RESOURCES
if [ -z "$TARGET_RESOURCES" ] || [ "$TARGET_RESOURCES" == "all" ]; then
    echo -e "${YELLOW}Checking all resources${NC}"
    TARGET_RESOURCES="all"
else
    echo -e "${YELLOW}Checking specific resource(s): $TARGET_RESOURCES${NC}"
fi

# Check gcloud CLI permissions
echo "Checking gcloud CLI permissions..."
add_section "$OUTPUT_FILE" "permissions" "GCloud CLI Permissions Check" "active"
check_gcloud_command_access "$OUTPUT_FILE" "builds" "list"
check_gcloud_command_access "$OUTPUT_FILE" "artifacts" "repositories"
check_gcloud_command_access "$OUTPUT_FILE" "container" "images"
check_gcloud_command_access "$OUTPUT_FILE" "compute" "security-policies"
check_gcloud_command_access "$OUTPUT_FILE" "scc" "findings"
check_gcloud_command_access "$OUTPUT_FILE" "secrets" "list"
close_section "$OUTPUT_FILE"

# Reset counters for the actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

# Requirement 6.1: Governance and Documentation
add_section "$OUTPUT_FILE" "req-6.1" "Requirement 6.1: Processes and mechanisms for developing and maintaining secure systems and software are defined and understood" "active"

# Manual verification for 6.1.1 and 6.1.2
governance_details="<p>Requirement 6.1 focuses on governance and documentation:</p><ul>"
governance_details+="<li><strong>6.1.1</strong>: Security policies and operational procedures must be documented, kept up to date, in use, and known to all affected parties</li>"
governance_details+="<li><strong>6.1.2</strong>: Roles and responsibilities for Requirement 6 activities must be documented, assigned, and understood</li>"
governance_details+="</ul>"
governance_details+="<p class=\"yellow\">Manual verification required: Ensure development security policies, procedures, and responsibilities are properly documented and communicated.</p>"

add_check_item "$OUTPUT_FILE" "warning" "6.1 - Governance and Documentation" \
    "$governance_details" \
    "Document and maintain security policies for software development, vulnerability management, and change control. Assign clear roles and responsibilities."
((warning_checks++))
((total_checks++))

close_section "$OUTPUT_FILE"

# Requirement 6.2: Bespoke and custom software are developed securely
add_section "$OUTPUT_FILE" "req-6.2" "Requirement 6.2: Bespoke and custom software are developed securely" "active"

# Check 6.2.1 - Secure development practices
echo "Checking secure development practices..."
dev_details=$(check_secure_development)
if [[ "$dev_details" == *"class=\"red\""* ]] || [[ "$dev_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "6.2.1 - Secure software development" \
        "$dev_details" \
        "Implement secure development practices using GCP security tools. Use Secret Manager for credentials, Cloud KMS for encryption, and security scanning in CI/CD pipelines."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "6.2.1 - Secure software development" \
        "$dev_details"
    ((passed_checks++))
fi
((total_checks++))

# Check 6.2.1 - Cloud Build CI/CD security
echo "Checking Cloud Build for secure CI/CD..."
cb_details=$(check_cloud_build_security)
if [[ "$cb_details" == *"class=\"red\""* ]] || [[ "$cb_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "6.2.1 - CI/CD Pipeline Security" \
        "$cb_details" \
        "Enhance Cloud Build with security scanning steps, approval processes, and secure handling of sensitive data. Include SAST, DAST, and dependency scanning in build pipelines."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "6.2.1 - CI/CD Pipeline Security" \
        "$cb_details"
    ((passed_checks++))
fi
((total_checks++))

# Manual verification for training and code reviews
training_details="<p>Manual verification required for:</p><ul>"
training_details+="<li><strong>6.2.2</strong>: Developer training on software security (at least annually)</li>"
training_details+="<li><strong>6.2.3</strong>: Code review processes before production release</li>"
training_details+="<li><strong>6.2.4</strong>: Protection against common software attacks (injection, XSS, etc.)</li>"
training_details+="</ul>"
training_details+="<p>Recommendations for GCP:</p><ul>"
training_details+="<li>Use Cloud Code for secure development environments</li>"
training_details+="<li>Implement automated security testing in Cloud Build</li>"
training_details+="<li>Use Cloud Security Scanner for web application testing</li>"
training_details+="<li>Leverage Container Analysis for dependency scanning</li>"
training_details+="</ul>"

add_check_item "$OUTPUT_FILE" "warning" "6.2.2-6.2.4 - Training and Code Review" \
    "$training_details" \
    "Implement developer security training, code review processes, and protection against common attacks using GCP security tools."
((warning_checks++))
((total_checks++))

close_section "$OUTPUT_FILE"

# Requirement 6.3: Security vulnerabilities are identified and addressed
add_section "$OUTPUT_FILE" "req-6.3" "Requirement 6.3: Security vulnerabilities are identified and addressed" "active"

# Check 6.3.1 - Vulnerability management
echo "Checking vulnerability management..."
vuln_details=$(check_vulnerability_management)
if [[ "$vuln_details" == *"class=\"red\""* ]] || [[ "$vuln_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "6.3.1 - Vulnerability identification and management" \
        "$vuln_details" \
        "Enable Security Command Center, Web Security Scanner, and Container Analysis for comprehensive vulnerability management. Address critical vulnerabilities within one month."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "6.3.1 - Vulnerability identification and management" \
        "$vuln_details"
    ((passed_checks++))
fi
((total_checks++))

# Check 6.3.2 - Container vulnerability scanning
echo "Checking container security..."
container_details=$(check_container_security)
if [[ "$container_details" == *"class=\"red\""* ]] || [[ "$container_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "6.3.2 - Container vulnerability scanning" \
        "$container_details" \
        "Enable vulnerability scanning for all container images in Artifact Registry and Container Registry. Address high and critical vulnerabilities promptly."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "6.3.2 - Container vulnerability scanning" \
        "$container_details"
    ((passed_checks++))
fi
((total_checks++))

# Manual verification for patch management
patch_details="<p>Manual verification required for:</p><ul>"
patch_details+="<li><strong>6.3.2</strong>: Maintain inventory of software components</li>"
patch_details+="<li><strong>6.3.3</strong>: Patch management (critical vulnerabilities within one month)</li>"
patch_details+="</ul>"
patch_details+="<p>Use GCP tools for patch management:</p><ul>"
patch_details+="<li>OS Config for VM patch management</li>"
patch_details+="<li>Container Analysis for container vulnerability tracking</li>"
patch_details+="<li>Security Command Center for centralized vulnerability management</li>"
patch_details+="</ul>"

add_check_item "$OUTPUT_FILE" "warning" "6.3.2-6.3.3 - Software inventory and patch management" \
    "$patch_details" \
    "Maintain software inventory and implement timely patch management using GCP tools."
((warning_checks++))
((total_checks++))

close_section "$OUTPUT_FILE"

# Requirement 6.4: Public-facing web applications are protected against attacks
add_section "$OUTPUT_FILE" "req-6.4" "Requirement 6.4: Public-facing web applications are protected against attacks" "active"

# Check 6.4.1 and 6.4.2 - Web application protection
echo "Checking web application protection..."
web_details=$(check_web_app_protection)
if [[ "$web_details" == *"class=\"red\""* ]]; then
    add_check_item "$OUTPUT_FILE" "fail" "6.4.1-6.4.2 - Web application protection" \
        "$web_details" \
        "Implement Cloud Armor security policies for all public-facing web applications. Configure protection against OWASP Top 10 vulnerabilities and enable logging."
    ((failed_checks++))
elif [[ "$web_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "6.4.1-6.4.2 - Web application protection" \
        "$web_details" \
        "Enhance web application protection with Cloud Armor. Include rate limiting, geo-blocking, and comprehensive security rules."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "6.4.1-6.4.2 - Web application protection" \
        "$web_details"
    ((passed_checks++))
fi
((total_checks++))

# Manual verification for payment page scripts
payment_details="<p>Manual verification required for:</p><ul>"
payment_details+="<li><strong>6.4.3</strong>: Payment page script management and integrity verification</li>"
payment_details+="</ul>"
payment_details+="<p>GCP recommendations:</p><ul>"
payment_details+="<li>Use Cloud CDN with signed URLs for script integrity</li>"
payment_details+="<li>Implement Content Security Policy headers</li>"
payment_details+="<li>Use Cloud Load Balancing with security headers</li>"
payment_details+="<li>Monitor script changes with Cloud Logging</li>"
payment_details+="</ul>"

add_check_item "$OUTPUT_FILE" "warning" "6.4.3 - Payment page script management" \
    "$payment_details" \
    "Implement script integrity verification and authorization mechanisms for payment pages."
((warning_checks++))
((total_checks++))

close_section "$OUTPUT_FILE"

# Requirement 6.5: Changes to all system components are managed securely
add_section "$OUTPUT_FILE" "req-6.5" "Requirement 6.5: Changes to all system components are managed securely" "active"

# Check 6.5.1-6.5.6 - Change management
echo "Checking change management and environment separation..."
change_details=$(check_change_management)
if [[ "$change_details" == *"class=\"red\""* ]] || [[ "$change_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "6.5.1-6.5.6 - Change management and environment separation" \
        "$change_details" \
        "Implement formal change management processes with proper environment separation. Use Infrastructure as Code, version control, and approval workflows."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "6.5.1-6.5.6 - Change management and environment separation" \
        "$change_details"
    ((passed_checks++))
fi
((total_checks++))

# Manual verification for change control procedures
change_proc_details="<p>Manual verification required for change control procedures:</p><ul>"
change_proc_details+="<li><strong>6.5.1</strong>: Change management procedures (reason, impact, approval, testing)</li>"
change_proc_details+="<li><strong>6.5.2</strong>: Post-change validation of PCI DSS requirements</li>"
change_proc_details+="<li><strong>6.5.3</strong>: Separation between production and pre-production</li>"
change_proc_details+="<li><strong>6.5.4</strong>: Role separation between environments</li>"
change_proc_details+="<li><strong>6.5.5</strong>: No live PANs in pre-production</li>"
change_proc_details+="<li><strong>6.5.6</strong>: Test data removal before production</li>"
change_proc_details+="</ul>"
change_proc_details+="<p>GCP best practices:</p><ul>"
change_proc_details+="<li>Use separate GCP projects for different environments</li>"
change_proc_details+="<li>Implement IAM policies for role separation</li>"
change_proc_details+="<li>Use Cloud Build for automated deployment pipelines</li>"
change_proc_details+="<li>Leverage Deployment Manager for Infrastructure as Code</li>"
change_proc_details+="</ul>"

add_check_item "$OUTPUT_FILE" "warning" "6.5 - Change control procedures" \
    "$change_proc_details" \
    "Document and implement comprehensive change management procedures with proper environment separation and role-based access controls."
((warning_checks++))
((total_checks++))

close_section "$OUTPUT_FILE"

# Finalize the report
finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"

# Summary
echo -e "\n${CYAN}=== SUMMARY OF PCI DSS REQUIREMENT $REQUIREMENT_NUMBER CHECKS ===${NC}"

compliance_percentage=0
if [ $((total_checks - warning_checks)) -gt 0 ]; then
    compliance_percentage=$(( (passed_checks * 100) / (total_checks - warning_checks) ))
fi

echo -e "\nTotal checks performed: $total_checks"
echo -e "Passed checks: $passed_checks"
echo -e "Failed checks: $failed_checks"
echo -e "Warning/manual checks: $warning_checks"
echo -e "Compliance percentage (excluding warnings): $compliance_percentage%"

echo -e "\nPCI DSS Requirement $REQUIREMENT_NUMBER assessment completed at $(date)"
echo -e "HTML Report saved to: $OUTPUT_FILE"

# Open the report
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE"
else
    echo -e "\nReport generated: $OUTPUT_FILE"
fi

echo "Assessment completed!"
echo "Total checks: $total_checks"
echo "Passed: $passed_checks"
echo "Failed: $failed_checks"
echo "Warnings (manual verification required): $warning_checks"