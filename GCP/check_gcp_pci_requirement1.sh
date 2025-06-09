#!/usr/bin/env bash

# PCI DSS Requirement 1 Compliance Check Script for GCP
# This script evaluates GCP network security controls for PCI DSS Requirement 1 compliance
# Requirements covered: 1.2 - 1.5 (Network Security Controls, CDE isolation, etc.)

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="1"

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
check_required_permissions "compute.networks.list" "compute.firewalls.list" || exit 1

# Set output file path
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"

# Initialize HTML report using shared library
initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"
# Begin main assessment logic

# Ask for CDE networks
read -p "Enter CDE VPC network names (comma-separated or 'all' for all networks): " CDE_NETWORKS
if [ -z "$CDE_NETWORKS" ] || [ "$CDE_NETWORKS" == "all" ]; then
    print_status "WARN" "Checking all VPC networks"
    CDE_NETWORKS="all"
else
    print_status "WARN" "Checking specific networks: $CDE_NETWORKS"
fi

print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 1 (GCP)"
print_status "INFO" "============================================="
echo ""

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

check_gcp_permission "Compute Engine" "instances" "gcloud compute instances list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "routes" "gcloud compute routes list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "Compute Engine" "routers" "gcloud compute routers list $PROJECT_FLAG --limit=1"
((total_checks++))

check_gcp_permission "DNS" "zones" "gcloud dns managed-zones list $PROJECT_FLAG --limit=1"
((total_checks++))

if [ "$ASSESSMENT_SCOPE" == "organization" ] && [ -n "$DEFAULT_ORG" ]; then
    check_gcp_permission "VPC Service Controls" "policies" "gcloud access-context-manager policies list --organization=$DEFAULT_ORG --limit=1"
    ((total_checks++))
fi

# Calculate permissions percentage
available_permissions=$((total_checks - access_denied_checks))
if [ $available_permissions -gt 0 ]; then
    permissions_percentage=$(( ((total_checks - access_denied_checks) * 100) / total_checks ))
else
    permissions_percentage=0
fi

if [ $permissions_percentage -lt 70 ]; then
    print_status "FAIL" "WARNING: Insufficient permissions to perform a complete PCI Requirement 1 assessment."
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
# SECTION 2: DETERMINE NETWORKS TO CHECK
#----------------------------------------------------------------------
add_html_section "$OUTPUT_FILE" "Target VPC Networks" "<p>Identifying VPC networks for assessment...</p>" "info"

print_status "INFO" "=== IDENTIFYING TARGET VPC NETWORKS ==="

if [ "$CDE_NETWORKS" == "all" ]; then
    TARGET_NETWORKS=$(get_all_networks)
    GET_NETWORKS_RESULT=$?
    if [ $GET_NETWORKS_RESULT -ne 0 ]; then
        print_status "FAIL" "Failed to retrieve VPC network information. Check your permissions."
        add_html_section "$OUTPUT_FILE" "Network Identification" "<p class='red'>Failed to retrieve VPC network information.</p>" "fail"
        exit 1
    else
        network_count=$(echo "$TARGET_NETWORKS" | wc -l)
        add_html_section "$OUTPUT_FILE" "Network Identification" "<p>All $network_count VPC networks will be assessed:</p><pre>$TARGET_NETWORKS</pre>" "info"
    fi
else
    TARGET_NETWORKS=$(echo $CDE_NETWORKS | tr ',' '\n')
    network_count=$(echo "$TARGET_NETWORKS" | wc -l)
    add_html_section "$OUTPUT_FILE" "Network Identification" "<p>Assessment will be performed on $network_count specified networks:</p><pre>$TARGET_NETWORKS</pre>" "info"
fi

#----------------------------------------------------------------------
# SECTION 3: PCI REQUIREMENT 1.2 - NETWORK SECURITY CONTROLS CONFIG
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 1.2: NETWORK SECURITY CONTROLS CONFIGURATION ==="

# Check 1.2.5 - Ports, protocols, and services inventory
print_status "INFO" "1.2.5 - Ports, protocols, and services inventory"
print_status "INFO" "Checking firewall rules for allowed ports, protocols, and services..."

firewall_details="<p>Findings for allowed ports, protocols, and services:</p><ul>"

# Get all firewall rules
firewall_rules=$(gcloud compute firewall-rules list --format="value(name,direction,sourceRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW,targetTags.join(','),network)" 2>/dev/null)

if [ -z "$firewall_rules" ]; then
    print_status "WARN" "No firewall rules found"
    firewall_details+="<li class='yellow'>No firewall rules found</li>"
else
    # Process firewall rules
    while IFS=$'\t' read -r name direction sources allowed tags network; do
        if [ -z "$name" ]; then continue; fi
        
        firewall_details+="<li><strong>Firewall Rule:</strong> $name</li><ul>"
        firewall_details+="<li><strong>Direction:</strong> $direction</li>"
        firewall_details+="<li><strong>Network:</strong> $network</li>"
        
        # Check for overly permissive rules (0.0.0.0/0)
        if [[ "$sources" == *"0.0.0.0/0"* ]]; then
            print_status "FAIL" "WARNING: Firewall rule $name allows traffic from anywhere (0.0.0.0/0)"
            firewall_details+="<li class='red'><strong>WARNING:</strong> Allows traffic from anywhere (0.0.0.0/0)</li>"
            
            if [ -n "$allowed" ]; then
                firewall_details+="<li><strong>Allowed protocols/ports:</strong></li><ul>"
                # Parse allowed protocols and ports
                IFS=',' read -ra PROTOCOLS <<< "$allowed"
                for protocol in "${PROTOCOLS[@]}"; do
                    print_status "FAIL" "  $protocol open to the internet"
                    firewall_details+="<li class='red'>$protocol open to the internet</li>"
                done
                firewall_details+="</ul>"
            fi
        else
            print_status "PASS" "Firewall rule $name has restricted source ranges"
            firewall_details+="<li class='green'>Has restricted source ranges: $sources</li>"
        fi
        
        if [ -n "$tags" ]; then
            firewall_details+="<li><strong>Target tags:</strong> $tags</li>"
        fi
        
        firewall_details+="</ul>"
        
    done <<< "$firewall_rules"
fi

firewall_details+="</ul>"

add_html_section "$OUTPUT_FILE" "1.2.5 - Ports, protocols, and services inventory" "$firewall_details" "info"
((total_checks++))

# Check 1.2.6 - Security features for insecure services/protocols
print_status "INFO" "1.2.6 - Security features for insecure services/protocols"
print_status "INFO" "Checking for common insecure services/protocols in firewall rules..."

insecure_services=false
insecure_details="<p>Analysis of insecure services/protocols in firewall rules:</p><ul>"

# Check for insecure protocols in firewall rules
while IFS=$'\t' read -r name direction sources allowed tags network; do
    if [ -z "$name" ]; then continue; fi
    
    rule_has_insecure=false
    
    # Check for common insecure ports/protocols
    if [[ "$allowed" == *"tcp:21"* ]]; then
        print_status "FAIL" "WARNING: Firewall rule $name allows FTP (port 21)"
        insecure_details+="<li class='red'>Rule $name allows FTP (port 21) - Insecure cleartext protocol</li>"
        insecure_services=true
        rule_has_insecure=true
    fi
    
    if [[ "$allowed" == *"tcp:23"* ]]; then
        print_status "FAIL" "WARNING: Firewall rule $name allows Telnet (port 23)"
        insecure_details+="<li class='red'>Rule $name allows Telnet (port 23) - Insecure cleartext protocol</li>"
        insecure_services=true
        rule_has_insecure=true
    fi
    
    if [[ "$allowed" == *"tcp:1433"* ]]; then
        print_status "WARN" "NOTE: Firewall rule $name allows SQL Server (port 1433) - ensure encryption is in use"
        insecure_details+="<li class='yellow'>Rule $name allows SQL Server (port 1433) - Ensure encryption is in use</li>"
        insecure_services=true
        rule_has_insecure=true
    fi
    
    if [[ "$allowed" == *"tcp:3306"* ]]; then
        print_status "WARN" "NOTE: Firewall rule $name allows MySQL (port 3306) - ensure encryption is in use"
        insecure_details+="<li class='yellow'>Rule $name allows MySQL (port 3306) - Ensure encryption is in use</li>"
        insecure_services=true
        rule_has_insecure=true
    fi
    
done <<< "$firewall_rules"

insecure_details+="</ul>"

if [ "$insecure_services" = false ]; then
    print_status "PASS" "No common insecure services/protocols detected in firewall rules"
    add_html_section "$OUTPUT_FILE" "1.2.6 - Security features for insecure services/protocols" "<p class='green'>No common insecure services/protocols detected in firewall rules</p>" "pass"
    ((passed_checks++))
else
    print_status "FAIL" "Insecure services/protocols detected in firewall rules"
    add_html_section "$OUTPUT_FILE" "1.2.6 - Security features for insecure services/protocols" "$insecure_details" "fail"
    ((failed_checks++))
fi
((total_checks++))

# Check 1.2.7 - Regular review of NSC configurations
print_status "INFO" "1.2.7 - Regular review of NSC configurations"
print_status "INFO" "Checking for Security Command Center and monitoring configurations"

# Check if Security Command Center is enabled
scc_enabled=$(gcloud security-center organizations list 2>/dev/null | wc -l)
if [ $scc_enabled -gt 0 ]; then
    print_status "PASS" "Security Command Center is available for monitoring"
    add_html_section "$OUTPUT_FILE" "1.2.7 - NSC configuration monitoring" "<p class='green'>Security Command Center is available for monitoring NSC configurations.</p>" "pass"
    ((passed_checks++))
else
    print_status "WARN" "Security Command Center not detected"
    add_html_section "$OUTPUT_FILE" "1.2.7 - NSC configuration monitoring" "<p class='yellow'>Security Command Center not detected. Consider enabling for automated monitoring.</p>" "warning"
    ((warning_checks++))
fi
((total_checks++))

# Check 1.2.8 - NSC configuration files security
print_status "INFO" "1.2.8 - NSC configuration files security"
print_status "INFO" "Checking for IAM policies affecting NSC configuration security"

# Check for overly permissive IAM policies
compute_admin_bindings=$(gcloud projects get-iam-policy $DEFAULT_PROJECT --format="value(bindings[?role=='roles/compute.admin'].members[])" 2>/dev/null | wc -l)
network_admin_bindings=$(gcloud projects get-iam-policy $DEFAULT_PROJECT --format="value(bindings[?role=='roles/compute.networkAdmin'].members[])" 2>/dev/null | wc -l)

total_admin_bindings=$((compute_admin_bindings + network_admin_bindings))

if [ $total_admin_bindings -gt 5 ]; then
    print_status "WARN" "Multiple users/service accounts have network administration privileges"
    add_html_section "$OUTPUT_FILE" "1.2.8 - NSC configuration files security" "<p class='yellow'>Multiple users/service accounts have network administration privileges ($total_admin_bindings total). Review for least privilege compliance.</p>" "warning"
    ((warning_checks++))
else
    print_status "PASS" "Limited number of network administrators detected"
    add_html_section "$OUTPUT_FILE" "1.2.8 - NSC configuration files security" "<p class='green'>Limited number of network administrators detected ($total_admin_bindings total).</p>" "pass"
    ((passed_checks++))
fi
((total_checks++))

#----------------------------------------------------------------------
# SECTION 4: PCI REQUIREMENT 1.3 - CDE NETWORK ACCESS RESTRICTION
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 1.3: CDE NETWORK ACCESS RESTRICTION ==="

# Check 1.3.1 - Inbound traffic to CDE restriction
print_status "INFO" "1.3.1 - Inbound traffic to CDE restriction"
print_status "INFO" "Checking for properly restricted inbound traffic to CDE networks..."

inbound_restriction_details="<p>Analysis of inbound traffic controls for CDE networks:</p><ul>"

for network in $TARGET_NETWORKS; do
    if [ -z "$network" ]; then continue; fi
    
    inbound_restriction_details+="<li><strong>Network:</strong> $network</li><ul>"
    
    # Get subnets for this network
    subnets=$(gcloud compute networks subnets list --filter="network:$network" --format="value(name,region)" 2>/dev/null)
    
    if [ -z "$subnets" ]; then
        inbound_restriction_details+="<li class='yellow'>No subnets found in network</li>"
        continue
    fi
    
    # Check firewall rules for this network
    network_fw_rules=$(gcloud compute firewall-rules list --filter="network:$network AND direction:INGRESS" --format="value(name,sourceRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW)" 2>/dev/null)
    
    if [ -n "$network_fw_rules" ]; then
        inbound_restriction_details+="<li><strong>Ingress firewall rules:</strong></li><ul>"
        
        while IFS=$'\t' read -r fw_name sources allowed; do
            if [ -z "$fw_name" ]; then continue; fi
            
            inbound_restriction_details+="<li>$fw_name</li>"
            
            if [[ "$sources" == *"0.0.0.0/0"* ]]; then
                inbound_restriction_details+="<li class='red'>WARNING: Allows traffic from anywhere (0.0.0.0/0)</li>"
            else
                inbound_restriction_details+="<li class='green'>Restricted sources: $sources</li>"
            fi
            
        done <<< "$network_fw_rules"
        
        inbound_restriction_details+="</ul>"
    else
        inbound_restriction_details+="<li class='green'>No permissive ingress rules found</li>"
    fi
    
    inbound_restriction_details+="</ul>"
done

inbound_restriction_details+="</ul>"

add_html_section "$OUTPUT_FILE" "1.3.1 - Inbound traffic to CDE restriction" "$inbound_restriction_details" "warning"
((total_checks++))
((warning_checks++))

# Check 1.3.2 - Outbound traffic from CDE restriction
print_status "INFO" "1.3.2 - Outbound traffic from CDE restriction"
print_status "INFO" "Checking for properly restricted outbound traffic from CDE networks..."

outbound_restriction_details="<p>Analysis of outbound traffic controls for CDE networks:</p><ul>"

for network in $TARGET_NETWORKS; do
    if [ -z "$network" ]; then continue; fi
    
    outbound_restriction_details+="<li><strong>Network:</strong> $network</li><ul>"
    
    # Check egress firewall rules for this network
    network_egress_rules=$(gcloud compute firewall-rules list --filter="network:$network AND direction:EGRESS" --format="value(name,destinationRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW)" 2>/dev/null)
    
    if [ -n "$network_egress_rules" ]; then
        outbound_restriction_details+="<li><strong>Egress firewall rules:</strong></li><ul>"
        
        while IFS=$'\t' read -r fw_name destinations allowed; do
            if [ -z "$fw_name" ]; then continue; fi
            
            outbound_restriction_details+="<li>$fw_name</li>"
            
            if [[ "$destinations" == *"0.0.0.0/0"* ]]; then
                outbound_restriction_details+="<li class='yellow'>Allows traffic to anywhere (0.0.0.0/0)</li>"
            else
                outbound_restriction_details+="<li class='green'>Restricted destinations: $destinations</li>"
            fi
            
        done <<< "$network_egress_rules"
        
        outbound_restriction_details+="</ul>"
    else
        outbound_restriction_details+="<li class='yellow'>No explicit egress rules found (default allow all)</li>"
    fi
    
    outbound_restriction_details+="</ul>"
done

outbound_restriction_details+="</ul>"

add_html_section "$OUTPUT_FILE" "1.3.2 - Outbound traffic from CDE restriction" "$outbound_restriction_details" "warning"
((total_checks++))
((warning_checks++))

# Check 1.3.3 - Private IP filtering
print_status "INFO" "1.3.3 - Private IP filtering"
print_status "INFO" "Checking for private IP filtering at network boundaries..."

private_ip_details="<p>Analysis of potential private IP exposure:</p><ul>"

# Check for VPC peering connections
vpc_peerings=$(gcloud compute networks peerings list --format="value(name,network,peerNetwork)" 2>/dev/null)

if [ -z "$vpc_peerings" ]; then
    print_status "PASS" "No VPC peering connections detected"
    private_ip_details+="<li class='green'>No VPC peering connections detected</li>"
else
    print_status "WARN" "VPC peering connections detected - potential private IP routing:"
    private_ip_details+="<li class='yellow'>VPC peering connections detected:</li><ul>"
    
    while IFS=$'\t' read -r peering_name network peer_network; do
        if [ -z "$peering_name" ]; then continue; fi
        
        print_status "WARN" "  Peering: $peering_name ($network <-> $peer_network)"
        private_ip_details+="<li>$peering_name: $network ↔ $peer_network</li>"
        
    done <<< "$vpc_peerings"
    
    private_ip_details+="</ul>"
fi

# Check for VPN connections
vpn_gateways=$(gcloud compute vpn-gateways list --format="value(name,region)" 2>/dev/null)

if [ -z "$vpn_gateways" ]; then
    print_status "PASS" "No VPN gateways detected"
    private_ip_details+="<li class='green'>No VPN gateways detected</li>"
else
    print_status "WARN" "VPN gateways detected - potential private IP routing:"
    private_ip_details+="<li class='yellow'>VPN gateways detected:</li><ul>"
    
    while IFS=$'\t' read -r gw_name region; do
        if [ -z "$gw_name" ]; then continue; fi
        
        print_status "WARN" "  VPN Gateway: $gw_name (region: $region)"
        private_ip_details+="<li>$gw_name (region: $region)</li>"
        
    done <<< "$vpn_gateways"
    
    private_ip_details+="</ul>"
fi

private_ip_details+="</ul>"

add_html_section "$OUTPUT_FILE" "1.3.3 - Private IP filtering" "$private_ip_details" "info"
((total_checks++))

#----------------------------------------------------------------------
# SECTION 5: PCI REQUIREMENT 1.4 - NETWORK CONNECTIONS
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 1.4: NETWORK CONNECTIONS BETWEEN TRUSTED/UNTRUSTED NETWORKS ==="

# Check 1.4.1 - Network connection controls
print_status "INFO" "1.4.1 - Network connection controls"
print_status "INFO" "Checking for controls on network connections between trusted and untrusted networks..."

connection_controls_details="<p>Analysis of network connections between trusted and untrusted networks:</p><ul>"

for network in $TARGET_NETWORKS; do
    if [ -z "$network" ]; then continue; fi
    
    connection_controls_details+="<li><strong>Network:</strong> $network</li><ul>"
    
    # Check for Cloud NAT
    cloud_nats=$(gcloud compute routers list --filter="network:$network" --format="value(name,region)" 2>/dev/null)
    
    if [ -n "$cloud_nats" ]; then
        connection_controls_details+="<li class='green'>Cloud NAT routers detected (controlled outbound access):</li><ul>"
        
        while IFS=$'\t' read -r router_name region; do
            if [ -z "$router_name" ]; then continue; fi
            
            connection_controls_details+="<li>$router_name (region: $region)</li>"
            
        done <<< "$cloud_nats"
        
        connection_controls_details+="</ul>"
    else
        connection_controls_details+="<li class='yellow'>No Cloud NAT routers detected</li>"
    fi
    
    # Check for external IP addresses on instances
    external_ips=$(gcloud compute instances list --filter="networkInterfaces.network:$network" --format="value(name,networkInterfaces[0].accessConfigs[0].natIP)" 2>/dev/null | grep -v "^[[:space:]]*$")
    
    if [ -n "$external_ips" ]; then
        connection_controls_details+="<li class='yellow'>Instances with external IP addresses:</li><ul>"
        
        while IFS=$'\t' read -r instance_name external_ip; do
            if [ -z "$instance_name" ]; then continue; fi
            
            if [ -n "$external_ip" ]; then
                connection_controls_details+="<li>$instance_name: $external_ip</li>"
            fi
            
        done <<< "$external_ips"
        
        connection_controls_details+="</ul>"
    else
        connection_controls_details+="<li class='green'>No instances with external IP addresses detected</li>"
    fi
    
    connection_controls_details+="</ul>"
done

connection_controls_details+="</ul>"

add_html_section "$OUTPUT_FILE" "1.4.1 - Network connection controls" "$connection_controls_details" "info"
((total_checks++))

# Check 1.4.2 - Private IP address filtering
print_status "INFO" "1.4.2 - Private IP address filtering"
print_status "INFO" "Checking for private IP address filtering controls..."

# Check for VPC Service Controls
vsc_perimeters=""
if [ -n "$DEFAULT_ORG" ]; then
    # Try to get access policies first
    access_policies=$(gcloud access-context-manager policies list --organization=$DEFAULT_ORG --format="value(name)" 2>/dev/null)
    
    if [ -n "$access_policies" ]; then
        for policy in $access_policies; do
            perimeters=$(gcloud access-context-manager perimeters list --policy=$policy --format="value(name,title)" 2>/dev/null)
            if [ -n "$perimeters" ]; then
                vsc_perimeters+="$perimeters"$'\n'
            fi
        done
    fi
fi

vsc_details="<p>Analysis of private IP address filtering controls:</p><ul>"

if [ -n "$vsc_perimeters" ]; then
    print_status "PASS" "VPC Service Controls perimeters detected"
    vsc_details+="<li class='green'>VPC Service Controls perimeters detected:</li><ul>"
    
    while IFS=$'\t' read -r perimeter_name title; do
        if [ -z "$perimeter_name" ]; then continue; fi
        
        vsc_details+="<li>$perimeter_name ($title)</li>"
        
    done <<< "$vsc_perimeters"
    
    vsc_details+="</ul>"
    vsc_details+="<li>These provide additional private IP filtering controls</li>"
    
    add_html_section "$OUTPUT_FILE" "1.4.2 - Private IP address filtering" "$vsc_details" "pass"
    ((passed_checks++))
else
    print_status "WARN" "No VPC Service Controls perimeters detected"
    vsc_details+="<li class='yellow'>No VPC Service Controls perimeters detected</li>"
    vsc_details+="<li>Consider implementing VPC Service Controls for enhanced private IP filtering</li>"
    
    add_html_section "$OUTPUT_FILE" "1.4.2 - Private IP address filtering" "$vsc_details" "warning"
    ((warning_checks++))
fi

vsc_details+="</ul>"
((total_checks++))

#----------------------------------------------------------------------
# SECTION 6: PCI REQUIREMENT 1.5 - FIREWALL RULE MANAGEMENT
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 1.5: NETWORK SECURITY CONTROL RULESET MANAGEMENT ==="

# Check 1.5.1 - Firewall rule management
print_status "INFO" "1.5.1 - Firewall rule management"
print_status "INFO" "Checking for proper firewall rule management..."

rule_management_details="<p>Analysis of firewall rule management:</p><ul>"

# Get all firewall rules and analyze them
all_fw_rules=$(gcloud compute firewall-rules list --format="value(name,disabled,priority,direction)" 2>/dev/null)

total_rules=0
disabled_rules=0
high_priority_rules=0

while IFS=$'\t' read -r rule_name disabled priority direction; do
    if [ -z "$rule_name" ]; then continue; fi
    
    ((total_rules++))
    
    if [ "$disabled" == "True" ]; then
        ((disabled_rules++))
    fi
    
    # Check for high priority rules (lower number = higher priority)
    if [ -n "$priority" ] && [ "$priority" -lt 1000 ]; then
        ((high_priority_rules++))
    fi
    
done <<< "$all_fw_rules"

rule_management_details+="<li><strong>Total firewall rules:</strong> $total_rules</li>"
rule_management_details+="<li><strong>Disabled rules:</strong> $disabled_rules</li>"
rule_management_details+="<li><strong>High priority rules:</strong> $high_priority_rules</li>"

if [ $disabled_rules -gt 0 ]; then
    rule_management_details+="<li class='yellow'>Consider removing disabled firewall rules to simplify management</li>"
fi

if [ $total_rules -gt 50 ]; then
    rule_management_details+="<li class='yellow'>Large number of firewall rules detected - review for consolidation opportunities</li>"
fi

# Check for default-allow rules
default_allow_rules=$(gcloud compute firewall-rules list --filter="name:default-allow*" --format="value(name)" 2>/dev/null | wc -l)

if [ $default_allow_rules -gt 0 ]; then
    rule_management_details+="<li class='red'>Default allow rules detected: $default_allow_rules</li>"
    rule_management_details+="<li>Review default allow rules for security implications</li>"
else
    rule_management_details+="<li class='green'>No default allow rules detected</li>"
fi

rule_management_details+="</ul>"

add_html_section "$OUTPUT_FILE" "1.5.1 - Firewall rule management" "$rule_management_details" "info"
((total_checks++))

#----------------------------------------------------------------------
# FINAL REPORT
#----------------------------------------------------------------------

# Add final summary metrics
add_summary_metrics "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"

# Finalize HTML report using shared library
finalize_report "$OUTPUT_FILE" "${REQUIREMENT_NUMBER}"

# Display final summary using shared library
print_status "INFO" "=== ASSESSMENT SUMMARY ==="
print_status "INFO" "Total checks: $total_checks"
print_status "PASS" "Passed: $passed_checks"
print_status "FAIL" "Failed: $failed_checks"
print_status "WARN" "Warnings: $warning_checks"
print_status "INFO" "Report has been generated: $OUTPUT_FILE"
print_status "PASS" "=================================================================="