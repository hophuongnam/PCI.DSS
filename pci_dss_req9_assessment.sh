#!/bin/bash
#
# PCI DSS v4.0 Requirement 9 Assessment Script for Google Cloud Platform
# This script assesses compliance with PCI DSS Requirement 9: Restrict Physical Access to Cardholder Data
#
# Note: While many physical security controls are managed by GCP, this script focuses on the 
# aspects that can be verified through GCP configuration and best practices.

# Set strict error handling
set -o errexit
set -o pipefail
set -o nounset

# Global variables
PROJECT_ID=""
REPORT_FILE="pci_dss_req9_report.html"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
TEMP_DIR=$(mktemp -d)
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Color codes for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to display usage information
usage() {
    echo "Usage: $0 --project-id=PROJECT_ID [--output=OUTPUT_FILE]"
    echo ""
    echo "Options:"
    echo "  --project-id=PROJECT_ID    GCP Project ID to assess (required)"
    echo "  --output=OUTPUT_FILE       Output HTML report file (default: pci_dss_req9_report.html)"
    echo ""
    exit 1
}

# Function to log messages
log() {
    local level=$1
    local message=$2
    
    case $level in
        "INFO")
            echo -e "[${GREEN}INFO${NC}] $message"
            ;;
        "WARNING")
            echo -e "[${YELLOW}WARNING${NC}] $message"
            ;;
        "ERROR")
            echo -e "[${RED}ERROR${NC}] $message"
            ;;
        *)
            echo "[$level] $message"
            ;;
    esac
}

# Function to validate JSON output
validate_json() {
    local json_file=$1
    local default_value=${2:-"[]"}
    
    if [[ ! -f "$json_file" ]]; then
        echo "$default_value"
        return 1
    fi
    
    if ! jq empty "$json_file" 2>/dev/null; then
        echo "$default_value"
        return 1
    fi
    
    # Check if the content is an array, if not, wrap it
    local content=$(cat "$json_file")
    if [[ $(jq 'if type == "array" then "array" else "not_array" end' <<< "$content" 2>/dev/null) != "array" ]]; then
        jq -s '.' "$json_file" 2>/dev/null || echo "$default_value"
    else
        cat "$json_file"
    fi
}

# Function to check if gcloud is installed and authenticated
check_gcloud() {
    if ! command -v gcloud &> /dev/null; then
        log "ERROR" "gcloud CLI is not installed. Please install it and try again."
        exit 1
    fi
    
    # Check if user is authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        log "ERROR" "Not authenticated with gcloud. Please run 'gcloud auth login' and try again."
        exit 1
    fi
    
    # Verify project exists and is accessible
    if ! gcloud projects describe "$PROJECT_ID" &> /dev/null; then
        log "ERROR" "Project $PROJECT_ID not found or not accessible. Please check the project ID and your permissions."
        exit 1
    fi
    
    log "INFO" "Successfully authenticated with gcloud and verified access to project $PROJECT_ID"
}

# Function to add a finding to the report
add_finding() {
    local requirement=$1
    local status=$2
    local title=$3
    local details=$4
    local recommendation=$5
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    case $status in
        "PASS")
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            status_color="green"
            ;;
        "WARNING")
            WARNING_CHECKS=$((WARNING_CHECKS + 1))
            status_color="orange"
            ;;
        "FAIL")
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            status_color="red"
            ;;
        *)
            status_color="gray"
            ;;
    esac
    
    # Escape HTML special characters in details and recommendation
    details=$(echo "$details" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g')
    recommendation=$(echo "$recommendation" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g')
    
    # Add to findings array for later inclusion in the report
    echo "<div class=\"finding\">" >> "$TEMP_DIR/findings.html"
    echo "  <div class=\"finding-header\">" >> "$TEMP_DIR/findings.html"
    echo "    <span class=\"requirement\">$requirement</span>" >> "$TEMP_DIR/findings.html"
    echo "    <span class=\"status status-$status_color\">$status</span>" >> "$TEMP_DIR/findings.html"
    echo "  </div>" >> "$TEMP_DIR/findings.html"
    echo "  <div class=\"finding-content\">" >> "$TEMP_DIR/findings.html"
    echo "    <h3>$title</h3>" >> "$TEMP_DIR/findings.html"
    echo "    <div class=\"details\"><strong>Details:</strong> $details</div>" >> "$TEMP_DIR/findings.html"
    echo "    <div class=\"recommendation\"><strong>Recommendation:</strong> $recommendation</div>" >> "$TEMP_DIR/findings.html"
    echo "  </div>" >> "$TEMP_DIR/findings.html"
    echo "</div>" >> "$TEMP_DIR/findings.html"
}

# Function to initialize the HTML report
initialize_report() {
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS v4.0 Requirement 9 Assessment Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .header {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .summary {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .summary-stats {
            display: flex;
            justify-content: space-around;
            text-align: center;
            margin: 20px 0;
        }
        .stat {
            padding: 10px;
            border-radius: 5px;
        }
        .stat-passed {
            background-color: #d4edda;
            color: #155724;
        }
        .stat-warning {
            background-color: #fff3cd;
            color: #856404;
        }
        .stat-failed {
            background-color: #f8d7da;
            color: #721c24;
        }
        .finding {
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 15px;
            overflow: hidden;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            background-color: #f8f9fa;
            border-bottom: 1px solid #ddd;
        }
        .finding-content {
            padding: 15px;
        }
        .requirement {
            font-weight: bold;
        }
        .status {
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
        }
        .status-green {
            background-color: #d4edda;
            color: #155724;
        }
        .status-orange {
            background-color: #fff3cd;
            color: #856404;
        }
        .status-red {
            background-color: #f8d7da;
            color: #721c24;
        }
        .details, .recommendation {
            margin-top: 10px;
        }
        .section {
            margin-bottom: 30px;
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .footer {
            margin-top: 30px;
            border-top: 1px solid #ddd;
            padding-top: 10px;
            font-size: 0.9em;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>PCI DSS v4.0 Requirement 9 Assessment Report</h1>
        <p>Project ID: $PROJECT_ID</p>
        <p>Assessment Date: $TIMESTAMP</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary">
            <p>This report presents the findings of an automated assessment of Google Cloud Platform configurations against PCI DSS v4.0 Requirement 9: Restrict Physical Access to Cardholder Data.</p>
            <p>While many physical security controls are managed by Google Cloud Platform as part of their shared responsibility model, this assessment focuses on the configurations and practices that organizations can control and verify.</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Assessment Scope</h2>
        <p>The assessment covers the following aspects of PCI DSS Requirement 9:</p>
        <ul>
            <li>9.2: Physical access controls for GCP resources</li>
            <li>9.3: Personnel and visitor access management</li>
            <li>9.4: Media protection and secure storage</li>
            <li>9.5: Protection of point-of-interaction (POI) devices</li>
        </ul>
        <p>Note: Some physical security requirements are managed by Google Cloud Platform and cannot be directly assessed through API calls.</p>
    </div>
    
    <div class="section">
        <h2>Findings</h2>
        <!-- Findings will be inserted here -->
EOF

    # Create an empty findings file
    > "$TEMP_DIR/findings.html"
}

# Function to finalize the HTML report
finalize_report() {
    # Calculate pass percentage
    local pass_percentage=0
    if [ $TOTAL_CHECKS -gt 0 ]; then
        pass_percentage=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
    fi
    
    # Insert summary statistics
    cat >> "$REPORT_FILE" << EOF
        <div class="summary-stats">
            <div class="stat stat-passed">
                <h3>$PASSED_CHECKS</h3>
                <p>Passed</p>
            </div>
            <div class="stat stat-warning">
                <h3>$WARNING_CHECKS</h3>
                <p>Warnings</p>
            </div>
            <div class="stat stat-failed">
                <h3>$FAILED_CHECKS</h3>
                <p>Failed</p>
            </div>
            <div class="stat">
                <h3>$pass_percentage%</h3>
                <p>Compliance</p>
            </div>
        </div>
EOF

    # Insert findings
    if [ -f "$TEMP_DIR/findings.html" ]; then
        cat "$TEMP_DIR/findings.html" >> "$REPORT_FILE"
    fi
    
    # Close the report
    cat >> "$REPORT_FILE" << EOF
    </div>
    
    <div class="section">
        <h2>Recommendations Summary</h2>
        <p>Based on the findings, consider implementing the following key recommendations:</p>
        <ul>
            <li>Review and implement proper IAM controls for all storage resources containing sensitive data</li>
            <li>Ensure encryption is enabled for all storage containing cardholder data</li>
            <li>Implement proper backup and retention policies</li>
            <li>Document and maintain procedures for secure media handling in cloud environments</li>
            <li>Regularly review access logs and audit trails for storage resources</li>
        </ul>
    </div>
    
    <div class="footer">
        <p>This report was generated automatically and should be reviewed by security professionals familiar with PCI DSS requirements.</p>
        <p>Google Cloud Platform provides many physical security controls as part of their shared responsibility model. Refer to GCP documentation for details on physical security measures implemented by Google.</p>
    </div>
</body>
</html>
EOF

    log "INFO" "Report generated: $REPORT_FILE"
}

# Function to check Cloud Storage bucket configurations
check_storage_buckets() {
    log "INFO" "Checking Cloud Storage bucket configurations..."
    
    # Get list of storage buckets
    gcloud storage ls --project="$PROJECT_ID" --format=json > "$TEMP_DIR/buckets.json" 2>/dev/null || {
        log "WARNING" "Failed to retrieve storage buckets. Check permissions or if Storage API is enabled."
        add_finding "9.4.1" "WARNING" "Cloud Storage Bucket Inventory" \
            "Failed to retrieve storage bucket inventory. This may indicate insufficient permissions or the Storage API is not enabled." \
            "Ensure the script is run with sufficient permissions (roles/storage.admin or roles/viewer) and the Storage API is enabled."
        return
    }
    
    # Validate JSON output
    BUCKETS_JSON=$(validate_json "$TEMP_DIR/buckets.json")
    
    # Check if we have any buckets
    BUCKET_COUNT=$(echo "$BUCKETS_JSON" | jq '. | length')
    
    if [ "$BUCKET_COUNT" -eq 0 ]; then
        add_finding "9.4.1" "PASS" "No Cloud Storage Buckets Found" \
            "No Cloud Storage buckets were found in the project." \
            "No action needed. If you expect to have storage buckets, verify project ID and permissions."
        return
    fi
    
    # Extract bucket names
    echo "$BUCKETS_JSON" | jq -r '.[] | .name' > "$TEMP_DIR/bucket_names.txt"
    
    # Check each bucket's configuration
    while IFS= read -r bucket_name; do
        # Get bucket details
        gcloud storage buckets describe "gs://$bucket_name" --format=json > "$TEMP_DIR/bucket_details.json" 2>/dev/null || {
            log "WARNING" "Failed to retrieve details for bucket: $bucket_name"
            continue
        }
        
        # Check encryption settings
        ENCRYPTION_TYPE=$(jq -r '.encryption.defaultKmsKeyName // "Google-managed"' "$TEMP_DIR/bucket_details.json")
        
        if [ "$ENCRYPTION_TYPE" == "Google-managed" ]; then
            add_finding "9.4.1" "WARNING" "Default Encryption for Bucket $bucket_name" \
                "Bucket $bucket_name is using Google-managed encryption keys. For PCI DSS compliance, consider using customer-managed encryption keys (CMEK) for better control." \
                "Configure customer-managed encryption keys (CMEK) for buckets that may contain cardholder data or sensitive authentication data."
        else
            add_finding "9.4.1" "PASS" "Custom Encryption for Bucket $bucket_name" \
                "Bucket $bucket_name is using customer-managed encryption keys: $ENCRYPTION_TYPE" \
                "Maintain proper key management procedures for the customer-managed keys."
        fi
        
        # Check public access prevention
        PUBLIC_ACCESS=$(jq -r '.iamConfiguration.publicAccessPrevention // "inherited"' "$TEMP_DIR/bucket_details.json")
        
        if [ "$PUBLIC_ACCESS" != "enforced" ]; then
            add_finding "9.4.1" "FAIL" "Public Access Prevention Not Enforced for $bucket_name" \
                "Bucket $bucket_name does not have public access prevention enforced. This could potentially allow public access to data if IAM policies are misconfigured." \
                "Enable public access prevention for all buckets that may contain cardholder data or sensitive authentication data."
        else
            add_finding "9.4.1" "PASS" "Public Access Prevention Enforced for $bucket_name" \
                "Bucket $bucket_name has public access prevention enforced." \
                "Continue to monitor for any changes to this configuration."
        fi
        
        # Check bucket IAM policies
        gcloud storage buckets get-iam-policy "gs://$bucket_name" --format=json > "$TEMP_DIR/bucket_iam.json" 2>/dev/null || {
            log "WARNING" "Failed to retrieve IAM policy for bucket: $bucket_name"
            continue
        }
        
        # Check for public access in IAM policy
        PUBLIC_IAM=$(jq '.bindings[] | select(.members[] | contains("allUsers") or contains("allAuthenticatedUsers"))' "$TEMP_DIR/bucket_iam.json" 2>/dev/null)
        
        if [ -n "$PUBLIC_IAM" ]; then
            add_finding "9.4.1" "FAIL" "Public IAM Access for Bucket $bucket_name" \
                "Bucket $bucket_name has IAM policies that grant access to 'allUsers' or 'allAuthenticatedUsers', making it publicly accessible." \
                "Remove public access by updating the IAM policy to remove 'allUsers' and 'allAuthenticatedUsers' members."
        else
            add_finding "9.4.1" "PASS" "No Public IAM Access for Bucket $bucket_name" \
                "Bucket $bucket_name does not have IAM policies that grant public access." \
                "Continue to monitor for any changes to IAM policies."
        fi
        
        # Check object versioning (for media protection)
        VERSIONING=$(jq -r '.versioning.enabled // false' "$TEMP_DIR/bucket_details.json")
        
        if [ "$VERSIONING" == "true" ]; then
            add_finding "9.4.1" "PASS" "Object Versioning Enabled for $bucket_name" \
                "Bucket $bucket_name has object versioning enabled, which helps protect against accidental deletion or modification of data." \
                "Ensure proper lifecycle policies are in place to manage versioned objects."
        else
            add_finding "9.4.1" "WARNING" "Object Versioning Not Enabled for $bucket_name" \
                "Bucket $bucket_name does not have object versioning enabled. This may not provide adequate protection against accidental deletion or modification." \
                "Consider enabling object versioning for buckets that contain cardholder data or sensitive authentication data."
        fi
        
    done < "$TEMP_DIR/bucket_names.txt"
}

# Function to check Cloud SQL instance configurations
check_cloud_sql() {
    log "INFO" "Checking Cloud SQL instance configurations..."
    
    # Get list of Cloud SQL instances
    gcloud sql instances list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/sql_instances.json" 2>/dev/null || {
        log "WARNING" "Failed to retrieve Cloud SQL instances. Check permissions or if SQL API is enabled."
        add_finding "9.4.1" "WARNING" "Cloud SQL Instance Inventory" \
            "Failed to retrieve Cloud SQL instance inventory. This may indicate insufficient permissions or the SQL API is not enabled." \
            "Ensure the script is run with sufficient permissions and the SQL API is enabled."
        return
    }
    
    # Validate JSON output
    SQL_INSTANCES_JSON=$(validate_json "$TEMP_DIR/sql_instances.json")
    
    # Check if we have any SQL instances
    INSTANCE_COUNT=$(echo "$SQL_INSTANCES_JSON" | jq '. | length')
    
    if [ "$INSTANCE_COUNT" -eq 0 ]; then
        add_finding "9.4.1" "PASS" "No Cloud SQL Instances Found" \
            "No Cloud SQL instances were found in the project." \
            "No action needed. If you expect to have SQL instances, verify project ID and permissions."
        return
    fi
    
    # Check each SQL instance's configuration
    echo "$SQL_INSTANCES_JSON" | jq -c '.[]' | while read -r instance; do
        INSTANCE_NAME=$(echo "$instance" | jq -r '.name')
        
        # Check encryption settings
        CMEK_CONFIG=$(echo "$instance" | jq -r '.diskEncryptionConfiguration.kmsKeyName // "none"')
        
        if [ "$CMEK_CONFIG" == "none" ]; then
            add_finding "9.4.1" "WARNING" "Default Encryption for SQL Instance $INSTANCE_NAME" \
                "Cloud SQL instance $INSTANCE_NAME is using Google-managed encryption keys. For PCI DSS compliance, consider using customer-managed encryption keys (CMEK) for better control." \
                "Configure customer-managed encryption keys (CMEK) for SQL instances that may contain cardholder data."
        else
            add_finding "9.4.1" "PASS" "Custom Encryption for SQL Instance $INSTANCE_NAME" \
                "Cloud SQL instance $INSTANCE_NAME is using customer-managed encryption keys: $CMEK_CONFIG" \
                "Maintain proper key management procedures for the customer-managed keys."
        fi
        
        # Check backup configuration
        BACKUP_ENABLED=$(echo "$instance" | jq -r '.settings.backupConfiguration.enabled // false')
        
        if [ "$BACKUP_ENABLED" == "true" ]; then
            BACKUP_RETENTION=$(echo "$instance" | jq -r '.settings.backupConfiguration.retentionSettings.retainedBackups // 0')
            
            if [ "$BACKUP_RETENTION" -lt 7 ]; then
                add_finding "9.4.1.1" "WARNING" "Short Backup Retention for SQL Instance $INSTANCE_NAME" \
                    "Cloud SQL instance $INSTANCE_NAME has backups enabled but retention period is only $BACKUP_RETENTION days." \
                    "Consider increasing backup retention to at least 30 days for databases that may contain cardholder data."
            else
                add_finding "9.4.1.1" "PASS" "Adequate Backup Retention for SQL Instance $INSTANCE_NAME" \
                    "Cloud SQL instance $INSTANCE_NAME has backups enabled with retention period of $BACKUP_RETENTION days." \
                    "Ensure backups are periodically tested for restoration capability."
            fi
        else
            add_finding "9.4.1.1" "FAIL" "Backups Not Enabled for SQL Instance $INSTANCE_NAME" \
                "Cloud SQL instance $INSTANCE_NAME does not have automated backups enabled." \
                "Enable automated backups for all SQL instances that may contain cardholder data."
        fi
        
        # Check network configuration
        PRIVATE_IP=$(echo "$instance" | jq -r '.ipAddresses[] | select(.type == "PRIVATE") | .ipAddress' 2>/dev/null)
        PUBLIC_IP=$(echo "$instance" | jq -r '.ipAddresses[] | select(.type == "PRIMARY") | .ipAddress' 2>/dev/null)
        
        if [ -z "$PRIVATE_IP" ] && [ -n "$PUBLIC_IP" ]; then
            add_finding "9.4.1" "FAIL" "Public IP Exposure for SQL Instance $INSTANCE_NAME" \
                "Cloud SQL instance $INSTANCE_NAME is exposed via public IP ($PUBLIC_IP) without private IP configuration." \
                "Configure the SQL instance to use private IP and remove public IP access. If public access is required, implement authorized networks restrictions."
        elif [ -n "$PRIVATE_IP" ] && [ -n "$PUBLIC_IP" ]; then
            add_finding "9.4.1" "WARNING" "Mixed IP Configuration for SQL Instance $INSTANCE_NAME" \
                "Cloud SQL instance $INSTANCE_NAME is configured with both private IP ($PRIVATE_IP) and public IP ($PUBLIC_IP)." \
                "Consider removing public IP access and using only private IP for better security."
        elif [ -n "$PRIVATE_IP" ] && [ -z "$PUBLIC_IP" ]; then
            add_finding "9.4.1" "PASS" "Private IP Only for SQL Instance $INSTANCE_NAME" \
                "Cloud SQL instance $INSTANCE_NAME is configured to use only private IP ($PRIVATE_IP)." \
                "Continue to monitor for any configuration changes."
        fi
    done
}

# Function to check Compute Engine instance configurations
check_compute_instances() {
    log "INFO" "Checking Compute Engine instance configurations..."
    
    # Get list of Compute Engine instances
    gcloud compute instances list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/instances.json" 2>/dev/null || {
        log "WARNING" "Failed to retrieve Compute Engine instances. Check permissions or if Compute API is enabled."
        add_finding "9.4.1" "WARNING" "Compute Engine Instance Inventory" \
            "Failed to retrieve Compute Engine instance inventory. This may indicate insufficient permissions or the Compute API is not enabled." \
            "Ensure the script is run with sufficient permissions and the Compute API is enabled."
        return
    }
    
    # Validate JSON output
    INSTANCES_JSON=$(validate_json "$TEMP_DIR/instances.json")
    
    # Check if we have any instances
    INSTANCE_COUNT=$(echo "$INSTANCES_JSON" | jq '. | length')
    
    if [ "$INSTANCE_COUNT" -eq 0 ]; then
        add_finding "9.4.1" "PASS" "No Compute Engine Instances Found" \
            "No Compute Engine instances were found in the project." \
            "No action needed. If you expect to have Compute instances, verify project ID and permissions."
        return
    fi
    
    # Check each instance's configuration
    echo "$INSTANCES_JSON" | jq -c '.[]' | while read -r instance; do
        INSTANCE_NAME=$(echo "$instance" | jq -r '.name')
        ZONE=$(echo "$instance" | jq -r '.zone' | sed 's|.*/||')
        
        # Check disk encryption
        gcloud compute disks list --filter="zone:$ZONE" --project="$PROJECT_ID" --format=json > "$TEMP_DIR/disks.json" 2>/dev/null
        
        DISKS_JSON=$(validate_json "$TEMP_DIR/disks.json")
        
        # Get disks attached to this instance
        INSTANCE_DISKS=$(echo "$DISKS_JSON" | jq -c ".[] | select(.users[] | contains(\"$INSTANCE_NAME\"))")
        
        if [ -z "$INSTANCE_DISKS" ]; then
            add_finding "9.4.1" "WARNING" "No Disks Found for Instance $INSTANCE_NAME" \
                "Could not identify disks attached to Compute Engine instance $INSTANCE_NAME." \
                "Verify disk configurations manually for this instance."
            continue
        fi
        
        # Check each disk's encryption
        echo "$INSTANCE_DISKS" | while read -r disk; do
            DISK_NAME=$(echo "$disk" | jq -r '.name')
            CMEK_KEY=$(echo "$disk" | jq -r '.diskEncryptionKey.kmsKeyName // "none"')
            
            if [ "$CMEK_KEY" == "none" ]; then
                add_finding "9.4.1" "WARNING" "Default Encryption for Disk $DISK_NAME" \
                    "Disk $DISK_NAME attached to instance $INSTANCE_NAME is using Google-managed encryption keys. For PCI DSS compliance, consider using customer-managed encryption keys (CMEK) for better control." \
                    "Configure customer-managed encryption keys (CMEK) for disks that may contain cardholder data."
            else
                add_finding "9.4.1" "PASS" "Custom Encryption for Disk $DISK_NAME" \
                    "Disk $DISK_NAME attached to instance $INSTANCE_NAME is using customer-managed encryption keys: $CMEK_KEY" \
                    "Maintain proper key management procedures for the customer-managed keys."
            fi
        done
        
        # Check instance metadata for serial port access
        SERIAL_PORT_ENABLED=$(echo "$instance" | jq -r '.metadata.items[] | select(.key == "serial-port-enable") | .value // "false"' 2>/dev/null)
        
        if [ "$SERIAL_PORT_ENABLED" == "true" ]; then
            add_finding "9.2.3" "WARNING" "Serial Port Access Enabled for $INSTANCE_NAME" \
                "Compute Engine instance $INSTANCE_NAME has serial port access enabled, which could provide an additional access vector." \
                "Disable serial port access unless specifically required, and if required, ensure it's properly secured and monitored."
        else
            add_finding "9.2.3" "PASS" "Serial Port Access Not Enabled for $INSTANCE_NAME" \
                "Compute Engine instance $INSTANCE_NAME does not have serial port access enabled." \
                "Continue to monitor for any configuration changes."
        fi
        
        # Check for public IP
        PUBLIC_IP=$(echo "$instance" | jq -r '.networkInterfaces[].accessConfigs[].natIP // "none"' 2>/dev/null)
        
        if [ "$PUBLIC_IP" != "none" ]; then
            add_finding "9.2.2" "WARNING" "Public IP Assigned to $INSTANCE_NAME" \
                "Compute Engine instance $INSTANCE_NAME has a public IP address ($PUBLIC_IP), which increases its exposure." \
                "Consider using only internal IP addresses for instances that process or store cardholder data. If public access is required, implement proper firewall rules."
        else
            add_finding "9.2.2" "PASS" "No Public IP for $INSTANCE_NAME" \
                "Compute Engine instance $INSTANCE_NAME does not have a public IP address." \
                "Continue to monitor for any configuration changes."
        fi
    done
}

# Function to check Cloud KMS configurations
check_cloud_kms() {
    log "INFO" "Checking Cloud KMS configurations..."
    
    # Check if KMS API is enabled
    gcloud services list --project="$PROJECT_ID" --filter="name:cloudkms.googleapis.com" --format=json > "$TEMP_DIR/kms_api.json" 2>/dev/null || {
        log "WARNING" "Failed to check if KMS API is enabled."
        add_finding "9.4.1" "WARNING" "Cloud KMS API Status" \
            "Failed to determine if Cloud KMS API is enabled. This may indicate insufficient permissions." \
            "Ensure the script is run with sufficient permissions to check API enablement status."
        return
    }
    
    KMS_API_JSON=$(validate_json "$TEMP_DIR/kms_api.json")
    KMS_API_ENABLED=$(echo "$KMS_API_JSON" | jq '. | length')
    
    if [ "$KMS_API_ENABLED" -eq 0 ]; then
        add_finding "9.4.1" "WARNING" "Cloud KMS API Not Enabled" \
            "Cloud KMS API is not enabled for this project. This may indicate that customer-managed encryption keys are not being used." \
            "Consider enabling Cloud KMS API and implementing customer-managed encryption keys for resources that store cardholder data."
        return
    fi
    
    # Get list of KMS keyrings
    gcloud kms keyrings list --location=global --project="$PROJECT_ID" --format=json > "$TEMP_DIR/keyrings_global.json" 2>/dev/null
    
    # Check multiple regions for keyrings
    for region in us-central1 us-east1 us-west1 europe-west1 asia-east1; do
        gcloud kms keyrings list --location="$region" --project="$PROJECT_ID" --format=json > "$TEMP_DIR/keyrings_$region.json" 2>/dev/null
    done
    
    # Combine all keyring files
    jq -s 'add' "$TEMP_DIR/keyrings_"*.json > "$TEMP_DIR/all_keyrings.json" 2>/dev/null || echo "[]" > "$TEMP_DIR/all_keyrings.json"
    
    # Validate JSON output
    KEYRINGS_JSON=$(validate_json "$TEMP_DIR/all_keyrings.json")
    
    # Check if we have any keyrings
    KEYRING_COUNT=$(echo "$KEYRINGS_JSON" | jq '. | length')
    
    if [ "$KEYRING_COUNT" -eq 0 ]; then
        add_finding "9.4.1" "WARNING" "No Cloud KMS Keyrings Found" \
            "No Cloud KMS keyrings were found in the project. This may indicate that customer-managed encryption keys are not being used." \
            "Consider implementing customer-managed encryption keys for resources that store cardholder data."
        return
    fi
    
    # Check each keyring for keys
    echo "$KEYRINGS_JSON" | jq -c '.[]' | while read -r keyring; do
        KEYRING_NAME=$(echo "$keyring" | jq -r '.name' | sed 's|.*/||')
        LOCATION=$(echo "$keyring" | jq -r '.name' | sed 's|.*/keyrings/.*||' | sed 's|.*/||')
        
        # Get keys in this keyring
        gcloud kms keys list --keyring="$KEYRING_NAME" --location="$LOCATION" --project="$PROJECT_ID" --format=json > "$TEMP_DIR/keys_$KEYRING_NAME.json" 2>/dev/null
        
        KEYS_JSON=$(validate_json "$TEMP_DIR/keys_$KEYRING_NAME.json")
        KEY_COUNT=$(echo "$KEYS_JSON" | jq '. | length')
        
        if [ "$KEY_COUNT" -eq 0 ]; then
            add_finding "9.4.1" "WARNING" "Empty Keyring $KEYRING_NAME" \
                "Cloud KMS keyring $KEYRING_NAME in location $LOCATION does not contain any keys." \
                "Consider removing empty keyrings or adding keys as needed for encryption."
            continue
        fi
        
        # Check each key's rotation period and state
        echo "$KEYS_JSON" | jq -c '.[]' | while read -r key; do
            KEY_NAME=$(echo "$key" | jq -r '.name' | sed 's|.*/||')
            ROTATION_PERIOD=$(echo "$key" | jq -r '.rotationPeriod // "none"')
            KEY_STATE=$(echo "$key" | jq -r '.primary.state // "UNKNOWN"')
            
            if [ "$ROTATION_PERIOD" == "none" ]; then
                add_finding "9.4.1" "WARNING" "No Rotation Period for Key $KEY_NAME" \
                    "Cloud KMS key $KEY_NAME in keyring $KEYRING_NAME does not have an automatic rotation period configured." \
                    "Configure automatic key rotation for all encryption keys used to protect cardholder data."
            else
                # Convert rotation period to days (assuming format like "7776000s")
                ROTATION_DAYS=$((${ROTATION_PERIOD%s} / 86400))
                
                if [ "$ROTATION_DAYS" -gt 365 ]; then
                    add_finding "9.4.1" "WARNING" "Long Rotation Period for Key $KEY_NAME" \
                        "Cloud KMS key $KEY_NAME in keyring $KEYRING_NAME has a rotation period of $ROTATION_DAYS days, which exceeds 1 year." \
                        "Consider reducing the key rotation period to 365 days or less for keys used to protect cardholder data."
                else
                    add_finding "9.4.1" "PASS" "Proper Rotation Period for Key $KEY_NAME" \
                        "Cloud KMS key $KEY_NAME in keyring $KEYRING_NAME has a rotation period of $ROTATION_DAYS days." \
                        "Continue to monitor for any configuration changes."
                fi
            fi
            
            if [ "$KEY_STATE" != "ENABLED" ]; then
                add_finding "9.4.1" "WARNING" "Key $KEY_NAME Not Enabled" \
                    "Cloud KMS key $KEY_NAME in keyring $KEYRING_NAME is in state $KEY_STATE, not ENABLED." \
                    "Verify if this key is intended to be in this state. If it should be active, enable the key."
            else
                add_finding "9.4.1" "PASS" "Key $KEY_NAME is Enabled" \
                    "Cloud KMS key $KEY_NAME in keyring $KEYRING_NAME is properly enabled." \
                    "Continue to monitor for any state changes."
            fi
        done
    done
}

# Function to check logging and monitoring configurations
check_logging() {
    log "INFO" "Checking logging and monitoring configurations..."
    
    # Check if Cloud Audit Logging is properly configured
    gcloud logging sinks list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/logging_sinks.json" 2>/dev/null || {
        log "WARNING" "Failed to retrieve logging sinks. Check permissions."
        add_finding "9.2.1.1" "WARNING" "Cloud Logging Configuration" \
            "Failed to retrieve Cloud Logging sink configurations. This may indicate insufficient permissions." \
            "Ensure the script is run with sufficient permissions to check logging configurations."
        return
    }
    
    SINKS_JSON=$(validate_json "$TEMP_DIR/logging_sinks.json")
    SINK_COUNT=$(echo "$SINKS_JSON" | jq '. | length')
    
    if [ "$SINK_COUNT" -eq 0 ]; then
        add_finding "9.2.1.1" "WARNING" "No Cloud Logging Sinks" \
            "No Cloud Logging sinks were found in the project. This may indicate that logs are not being exported for long-term retention." \
            "Consider configuring logging sinks to export audit logs to a secure storage location for at least 90 days."
    else
        # Check each sink for audit log exports
        AUDIT_SINK_FOUND=false
        
        echo "$SINKS_JSON" | jq -c '.[]' | while read -r sink; do
            SINK_NAME=$(echo "$sink" | jq -r '.name')
            SINK_FILTER=$(echo "$sink" | jq -r '.filter')
            SINK_DESTINATION=$(echo "$sink" | jq -r '.destination')
            
            # Check if sink includes audit logs
            if echo "$SINK_FILTER" | grep -q "logName.*cloudaudit.googleapis.com"; then
                AUDIT_SINK_FOUND=true
                add_finding "9.2.1.1" "PASS" "Audit Log Export Configured" \
                    "Cloud Logging sink $SINK_NAME is configured to export audit logs to $SINK_DESTINATION." \
                    "Verify that the destination has appropriate retention policies and access controls."
            fi
        done
        
        if [ "$AUDIT_SINK_FOUND" = false ]; then
            add_finding "9.2.1.1" "WARNING" "No Audit Log Export" \
                "No Cloud Logging sinks were found that specifically export audit logs." \
                "Configure a logging sink to export audit logs to a secure storage location for at least 90 days."
        fi
    fi
    
    # Check Data Access audit logs
    gcloud logging read "logName:cloudaudit.googleapis.com/data_access" --project="$PROJECT_ID" --limit=1 --format=json > "$TEMP_DIR/data_access_logs.json" 2>/dev/null || {
        log "WARNING" "Failed to check Data Access audit logs. This may be due to permissions or no logs exist."
    }
    
    DATA_ACCESS_JSON=$(validate_json "$TEMP_DIR/data_access_logs.json" "[]")
    DATA_ACCESS_COUNT=$(echo "$DATA_ACCESS_JSON" | jq '. | length')
    
    if [ "$DATA_ACCESS_COUNT" -eq 0 ]; then
        add_finding "9.2.1.1" "WARNING" "Data Access Audit Logging" \
            "No Data Access audit logs were found. This may indicate that Data Access audit logging is not enabled or no relevant activity has occurred." \
            "Enable Data Access audit logging for all services that may process or store cardholder data."
    else
        add_finding "9.2.1.1" "PASS" "Data Access Audit Logging" \
            "Data Access audit logs were found, indicating that Data Access audit logging is enabled for some services." \
            "Verify that Data Access audit logging is enabled for all services that process or store cardholder data."
    fi
}

# Function to check organization policies
check_org_policies() {
    log "INFO" "Checking organization policies..."
    
    # List organization policies
    gcloud resource-manager org-policies list --project="$PROJECT_ID" --format=json > "$TEMP_DIR/org_policies.json" 2>/dev/null || {
        log "WARNING" "Failed to retrieve organization policies. Check permissions."
        add_finding "9.4.1" "WARNING" "Organization Policies" \
            "Failed to retrieve organization policies. This may indicate insufficient permissions." \
            "Ensure the script is run with sufficient permissions to check organization policies."
        return
    }
    
    ORG_POLICIES_JSON=$(validate_json "$TEMP_DIR/org_policies.json")
    
    # Check for specific policies related to data protection
    DOMAIN_RESTRICTED_SHARING=$(echo "$ORG_POLICIES_JSON" | jq -r '.[] | select(.constraint == "constraints/iam.allowedPolicyMemberDomains") | .constraint' 2>/dev/null)
    UNIFORM_BUCKET_ACCESS=$(echo "$ORG_POLICIES_JSON" | jq -r '.[] | select(.constraint == "constraints/storage.uniformBucketLevelAccess") | .constraint' 2>/dev/null)
    PUBLIC_ACCESS_PREVENTION=$(echo "$ORG_POLICIES_JSON" | jq -r '.[] | select(.constraint == "constraints/storage.publicAccessPrevention") | .constraint' 2>/dev/null)
    
    if [ -n "$DOMAIN_RESTRICTED_SHARING" ]; then
        add_finding "9.4.1" "PASS" "Domain Restricted Sharing Policy" \
            "The organization policy 'constraints/iam.allowedPolicyMemberDomains' is configured, which restricts resource sharing to specific domains." \
            "Verify that the policy is configured to allow only trusted domains."
    else
        add_finding "9.4.1" "WARNING" "Domain Restricted Sharing Policy" \
            "The organization policy 'constraints/iam.allowedPolicyMemberDomains' is not configured, which may allow resource sharing with any domain." \
            "Consider configuring this policy to restrict resource sharing to trusted domains only."
    fi
    
    if [ -n "$UNIFORM_BUCKET_ACCESS" ]; then
        add_finding "9.4.1" "PASS" "Uniform Bucket-Level Access Policy" \
            "The organization policy 'constraints/storage.uniformBucketLevelAccess' is configured, which enforces the use of uniform bucket-level access for Cloud Storage." \
            "Verify that the policy is configured to enforce uniform bucket-level access."
    else
        add_finding "9.4.1" "WARNING" "Uniform Bucket-Level Access Policy" \
            "The organization policy 'constraints/storage.uniformBucketLevelAccess' is not configured, which may allow fine-grained access control for Cloud Storage." \
            "Consider configuring this policy to enforce uniform bucket-level access for better security."
    fi
    
    if [ -n "$PUBLIC_ACCESS_PREVENTION" ]; then
        add_finding "9.4.1" "PASS" "Public Access Prevention Policy" \
            "The organization policy 'constraints/storage.publicAccessPrevention' is configured, which helps prevent public access to Cloud Storage buckets." \
            "Verify that the policy is configured to enforce public access prevention."
    else
        add_finding "9.4.1" "WARNING" "Public Access Prevention Policy" \
            "The organization policy 'constraints/storage.publicAccessPrevention' is not configured, which may allow public access to Cloud Storage buckets." \
            "Consider configuring this policy to enforce public access prevention for all buckets."
    fi
}

# Function to check VPC Service Controls
check_vpc_service_controls() {
    log "INFO" "Checking VPC Service Controls..."
    
    # Check if Access Context Manager API is enabled
    gcloud services list --project="$PROJECT_ID" --filter="name:accesscontextmanager.googleapis.com" --format=json > "$TEMP_DIR/acm_api.json" 2>/dev/null || {
        log "WARNING" "Failed to check if Access Context Manager API is enabled."
        return
    }
    
    ACM_API_JSON=$(validate_json "$TEMP_DIR/acm_api.json")
    ACM_API_ENABLED=$(echo "$ACM_API_JSON" | jq '. | length')
    
    if [ "$ACM_API_ENABLED" -eq 0 ]; then
        add_finding "9.4.1" "WARNING" "VPC Service Controls" \
            "Access Context Manager API is not enabled, which indicates that VPC Service Controls are not being used." \
            "Consider enabling VPC Service Controls to create security perimeters around sensitive resources."
        return
    fi
    
    # Try to list service perimeters
    gcloud access-context-manager perimeters list --format=json > "$TEMP_DIR/perimeters.json" 2>/dev/null || {
        log "WARNING" "Failed to retrieve VPC Service Controls perimeters. This may be due to permissions or no perimeters exist."
        add_finding "9.4.1" "WARNING" "VPC Service Controls" \
            "Failed to retrieve VPC Service Controls perimeters. This may indicate insufficient permissions or no perimeters exist." \
            "Ensure the script is run with sufficient permissions to check VPC Service Controls configurations."
        return
    }
    
    PERIMETERS_JSON=$(validate_json "$TEMP_DIR/perimeters.json")
    PERIMETER_COUNT=$(echo "$PERIMETERS_JSON" | jq '. | length')
    
    if [ "$PERIMETER_COUNT" -eq 0 ]; then
        add_finding "9.4.1" "WARNING" "VPC Service Controls" \
            "No VPC Service Controls perimeters were found. This may indicate that sensitive resources are not protected by service perimeters." \
            "Consider implementing VPC Service Controls to create security perimeters around resources that process or store cardholder data."
    else
        # Check if the current project is in any perimeter
        PROJECT_IN_PERIMETER=false
        PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)" 2>/dev/null)
        
        if [ -n "$PROJECT_NUMBER" ]; then
            echo "$PERIMETERS_JSON" | jq -c '.[]' | while read -r perimeter; do
                PERIMETER_NAME=$(echo "$perimeter" | jq -r '.name' | sed 's|.*/||')
                PROJECTS=$(echo "$perimeter" | jq -r '.status.resources[]' 2>/dev/null | grep -c "projects/$PROJECT_NUMBER" || echo "0")
                
                if [ "$PROJECTS" -gt 0 ]; then
                    PROJECT_IN_PERIMETER=true
                    RESTRICTED_SERVICES=$(echo "$perimeter" | jq -r '.status.restrictedServices[]' 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
                    
                    add_finding "9.4.1" "PASS" "Project Protected by VPC Service Controls" \
                        "Project $PROJECT_ID is protected by VPC Service Controls perimeter $PERIMETER_NAME. Restricted services: $RESTRICTED_SERVICES" \
                        "Verify that all services that process or store cardholder data are included in the restricted services list."
                fi
            done
        fi
        
        if [ "$PROJECT_IN_PERIMETER" = false ]; then
            add_finding "9.4.1" "WARNING" "Project Not in VPC Service Controls Perimeter" \
                "Project $PROJECT_ID is not included in any VPC Service Controls perimeter." \
                "Consider adding this project to a VPC Service Controls perimeter if it processes or stores cardholder data."
        fi
    fi
}

# Main function
main() {
    # Parse command line arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --project-id=*)
                PROJECT_ID="${1#*=}"
                ;;
            --output=*)
                REPORT_FILE="${1#*=}"
                ;;
            --help)
                usage
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
        shift
    done
    
    # Check if project ID is provided
    if [ -z "$PROJECT_ID" ]; then
        log "ERROR" "Project ID is required. Use --project-id=PROJECT_ID"
        usage
    fi
    
    # Check gcloud installation and authentication
    check_gcloud
    
    # Initialize HTML report
    initialize_report
    
    # Run assessment checks
    check_storage_buckets
    check_cloud_sql
    check_compute_instances
    check_cloud_kms
    check_logging
    check_org_policies
    check_vpc_service_controls
    
    # Finalize HTML report
    finalize_report
    
    # Clean up temporary files
    rm -rf "$TEMP_DIR"
    
    log "INFO" "Assessment completed successfully."
    log "INFO" "Total checks: $TOTAL_CHECKS (Passed: $PASSED_CHECKS, Warnings: $WARNING_CHECKS, Failed: $FAILED_CHECKS)"
    log "INFO" "Report generated: $REPORT_FILE"
}

# Parse command line arguments and run main function
main "$@"
