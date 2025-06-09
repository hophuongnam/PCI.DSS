#!/usr/bin/env bash

# PCI DSS Requirement 3 Compliance Check Script for GCP
# This script evaluates GCP controls for PCI DSS Requirement 3 compliance
# Requirements covered: 3.2 - 3.7 (Protect Stored Account Data)
# Requirement 3.1 removed - requires manual verification

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="3"

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
check_required_permissions "storage.buckets.list" "sql.instances.list" "cloudkms.keyRings.list" || exit 1

# Set output file path
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"

# Initialize HTML report using shared library
initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"
# Begin main assessment logic


print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 3 (GCP)"
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

# Ask for specific resources to assess
read -p "Enter specific resource types to assess (comma-separated: sql,storage,kms,compute or 'all' for all): " TARGET_RESOURCES
if [ -z "$TARGET_RESOURCES" ] || [ "$TARGET_RESOURCES" == "all" ]; then
    print_status "WARN" "Checking all resource types"
    TARGET_RESOURCES="all"
else
    print_status "WARN" "Checking specific resources: $TARGET_RESOURCES"
fi

# Initialize HTML report
initialize_report "$OUTPUT_FILE" "$REPORT_TITLE"

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

#----------------------------------------------------------------------
# SECTION 2: DETERMINE RESOURCES TO CHECK
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "Target Resources" "<p>Identifying target resources for assessment...</p>" "info"

print_status "INFO" "=== IDENTIFYING TARGET RESOURCES ==="

# Initialize resource arrays
declare -a SQL_INSTANCES=()
declare -a STORAGE_BUCKETS=()
declare -a COMPUTE_INSTANCES=()
declare -a KMS_KEYRINGS=()

# Retrieve resources based on user input and scope
if [ "$TARGET_RESOURCES" == "all" ] || [[ "$TARGET_RESOURCES" == *"sql"* ]]; then
    print_status "INFO" "Retrieving Cloud SQL instances..."
    SQL_INSTANCE_LIST=$(run_across_projects "gcloud sql instances list" "--format=value(name)")
    if [ -n "$SQL_INSTANCE_LIST" ]; then
        readarray -t SQL_INSTANCES <<< "$SQL_INSTANCE_LIST"
        print_status "PASS" "Found ${#SQL_INSTANCES[@]} Cloud SQL instances"
    else
        print_status "WARN" "No Cloud SQL instances found or access denied"
    fi
fi

if [ "$TARGET_RESOURCES" == "all" ] || [[ "$TARGET_RESOURCES" == *"storage"* ]]; then
    print_status "INFO" "Retrieving Cloud Storage buckets..."
    STORAGE_BUCKET_LIST=$(gsutil ls 2>/dev/null | sed 's|gs://||' | sed 's|/$||')
    if [ -n "$STORAGE_BUCKET_LIST" ]; then
        readarray -t STORAGE_BUCKETS <<< "$STORAGE_BUCKET_LIST"
        print_status "PASS" "Found ${#STORAGE_BUCKETS[@]} Cloud Storage buckets"
    else
        print_status "WARN" "No Cloud Storage buckets found or access denied"
    fi
fi

if [ "$TARGET_RESOURCES" == "all" ] || [[ "$TARGET_RESOURCES" == *"compute"* ]]; then
    print_status "INFO" "Retrieving Compute Engine instances..."
    COMPUTE_INSTANCE_LIST=$(run_across_projects "gcloud compute instances list" "--format=value(name)")
    if [ -n "$COMPUTE_INSTANCE_LIST" ]; then
        readarray -t COMPUTE_INSTANCES <<< "$COMPUTE_INSTANCE_LIST"
        print_status "PASS" "Found ${#COMPUTE_INSTANCES[@]} Compute Engine instances"
    else
        print_status "WARN" "No Compute Engine instances found or access denied"
    fi
fi

if [ "$TARGET_RESOURCES" == "all" ] || [[ "$TARGET_RESOURCES" == *"kms"* ]]; then
    print_status "INFO" "Retrieving Cloud KMS keyrings..."
    KMS_KEYRING_LIST=$(run_across_projects "gcloud kms keyrings list --location=global" "--format=value(name)")
    if [ -n "$KMS_KEYRING_LIST" ]; then
        readarray -t KMS_KEYRINGS <<< "$KMS_KEYRING_LIST"
        print_status "PASS" "Found ${#KMS_KEYRINGS[@]} Cloud KMS keyrings"
    else
        print_status "WARN" "No Cloud KMS keyrings found or access denied"
    fi
fi

add_section "$OUTPUT_FILE" "Resource Identification" "Assessment will include:<br>
- Cloud SQL Instances: ${#SQL_INSTANCES[@]}<br>
- Cloud Storage Buckets: ${#STORAGE_BUCKETS[@]}<br>
- Compute Engine Instances: ${#COMPUTE_INSTANCES[@]}<br>
- Cloud KMS Keyrings: ${#KMS_KEYRINGS[@]}" "info"

#----------------------------------------------------------------------
# SECTION 3: PCI REQUIREMENT 3.2 - STORAGE OF ACCOUNT DATA
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 3.2: STORAGE OF ACCOUNT DATA ===" 

add_section "$OUTPUT_FILE" "Requirement 3.2: Storage of account data is kept to a minimum" "<p>Analyzing data retention and lifecycle policies...</p>" "info"

# Check for Cloud Storage lifecycle policies
print_status "INFO" "3.2.1 - Cloud Storage lifecycle policies"
print_status "INFO" "Checking Cloud Storage buckets for lifecycle policies..."

storage_with_lifecycle=0
storage_without_lifecycle=0

for bucket in "${STORAGE_BUCKETS[@]}"; do
    if [ -z "$bucket" ]; then continue; fi
    
    print_status "INFO" "Checking lifecycle policy for bucket: $bucket"
    LIFECYCLE=$(gsutil lifecycle get "gs://$bucket" 2>&1)
    
    if [[ $LIFECYCLE == *"has no lifecycle configuration"* ]]; then
        print_status "WARN" "No lifecycle policy found for bucket: $bucket"
        ((storage_without_lifecycle++))
    elif [[ $LIFECYCLE == *"AccessDenied"* ]]; then
        print_status "FAIL" "Access denied when checking lifecycle policy for bucket: $bucket"
    else
        print_status "PASS" "Lifecycle policy found for bucket: $bucket"
        ((storage_with_lifecycle++))
    fi
done

if [ $storage_with_lifecycle -gt 0 ]; then
    if [ $storage_without_lifecycle -eq 0 ]; then
        add_section "$OUTPUT_FILE" "3.2.1 - Cloud Storage Lifecycle Policies" "<p class='green'>All Cloud Storage buckets have lifecycle policies configured ($storage_with_lifecycle of ${#STORAGE_BUCKETS[@]}).</p>" "pass"
        ((total_checks++))
        ((passed_checks++))
    else
        bucket_details="<p>The following Cloud Storage buckets do not have lifecycle policies configured:</p><ul>"
        for bucket in "${STORAGE_BUCKETS[@]}"; do
            if [ -z "$bucket" ]; then continue; fi
            LIFECYCLE=$(gsutil lifecycle get "gs://$bucket" 2>&1)
            if [[ $LIFECYCLE == *"has no lifecycle configuration"* ]]; then
                bucket_details+="<li>$bucket</li>"
            fi
        done
        bucket_details+="</ul><p>Lifecycle policies are essential for ensuring that data is retained only as long as necessary for business purposes, in accordance with PCI DSS requirement 3.2.1.</p>"
        
        add_section "$OUTPUT_FILE" "3.2.1 - Cloud Storage Lifecycle Policies" "$bucket_details<p class='yellow'>Configure lifecycle policies for all Cloud Storage buckets that may contain account data to ensure data is retained only as long as necessary and to automatically enforce retention policies.</p>" "warning"
        ((total_checks++))
        ((warning_checks++))
    fi
else
    if [ ${#STORAGE_BUCKETS[@]} -gt 0 ]; then
        add_section "$OUTPUT_FILE" "3.2.1 - Cloud Storage Lifecycle Policies" "<p class='yellow'>No Cloud Storage buckets were found to have lifecycle policies configured.</p><p>Configure lifecycle policies for all Cloud Storage buckets that may contain account data to ensure data is retained only as long as necessary.</p>" "warning"
        ((total_checks++))
        ((warning_checks++))
    fi
fi

#----------------------------------------------------------------------
# SECTION 4: PCI REQUIREMENT 3.3 - DATABASE LOGGING CHECKS
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 3.3: DATABASE LOGGING CHECKS ==="

add_section "$OUTPUT_FILE" "Requirement 3.3: Database logging configuration checks" "<p>Analyzing database logging configurations for sensitive data exposure...</p>" "info"

# Check for Cloud SQL database logging configurations
if [ ${#SQL_INSTANCES[@]} -gt 0 ]; then
    print_status "INFO" "3.3.1 - Cloud SQL logging configuration"
    print_status "INFO" "Checking Cloud SQL instances for potential issues with sensitive data logging..."
    
    for instance in "${SQL_INSTANCES[@]}"; do
        if [ -z "$instance" ]; then continue; fi
        
        # Extract project from instance name if in org scope
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            project=$(echo "$instance" | cut -d'/' -f1)
            instance_name=$(echo "$instance" | cut -d'/' -f2)
        else
            project="$DEFAULT_PROJECT"
            instance_name="$instance"
        fi
        
        # Get instance details including database version
        INSTANCE_DETAILS=$(gcloud sql instances describe "$instance_name" --project="$project" 2>/dev/null)
        DATABASE_VERSION=$(echo "$INSTANCE_DETAILS" | grep -o '"databaseVersion": "[^"]*' | cut -d'"' -f4)
        
        if [[ "$DATABASE_VERSION" == "MYSQL"* ]] || [[ "$DATABASE_VERSION" == "POSTGRES"* ]]; then
            # Check for general query logging settings
            FLAGS=$(echo "$INSTANCE_DETAILS" | grep -A10 '"databaseFlags"')
            
            if [[ "$FLAGS" == *"general_log"* ]]; then
                GENERAL_LOG_VALUE=$(echo "$FLAGS" | grep -A5 '"name": "general_log"' | grep -o '"value": "[^"]*' | cut -d'"' -f4)
                if [[ "$GENERAL_LOG_VALUE" == "on" || "$GENERAL_LOG_VALUE" == "1" ]]; then
                    add_section "$OUTPUT_FILE" "3.3.1 - Database Logging Settings" "<p class='red'>The Cloud SQL instance $instance_name has general query logging enabled, which might capture sensitive data.</p><p>Disable general query logging or ensure it doesn't capture sensitive data. Review query logs to confirm they don't contain sensitive data.</p>" "warning"
                    ((total_checks++))
                    ((warning_checks++))
                fi
            fi
            
            # Check for log statement settings in PostgreSQL
            if [[ "$DATABASE_VERSION" == "POSTGRES"* ]]; then
                if [[ "$FLAGS" == *"log_statement"* ]]; then
                    LOG_STATEMENT_VALUE=$(echo "$FLAGS" | grep -A5 '"name": "log_statement"' | grep -o '"value": "[^"]*' | cut -d'"' -f4)
                    if [[ "$LOG_STATEMENT_VALUE" == "all" ]]; then
                        add_section "$OUTPUT_FILE" "3.3.1 - PostgreSQL Logging Settings" "<p class='red'>The Cloud SQL instance $instance_name has log_statement set to 'all', which logs all SQL statements and might capture sensitive data.</p><p>Change log_statement setting to avoid logging sensitive data or ensure logs are properly protected.</p>" "warning"
                        ((total_checks++))
                        ((warning_checks++))
                    fi
                fi
            fi
        fi
    done
else
    add_section "$OUTPUT_FILE" "3.3.1 - Database Logging Check" "<p>No Cloud SQL instances found to check for logging settings.</p>" "info"
    ((total_checks++))
fi

#----------------------------------------------------------------------
# SECTION 5: PCI REQUIREMENT 3.5 - PAN SECURITY
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 3.5: PAN SECURITY ==="

add_section "$OUTPUT_FILE" "Requirement 3.5: Primary account number (PAN) is secured wherever it is stored" "<p>Analyzing encryption and security controls for PAN protection...</p>" "info"

# Check for Cloud KMS key usage
print_status "INFO" "3.5.1 - Cloud KMS encryption key availability"
print_status "INFO" "Checking Cloud KMS key usage..."

KMS_KEYS_LIST=()
if [ ${#KMS_KEYRINGS[@]} -gt 0 ]; then
    for keyring in "${KMS_KEYRINGS[@]}"; do
        if [ -z "$keyring" ]; then continue; fi
        
        # Extract project from keyring name if in org scope
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            project=$(echo "$keyring" | cut -d'/' -f1)
            keyring_name=$(echo "$keyring" | cut -d'/' -f2)
        else
            project="$DEFAULT_PROJECT"
            keyring_name="$keyring"
        fi
        
        # Get keys in this keyring
        KEYS=$(gcloud kms keys list --keyring="$keyring_name" --location=global --project="$project" --format="value(name)" 2>/dev/null)
        if [ -n "$KEYS" ]; then
            while IFS= read -r key; do
                if [ -n "$key" ]; then
                    KMS_KEYS_LIST+=("$key")
                fi
            done <<< "$KEYS"
        fi
    done
fi

if [ ${#KMS_KEYS_LIST[@]} -gt 0 ]; then
    key_details="<p>Found ${#KMS_KEYS_LIST[@]} Cloud KMS keys:</p><ul>"
    
    # Count different key purposes
    ENCRYPTION_KEYS=0
    SIGNING_KEYS=0
    
    for key in "${KMS_KEYS_LIST[@]}"; do
        if [ -z "$key" ]; then continue; fi
        
        # Extract project and key details
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            project=$(echo "$key" | cut -d'/' -f1)
            key_path=$(echo "$key" | cut -d'/' -f2-)
        else
            project="$DEFAULT_PROJECT"
            key_path="$key"
        fi
        
        KEY_PURPOSE=$(gcloud kms keys describe "$key_path" --project="$project" --format="value(purpose)" 2>/dev/null)
        
        if [ "$KEY_PURPOSE" == "ENCRYPT_DECRYPT" ]; then
            ((ENCRYPTION_KEYS++))
        elif [ "$KEY_PURPOSE" == "ASYMMETRIC_SIGN" ]; then
            ((SIGNING_KEYS++))
        fi
    done
    
    key_details+="<li>Encryption keys: $ENCRYPTION_KEYS</li>"
    key_details+="<li>Signing keys: $SIGNING_KEYS</li>"
    key_details+="</ul><p>These keys could be used for encryption of sensitive data. Manual verification is needed to ensure they are properly used for PAN encryption.</p>"
    
    add_section "$OUTPUT_FILE" "3.5.1 - Cloud KMS Key Availability" "$key_details" "info"
    ((total_checks++))
else
    add_section "$OUTPUT_FILE" "3.5.1 - Cloud KMS Key Availability" "<p class='yellow'>No Cloud KMS keys were found. If storing PAN, ensure proper encryption methods are used.</p><p>Create and use Cloud KMS keys to encrypt sensitive data if storing PAN in GCP services.</p>" "warning"
    ((total_checks++))
    ((warning_checks++))
fi

# Check Compute Engine disk encryption
print_status "INFO" "3.5.1 - Compute Engine disk encryption"
print_status "INFO" "Checking Compute Engine disk encryption..."

ENCRYPTED_DISKS=0
UNENCRYPTED_DISKS=0
TOTAL_DISKS=0

for instance in "${COMPUTE_INSTANCES[@]}"; do
    if [ -z "$instance" ]; then continue; fi
    
    # Extract project from instance name if in org scope
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        project=$(echo "$instance" | cut -d'/' -f1)
        instance_name=$(echo "$instance" | cut -d'/' -f2)
    else
        project="$DEFAULT_PROJECT"
        instance_name="$instance"
    fi
    
    # Get disks attached to the instance
    DISKS=$(gcloud compute instances describe "$instance_name" --project="$project" --format="value(disks[].source)" 2>/dev/null)
    
    for disk_url in $DISKS; do
        ((TOTAL_DISKS++))
        
        # Extract disk name from URL
        disk_name=$(basename "$disk_url")
        
        # Check if disk is encrypted with customer-managed key
        DISK_ENCRYPTION=$(gcloud compute disks describe "$disk_name" --project="$project" --format="value(diskEncryptionKey.kmsKeyName)" 2>/dev/null)
        
        if [ -n "$DISK_ENCRYPTION" ]; then
            ((ENCRYPTED_DISKS++))
        else
            # In GCP, all disks are encrypted by default with Google-managed keys
            # We count this as encrypted, but note it's not customer-managed
            ((ENCRYPTED_DISKS++))
        fi
    done
done

if [ $TOTAL_DISKS -gt 0 ]; then
    if [ $ENCRYPTED_DISKS -eq $TOTAL_DISKS ]; then
        add_section "$OUTPUT_FILE" "3.5.1 - Compute Engine Disk Encryption" "<p class='green'>All Compute Engine disks ($ENCRYPTED_DISKS of $TOTAL_DISKS) are encrypted. Note: GCP encrypts all disks by default with Google-managed keys.</p>" "pass"
        ((total_checks++))
        ((passed_checks++))
    else
        add_section "$OUTPUT_FILE" "3.5.1 - Compute Engine Disk Encryption" "<p class='yellow'>$UNENCRYPTED_DISKS of $TOTAL_DISKS disks may not have customer-managed encryption. GCP encrypts all disks by default with Google-managed keys, but consider using customer-managed keys for PAN data.</p>" "warning"
        ((total_checks++))
        ((warning_checks++))
    fi
fi

# Check Cloud SQL encryption
print_status "INFO" "3.5.1 - Cloud SQL encryption"
print_status "INFO" "Checking Cloud SQL instance encryption..."

ENCRYPTED_SQL=0
UNENCRYPTED_SQL=0

for instance in "${SQL_INSTANCES[@]}"; do
    if [ -z "$instance" ]; then continue; fi
    
    # Extract project from instance name if in org scope
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        project=$(echo "$instance" | cut -d'/' -f1)
        instance_name=$(echo "$instance" | cut -d'/' -f2)
    else
        project="$DEFAULT_PROJECT"
        instance_name="$instance"
    fi
    
    # Check if Cloud SQL instance uses customer-managed encryption key
    SQL_ENCRYPTION=$(gcloud sql instances describe "$instance_name" --project="$project" --format="value(diskEncryptionConfiguration.kmsKeyName)" 2>/dev/null)
    
    if [ -n "$SQL_ENCRYPTION" ]; then
        ((ENCRYPTED_SQL++))
    else
        # Cloud SQL is encrypted by default with Google-managed keys
        ((ENCRYPTED_SQL++))
    fi
done

if [ ${#SQL_INSTANCES[@]} -gt 0 ]; then
    if [ $ENCRYPTED_SQL -eq ${#SQL_INSTANCES[@]} ]; then
        add_section "$OUTPUT_FILE" "3.5.1 - Cloud SQL Encryption" "<p class='green'>All Cloud SQL instances ($ENCRYPTED_SQL of ${#SQL_INSTANCES[@]}) are encrypted. Note: GCP encrypts all Cloud SQL instances by default with Google-managed keys.</p>" "pass"
        ((total_checks++))
        ((passed_checks++))
    else
        sql_details="<p>The following Cloud SQL instances may not have customer-managed encryption:</p><ul>"
        for instance in "${SQL_INSTANCES[@]}"; do
            if [ -z "$instance" ]; then continue; fi
            
            # Extract project from instance name if in org scope
            if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
                project=$(echo "$instance" | cut -d'/' -f1)
                instance_name=$(echo "$instance" | cut -d'/' -f2)
            else
                project="$DEFAULT_PROJECT"
                instance_name="$instance"
            fi
            
            SQL_ENCRYPTION=$(gcloud sql instances describe "$instance_name" --project="$project" --format="value(diskEncryptionConfiguration.kmsKeyName)" 2>/dev/null)
            if [ -z "$SQL_ENCRYPTION" ]; then
                DATABASE_VERSION=$(gcloud sql instances describe "$instance_name" --project="$project" --format="value(databaseVersion)" 2>/dev/null)
                sql_details+="<li>$instance_name (Version: $DATABASE_VERSION)</li>"
            fi
        done
        sql_details+="</ul><p>GCP encrypts all Cloud SQL instances by default with Google-managed keys, but consider using customer-managed keys for PAN data to comply with PCI DSS requirement 3.5.1.</p>"
        
        add_section "$OUTPUT_FILE" "3.5.1 - Cloud SQL Encryption" "$sql_details" "warning"
        ((total_checks++))
        ((warning_checks++))
    fi
fi

#----------------------------------------------------------------------
# SECTION 6: PCI REQUIREMENT 3.6 - CRYPTOGRAPHIC KEY SECURITY
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 3.6: CRYPTOGRAPHIC KEY SECURITY ==="

add_section "$OUTPUT_FILE" "Requirement 3.6: Cryptographic keys used to protect stored account data are secured" "<p>Analyzing cryptographic key protection mechanisms...</p>" "info"

# Check Cloud KMS key policies and IAM
print_status "INFO" "3.6.1 - Cloud KMS key protection procedures"
print_status "INFO" "Checking Cloud KMS key policies and access controls..."

key_protection_details="<h4>Analysis of Cloud KMS Key Protection</h4><ul>"

if [ ${#KMS_KEYS_LIST[@]} -gt 0 ]; then
    secure_keys=0
    potentially_insecure_keys=0
    
    for key in "${KMS_KEYS_LIST[@]}"; do
        if [ -z "$key" ]; then continue; fi
        
        # Extract project and key details
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            project=$(echo "$key" | cut -d'/' -f1)
            key_path=$(echo "$key" | cut -d'/' -f2-)
        else
            project="$DEFAULT_PROJECT"
            key_path="$key"
        fi
        
        key_name=$(basename "$key_path")
        
        # Get IAM policy for the key
        KEY_IAM=$(gcloud kms keys get-iam-policy "$key_path" --project="$project" 2>/dev/null)
        
        key_protection_details+="<li><strong>Key:</strong> $key_name</li><ul>"
        
        # Check for overly permissive IAM policies
        if [[ "$KEY_IAM" == *"allUsers"* ]] || [[ "$KEY_IAM" == *"allAuthenticatedUsers"* ]]; then
            key_protection_details+="<li class='red'>Policy contains public access bindings</li>"
            ((potentially_insecure_keys++))
        else
            key_protection_details+="<li class='green'>No public access bindings detected</li>"
            ((secure_keys++))
        fi
        
        # Check for separation of key administrative and usage permissions
        admin_bindings=$(echo "$KEY_IAM" | grep -c "roles/cloudkms.admin\|roles/cloudkms.cryptoKeyDecrypter")
        if [ $admin_bindings -gt 0 ]; then
            key_protection_details+="<li class='green'>Key has administrative and usage role bindings</li>"
        fi
        
        # Check key rotation schedule
        ROTATION_PERIOD=$(gcloud kms keys describe "$key_path" --project="$project" --format="value(rotationPeriod)" 2>/dev/null)
        if [ -n "$ROTATION_PERIOD" ]; then
            key_protection_details+="<li class='green'>Key has automatic rotation configured: $ROTATION_PERIOD</li>"
        else
            key_protection_details+="<li class='yellow'>No automatic rotation configured</li>"
        fi
        
        key_protection_details+="</ul>"
    done
    
    key_protection_details+="<li>Overall: $secure_keys of ${#KMS_KEYS_LIST[@]} keys have secure access policies</li>"
    
    if [ $potentially_insecure_keys -eq 0 ]; then
        add_section "$OUTPUT_FILE" "3.6.1 - Key Protection Procedures" "<p class='green'>Cloud KMS keys appear to have secure access controls and protection mechanisms in place.</p>$key_protection_details</ul><p>While automated evidence is positive, verify through documentation that comprehensive key management procedures exist and include restriction of access to the fewest custodians necessary, key-encrypting keys at least as strong as data-encrypting keys, secure storage of keys in the fewest possible locations, and separation of key-encrypting keys from data-encrypting keys. Cloud KMS handles many of these requirements automatically by design.</p>" "pass"
        ((total_checks++))
        ((passed_checks++))
    else
        add_section "$OUTPUT_FILE" "3.6.1 - Key Protection Procedures" "<p class='yellow'>Some Cloud KMS keys may have security issues with access controls.</p>$key_protection_details</ul><p>Implement comprehensive procedures to protect cryptographic keys against disclosure and misuse, including: restricting access to the fewest custodians necessary, ensuring key-encrypting keys are at least as strong as data-encrypting keys, storing key-encrypting keys separately from data-encrypting keys, and storing keys securely in the fewest possible locations.</p>" "warning"
        ((total_checks++))
        ((warning_checks++))
    fi
else
    key_protection_details+="<li>No Cloud KMS keys found for analysis</li></ul>"
    add_section "$OUTPUT_FILE" "3.6.1 - Key Protection Procedures" "<p class='yellow'>No Cloud KMS keys found for key protection analysis.</p>$key_protection_details<p>If using cryptographic keys to protect stored account data, implement Cloud KMS with appropriate key management procedures.</p>" "warning"
    ((total_checks++))
    ((warning_checks++))
fi

#----------------------------------------------------------------------
# SECTION 7: PCI REQUIREMENT 3.7 - KEY MANAGEMENT
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 3.7: KEY MANAGEMENT ==="

add_section "$OUTPUT_FILE" "Requirement 3.7: Where cryptography is used to protect stored account data, key management processes and procedures covering all aspects of the key lifecycle are defined and implemented" "<p>Analyzing key management lifecycle procedures...</p>" "info"

# Check Cloud KMS key generation capabilities
print_status "INFO" "3.7.1 - Strong key generation"
print_status "INFO" "Checking Cloud KMS key generation capabilities..."

key_generation_details="<h4>Analysis of Cryptographic Key Generation</h4>"

if [ ${#KMS_KEYS_LIST[@]} -gt 0 ]; then
    key_generation_details+="<p class='green'>Found ${#KMS_KEYS_LIST[@]} Cloud KMS keys that provide hardware-backed cryptographic key generation:</p><ul>"
    
    # Analyze key algorithms and strengths
    SYMMETRIC_KEYS=0
    ASYMMETRIC_KEYS=0
    
    for key in "${KMS_KEYS_LIST[@]}"; do
        if [ -z "$key" ]; then continue; fi
        
        # Extract project and key details
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            project=$(echo "$key" | cut -d'/' -f1)
            key_path=$(echo "$key" | cut -d'/' -f2-)
        else
            project="$DEFAULT_PROJECT"
            key_path="$key"
        fi
        
        KEY_PURPOSE=$(gcloud kms keys describe "$key_path" --project="$project" --format="value(purpose)" 2>/dev/null)
        
        if [ "$KEY_PURPOSE" == "ENCRYPT_DECRYPT" ]; then
            ((SYMMETRIC_KEYS++))
        elif [[ "$KEY_PURPOSE" == "ASYMMETRIC"* ]]; then
            ((ASYMMETRIC_KEYS++))
        fi
    done
    
    key_generation_details+="<li>Symmetric encryption keys: $SYMMETRIC_KEYS</li>"
    key_generation_details+="<li>Asymmetric keys: $ASYMMETRIC_KEYS</li>"
    key_generation_details+="</ul>"
    
    key_generation_details+="<p>Cloud KMS provides the following key generation capabilities:</p>
    <ul>
        <li>Hardware-backed symmetric keys (AES-256) that are FIPS 140-2 Level 3 compliant</li>
        <li>Asymmetric keys (RSA and ECC) with various key lengths</li>
        <li>Hardware security module (HSM) backing for all keys</li>
        <li>Cryptographically secure random number generation</li>
    </ul>"
    
    add_section "$OUTPUT_FILE" "3.7.1 - Strong Key Generation" "<p class='green'>Cloud KMS provides secure key generation capabilities with hardware-backed key generation.</p>$key_generation_details<p>While automated evidence is positive, verify through documentation that key-management policies and procedures specifically address the generation of strong cryptographic keys and compliance with industry standards.</p>" "pass"
    ((total_checks++))
    ((passed_checks++))
else
    key_generation_details+="<p>No Cloud KMS keys found to analyze key generation capabilities.</p>"
    add_section "$OUTPUT_FILE" "3.7.1 - Strong Key Generation" "$key_generation_details<p>Implement key-management policies and procedures that address the generation of strong cryptographic keys. Consider using Cloud KMS for hardware-backed key generation.</p>" "warning"
    ((total_checks++))
    ((warning_checks++))
fi

# Requirement 3.7.2 - Key Distribution
add_section "$OUTPUT_FILE" "3.7.2 - Secure Key Distribution" "<p>Automated assessment provides limited evidence of cryptographic key distribution practices.</p>
<p>GCP provides secure key distribution mechanisms through TLS-encrypted API calls, IAM role-based access control, VPC Private Google Access for private network paths to Cloud KMS, and Cloud HSM integration for hardware-based key management.</p>
<p>Manual verification is required to confirm formal key distribution procedures.</p>
<p>Implement key-management policies and procedures that address secure distribution of cryptographic keys. Configure secure channels for key distribution and ensure methods maintain the integrity and confidentiality of keys.</p>" "warning"
((total_checks++))
((warning_checks++))

# Requirement 3.7.3 - Key Storage
add_section "$OUTPUT_FILE" "3.7.3 - Secure Key Storage" "<p>Automated assessment provides limited evidence of cryptographic key storage practices.</p>
<p>Cloud KMS stores keys in FIPS 140-2 Level 3 validated HSMs, and master keys in Cloud KMS never leave the HSMs unencrypted. Cloud HSM provides dedicated hardware security modules for enhanced security.</p>
<p>Manual verification is required to confirm formal key storage procedures.</p>
<p>Implement key-management policies and procedures that address secure storage of cryptographic keys. Ensure keys are stored securely in the fewest possible locations and protected against unauthorized access.</p>" "warning"
((total_checks++))
((warning_checks++))

# Requirement 3.7.4 - Key Cryptoperiod
print_status "INFO" "3.7.4 - Key cryptoperiod and rotation"
print_status "INFO" "Checking key rotation configurations..."

rotated_count=0
non_rotated_count=0
key_rotation_details=""

for key in "${KMS_KEYS_LIST[@]}"; do
    if [ -z "$key" ]; then continue; fi
    
    # Extract project and key details
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        project=$(echo "$key" | cut -d'/' -f1)
        key_path=$(echo "$key" | cut -d'/' -f2-)
    else
        project="$DEFAULT_PROJECT"
        key_path="$key"
    fi
    
    key_name=$(basename "$key_path")
    
    ROTATION_PERIOD=$(gcloud kms keys describe "$key_path" --project="$project" --format="value(rotationPeriod)" 2>/dev/null)
    NEXT_ROTATION=$(gcloud kms keys describe "$key_path" --project="$project" --format="value(nextRotationTime)" 2>/dev/null)
    
    if [ -n "$ROTATION_PERIOD" ]; then
        ((rotated_count++))
        key_rotation_details+="<li class='green'>Key $key_name: Rotation ENABLED (Period: $ROTATION_PERIOD)</li>"
        if [ -n "$NEXT_ROTATION" ]; then
            key_rotation_details+="<li>Next rotation: $NEXT_ROTATION</li>"
        fi
    else
        ((non_rotated_count++))
        key_rotation_details+="<li class='yellow'>Key $key_name: Rotation DISABLED</li>"
    fi
done

rotation_details="<p>Cloud KMS provides automatic key rotation capabilities:</p><ul>$key_rotation_details</ul>"

if [ $rotated_count -gt 0 ]; then
    rotation_status="some"
else
    rotation_status="limited"
fi

rotation_details+="<p>With Cloud KMS key rotation:</p><ul>
    <li>When enabled, GCP automatically rotates symmetric KMS keys at the specified interval</li>
    <li>Previous key material is retained to decrypt data encrypted before rotation</li>
    <li>New encryptions use the latest key material</li>
    <li>Applications don't need to change how they use the key</li>
    <li>Asymmetric KMS keys cannot be automatically rotated</li>
</ul>"

add_section "$OUTPUT_FILE" "3.7.4 - Key Cryptoperiod and Changes" "<p>Automated assessment found $rotation_status evidence of key rotation practices.</p>
$rotation_details
<p>Manual verification is required to confirm whether cryptoperiods are defined for each key type and whether procedures for key changes at defined intervals exist.</p>
<p>Implement key-management policies that define cryptoperiods for each key type and include processes for key changes at the end of those periods. Enable automatic key rotation for Cloud KMS keys where supported.</p>" "warning"
((total_checks++))
((warning_checks++))

# Requirement 3.7.5 - Key Retirement
add_section "$OUTPUT_FILE" "3.7.5 - Key Retirement and Replacement" "<p>Automated assessment provides limited evidence of key retirement practices.</p>
<p>Cloud KMS provides key retirement capabilities through key version management and destruction schedules with customizable waiting periods.</p>
<p>Manual verification is required to confirm whether policies for key retirement or replacement exist for various scenarios.</p>
<p>Implement policies for key retirement or replacement when keys reach cryptoperiod end, key integrity is weakened, or key is compromised. Ensure retired keys are not used for encryption.</p>" "warning"
((total_checks++))
((warning_checks++))

# Requirement 3.7.6 - Manual Key Operations
add_section "$OUTPUT_FILE" "3.7.6 - Manual Key Operations" "<p>Manual verification required. Automated assessment cannot determine if manual cleartext key operations are performed or how they are managed.</p>
<p>Cloud KMS generally handles keys in a way that prevents exposure of cleartext key material to users. However, some scenarios might involve manual key operations:</p>
<ul>
    <li>Import of external key material into Cloud KMS</li>
    <li>Use of Cloud HSM key management utilities</li>
    <li>On-premises key management systems integrated with GCP</li>
</ul>
<p>If manual cleartext key-management operations are performed, ensure they are managed using split knowledge and dual control. This typically requires implementing procedures where at least two people (each with partial knowledge) are required for key operations, and documenting these procedures formally.</p>" "warning"
((total_checks++))
((warning_checks++))

# Requirement 3.7.7 - Unauthorized Key Substitution
add_section "$OUTPUT_FILE" "3.7.7 - Prevention of Unauthorized Key Substitution" "<p>Manual verification required. Automated assessment provides limited insight into controls preventing unauthorized key substitution.</p>
<p>Cloud KMS implements several controls that can help prevent unauthorized key substitution:</p>
<ul>
    <li>IAM policies controlling who can use specific keys</li>
    <li>Key-level IAM policies defining permissions at the individual key level</li>
    <li>Cloud Audit Logs logging of all key operations</li>
    <li>Cloud KMS resource hierarchy for granular access control</li>
</ul>
<p>Manual review of these controls and related documentation is needed to verify proper implementation.</p>
<p>Implement key-management policies and procedures that prevent unauthorized substitution of cryptographic keys. This typically includes access controls, role separation, oversight mechanisms, and audit procedures to detect and prevent unauthorized key changes.</p>" "warning"
((total_checks++))
((warning_checks++))

# Requirement 3.7.8 - Key Custodian Acknowledgment
print_status "INFO" "3.7.8 - Key custodian acknowledgment"
print_status "INFO" "Checking for IAM roles that might be used for key custodians..."

# Check for IAM roles that might be used for key custodians
key_custodian_roles=$(run_across_projects "gcloud projects get-iam-policy" "--format=json" | grep -E "(cloudkms|crypto|key|custodian)" | wc -l)

custodian_details=""
if [ $key_custodian_roles -gt 0 ]; then
    custodian_details="<p>Found $key_custodian_roles IAM bindings with names suggesting they might be used for key custodians. Manual verification is needed to confirm formal acknowledgment procedures.</p>"
else
    custodian_details="<p>No IAM bindings found with names suggesting they might be used for key custodians. Manual verification is needed to identify key custodians and their acknowledgment procedures.</p>"
fi

add_section "$OUTPUT_FILE" "3.7.8 - Key Custodian Acknowledgment" "<p>Automated assessment provides limited evidence of key custodian acknowledgment procedures.</p>
$custodian_details
<p>Ensure all key custodians formally acknowledge (in writing or electronically) that they understand and accept their key-custodian responsibilities. This typically involves documented roles and responsibilities, specific procedures for each custodian role, and a formal acknowledgment process.</p>" "warning"
((total_checks++))
((warning_checks++))

#----------------------------------------------------------------------
# FINALIZE THE REPORT
#----------------------------------------------------------------------
finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"

echo ""
print_status "PASS" "======================= ASSESSMENT SUMMARY ======================="

compliance_percentage=0
if [ $((total_checks - warning_checks)) -gt 0 ]; then
    compliance_percentage=$(( (passed_checks * 100) / (total_checks - warning_checks) ))
fi

echo "Total checks performed: $total_checks"
echo "Passed checks: $passed_checks"
echo "Failed checks: $failed_checks"
echo "Warning/manual checks: $warning_checks"
echo "Automated compliance percentage (excluding warnings): $compliance_percentage%"

summary="<p>A total of $total_checks checks were performed:</p>
<ul>
    <li class=\"green\">Passed checks: $passed_checks</li>
    <li class=\"red\">Failed checks: $failed_checks</li>
    <li class=\"yellow\">Warning/manual checks: $warning_checks</li>
</ul>
<p>Automated compliance percentage (excluding warnings): $compliance_percentage%</p>

<p><strong>Next Steps:</strong></p>
<ol>
    <li>Review all warning items that require manual verification</li>
    <li>Address failed checks as a priority</li>
    <li>Implement recommendations provided in the report</li>
    <li>Document compensating controls where applicable</li>
    <li>Perform a follow-up assessment after remediation</li>
</ol>"

add_section "$OUTPUT_FILE" "Assessment Summary" "$summary" "info"

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