# GCP PCI DSS Shared Library Integration Guide

## Quick Start

### 1. Basic Integration Pattern

```bash
#!/usr/bin/env bash

# Load shared libraries
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"

# Setup environment
setup_environment "my_assessment.log"

# Register required permissions
register_required_permissions "1" \
    "compute.instances.list" \
    "compute.firewalls.list" \
    "resourcemanager.projects.get"

# Check permissions and handle limited access
if ! check_all_permissions; then
    if ! prompt_continue_limited; then
        exit 1
    fi
fi

# Validate scope
validate_scope_permissions

# Your assessment logic here...
```

### 2. Migration from Legacy Scripts

#### Before (Legacy Pattern):
```bash
# Manual color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
# ... more colors

# Manual argument parsing
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--scope) SCOPE="$2"; shift 2 ;;
        # ... more parsing
    esac
done

# Manual permission checking
gcloud projects test-iam-permissions...
```

#### After (Shared Library Pattern):
```bash
# Load shared libraries (colors included)
source lib/gcp_common.sh
source lib/gcp_permissions.sh

# Use standard argument parsing
parse_common_arguments "$@"

# Use centralized permission management
register_required_permissions "1" "compute.instances.list"
check_all_permissions
```

## Integration Examples

### Example 1: Basic Requirement Script

```bash
#!/usr/bin/env bash
# check_gcp_pci_requirement_example.sh

# Load shared libraries
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"

main() {
    # Setup
    setup_environment "requirement_x.log"
    parse_common_arguments "$@"
    
    # Validate prerequisites
    validate_prerequisites || exit 1
    
    # Register and check permissions
    register_required_permissions "X" \
        "compute.instances.list" \
        "compute.networks.list"
    
    if ! check_all_permissions; then
        prompt_continue_limited || exit 1
    fi
    
    # Validate scope
    validate_scope_permissions || exit 1
    
    # Your assessment logic here
    print_status "INFO" "Starting Requirement X assessment..."
    
    # Cleanup
    cleanup_temp_files
}

# Help function using shared pattern
show_help() {
    cat << EOF
GCP PCI DSS Requirement X Assessment Script

Usage: $0 [OPTIONS]

Options:
    -s, --scope SCOPE       Assessment scope (project|organization)
    -p, --project ID        Target project ID
    -o, --output DIR        Output directory for reports
    -r, --report-only       Generate reports only
    -v, --verbose           Enable verbose output
    -h, --help              Display this help

Examples:
    $0 -s project -p my-project-id
    $0 -s organization -p my-org-id -v
EOF
}

# Run main function
main "$@"
```

### Example 2: Advanced Integration with Error Handling

```bash
#!/usr/bin/env bash
# Advanced integration example

# Load shared libraries with error handling
LIB_DIR="$(dirname "$0")/lib"
if [[ ! -f "$LIB_DIR/gcp_common.sh" ]]; then
    echo "Error: Shared libraries not found in $LIB_DIR" >&2
    exit 1
fi

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1

main() {
    # Error handling for setup
    if ! setup_environment "advanced_assessment.log"; then
        print_status "FAIL" "Environment setup failed"
        exit 1
    fi
    
    # Parse arguments with error handling
    if ! parse_common_arguments "$@"; then
        show_help
        exit 1
    fi
    
    # Comprehensive permission setup
    local permissions=(
        "compute.instances.list"
        "compute.networks.list"
        "compute.firewalls.list"
        "resourcemanager.projects.get"
    )
    
    register_required_permissions "1" "${permissions[@]}"
    
    # Handle permission scenarios
    if check_all_permissions; then
        print_status "PASS" "All permissions available"
    else
        local coverage=$(get_permission_coverage)
        print_status "WARN" "Limited permissions: ${coverage}% coverage"
        
        if [[ $coverage -lt 50 ]]; then
            print_status "FAIL" "Insufficient permissions for reliable assessment"
            exit 1
        fi
        
        if ! prompt_continue_limited; then
            print_status "INFO" "Assessment cancelled by user"
            exit 0
        fi
    fi
    
    # Your assessment logic with comprehensive error handling
    perform_assessment || {
        print_status "FAIL" "Assessment failed"
        cleanup_temp_files
        exit 1
    }
    
    print_status "PASS" "Assessment completed successfully"
    cleanup_temp_files
}

perform_assessment() {
    print_status "INFO" "Performing comprehensive assessment..."
    
    # Validate scope first
    validate_scope_permissions || return 1
    
    # Your actual assessment code here
    return 0
}

main "$@"
```

## Best Practices

### 1. Library Loading Order
Always load `gcp_common.sh` first, then other libraries:
```bash
source "$LIB_DIR/gcp_common.sh"    # Must be first
source "$LIB_DIR/gcp_permissions.sh"
# source other libraries as needed
```

### 2. Error Handling
Use consistent error handling patterns:
```bash
# Good: Check return codes
if ! check_all_permissions; then
    # Handle error
fi

# Good: Use || for error handling
validate_scope_permissions || exit 1

# Avoid: Ignoring errors
check_all_permissions  # Bad - no error handling
```

### 3. Environment Setup
Always setup environment early:
```bash
main() {
    setup_environment "script_name.log"  # First thing
    parse_common_arguments "$@"           # Second thing
    # ... rest of script
}
```

### 4. Permission Management
Register all permissions at once:
```bash
# Good: All permissions registered together
register_required_permissions "1" \
    "compute.instances.list" \
    "compute.networks.list" \
    "storage.buckets.list"

# Avoid: Multiple registration calls
register_required_permissions "1" "compute.instances.list"
register_required_permissions "1" "compute.networks.list"  # Overwrites previous
```

## Troubleshooting

### Common Issues

#### 1. Library Not Found
```
Error: gcp_common.sh not found
```
**Solution:** Check LIB_DIR path and ensure libraries are in `lib/` directory.

#### 2. Function Not Available
```
bash: register_required_permissions: command not found
```
**Solution:** Ensure `gcp_permissions.sh` is loaded after `gcp_common.sh`.

#### 3. Permission Errors
```
Error: Cannot access project 'my-project'
```
**Solution:** Verify gcloud authentication and project access permissions.

### Debugging

Enable verbose mode for detailed output:
```bash
./your_script.sh -v  # Enables verbose logging
```

Check library loading:
```bash
# Verify functions are available
declare -F | grep -E "(setup_environment|check_all_permissions)"
```

## Performance Optimization

### 1. Minimal Overhead
Shared libraries add only ~0.012s overhead for loading, well within performance targets.

### 2. Function Caching
Some functions cache results to avoid repeated API calls:
```bash
# Permission checks are cached within single script execution
check_all_permissions  # Makes API calls
check_all_permissions  # Uses cached results
```

### 3. Conditional Loading
Load only required libraries:
```bash
# Only load what you need
source "$LIB_DIR/gcp_common.sh"
# Skip gcp_permissions.sh if not doing permission checks
```

## Migration Checklist

- [ ] Replace manual color definitions with shared library
- [ ] Replace custom argument parsing with `parse_common_arguments`
- [ ] Replace manual permission checking with `register_required_permissions`
- [ ] Replace custom environment setup with `setup_environment`
- [ ] Use consistent error handling with `print_status`
- [ ] Add proper cleanup with `cleanup_temp_files`
- [ ] Test all command-line options work correctly
- [ ] Verify output format matches original script
- [ ] Confirm performance is within 10% of original

## Support

For additional help:
- Check `lib/README_PERMISSIONS.md` for detailed API documentation
- Review `lib/SHARED_LIBRARY_ARCHITECTURE_DESIGN.md` for architecture details
- Examine existing integrated scripts as examples
- Run unit tests in `tests/` directory for validation