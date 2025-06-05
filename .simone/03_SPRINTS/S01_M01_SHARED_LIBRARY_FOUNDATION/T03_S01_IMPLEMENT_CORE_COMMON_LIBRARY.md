# Task: T03_S01 - Implement Core Common Library

## Basic Task Information
- **Task ID:** T03_S01
- **Sprint Sequence ID:** S01
- **Status:** open
- **Priority:** High
- **Complexity:** Medium
- **Estimated Effort:** 2 days
- **Created:** 2025-01-06
- **Last Updated:** 2025-01-06

## Description
Implement the core common library (`gcp_common.sh`) containing shared functions for CLI parsing, environment setup, logging, and validation utilities. This library serves as the foundation for all GCP PCI DSS assessment scripts and eliminates the primary source of code duplication across requirement scripts.

## Goal/Objectives
- Implement core shared library with common utility functions used across all requirement scripts
- Create unified CLI argument parsing framework supporting standard options (-s, -p, -o, -h)
- Implement comprehensive environment setup and initialization functions
- Create consistent logging and validation utilities with color-coded output
- Establish foundation for eliminating 60% code duplication across 9 requirement scripts

## Acceptance Criteria
- [ ] `gcp_common.sh` library file created with all core functions from technical specifications
- [ ] CLI argument parsing framework implemented supporting -s (scope), -p (project), -o (output), -h (help) options
- [ ] Environment setup functions implemented including colors, variables, and directory initialization
- [ ] Logging functions implemented with consistent color-coded formatting and status levels
- [ ] Validation utilities implemented for prerequisites, permissions, and input validation
- [ ] Library integration tested with sample script demonstrating successful function loading
- [ ] All functions follow standardized error handling patterns
- [ ] Documentation includes API reference and usage examples for each function

## Subtasks
- [ ] Create `lib/` directory structure in GCP project root
- [ ] Implement `gcp_common.sh` file with core framework structure
- [ ] Implement `source_gcp_libraries()` function for loading required libraries
- [ ] Implement `setup_environment()` function for color variables and directory initialization
- [ ] Implement `parse_common_arguments()` function for unified CLI parsing
- [ ] Implement `validate_prerequisites()` function for gcloud, jq, and connectivity checks
- [ ] Implement `print_status()` and logging functions with color-coded output
- [ ] Implement `load_requirement_config()` function for configuration file loading
- [ ] Create basic integration test script for library function validation
- [ ] Document library API with function signatures and usage examples
- [ ] Validate library loads correctly and functions execute without errors

## Technical Guidance Section

### Required Function Signatures
Based on GCP Refactoring PRD specifications, implement these exact function signatures:

```bash
# Core Library Loading
source_gcp_libraries()           # Load all required libraries

# Environment Management
setup_environment()             # Initialize colors, variables, directories  

# CLI Argument Processing
parse_common_arguments()        # Standard CLI parsing (-s, -p, -o, -h)

# Validation Functions
validate_prerequisites()        # Check gcloud, permissions, connectivity

# Output and Logging
print_status()                 # Colored output formatting

# Configuration Management
load_requirement_config()      # Load requirement-specific configuration
```

### Color-Coding Standards
Implement consistent terminal output color scheme:
- **Red:** Error messages and failed checks
- **Green:** Success messages and passed checks
- **Yellow:** Warning messages and partial compliance
- **Blue:** Informational messages and headers
- **Cyan:** Command examples and code snippets
- **White/Default:** Regular text and descriptions

### CLI Argument Patterns
Support standardized command-line options across all scripts:
- `-s, --scope`: Assessment scope (project|organization)
- `-p, --project`: Target project ID or organization ID
- `-o, --output`: Output directory for reports
- `-h, --help`: Display help information and usage examples

### Integration Points with Existing Scripts
- Functions must be compatible with existing gcloud SDK commands
- Maintain backward compatibility with current script interfaces
- Support both interactive and non-interactive execution modes
- Handle existing environment variable patterns

### Error Handling Patterns
Follow consistent error handling approach:
- Use standardized exit codes (0=success, 1=error, 2=warning)
- Provide actionable error messages with remediation suggestions
- Log errors to both console and log files
- Support graceful degradation when optional features fail

## Implementation Notes Section

### Detailed Implementation Approach

#### Phase 1: Directory Structure Setup
Create organized library structure:
```
GCP/
├── lib/
│   ├── gcp_common.sh           # Core common library (this task)
│   ├── gcp_html_report.sh      # HTML report engine (future task)
│   ├── gcp_permissions.sh      # Permission management (future task)
│   └── gcp_scope_mgmt.sh       # Scope management (future task)
├── config/                     # Configuration files (future)
└── assessments/                # Assessment modules (future)
```

#### Phase 2: Core Function Implementation
Implement functions in this order to maintain dependencies:
1. `source_gcp_libraries()` - Library loading mechanism
2. `setup_environment()` - Color variables and environment initialization
3. `print_status()` - Basic logging and output functions
4. `validate_prerequisites()` - System and tool validation
5. `parse_common_arguments()` - CLI argument processing
6. `load_requirement_config()` - Configuration file support

#### Phase 3: Testing Strategy
- Create `test_gcp_common.sh` script to validate each function
- Test library loading and function availability
- Validate CLI argument parsing with various input combinations
- Test error handling scenarios and edge cases
- Verify color output works across different terminal types

### Technical Implementation Details

#### Function Implementation Requirements

**source_gcp_libraries():**
- Determine library directory path relative to calling script
- Load gcp_common.sh and validate successful loading
- Set global variables for library paths and availability
- Handle missing library files gracefully

**setup_environment():**
- Define color variables (RED, GREEN, YELLOW, BLUE, CYAN, NC)
- Set default directories for logs, reports, and temporary files
- Initialize global variables for script execution
- Create required directories if they don't exist

**parse_common_arguments():**
- Process command-line arguments using getopts or manual parsing
- Support both short (-s) and long (--scope) option formats
- Validate argument values and set global variables
- Display help information when requested

**validate_prerequisites():**
- Check for required tools: gcloud, jq, curl
- Validate gcloud authentication status
- Test basic GCP API connectivity
- Verify minimum required permissions for assessment

**print_status():**
- Accept status level (info, warning, error, success) and message
- Apply appropriate color formatting based on status
- Support both console and log file output
- Include timestamp and script context information

**load_requirement_config():**
- Accept requirement number or config file path
- Load and validate configuration file format
- Set global variables from configuration values
- Handle missing or malformed configuration files

### Integration Testing Approach
Create comprehensive test script that:
1. Sources the library and verifies all functions are available
2. Tests each function with valid and invalid inputs
3. Validates color output and formatting
4. Checks error handling and exit codes
5. Verifies integration with existing script patterns

### Success Metrics
- Library loads successfully without errors
- All required functions are callable and functional
- CLI argument parsing handles standard use cases
- Color output displays correctly across terminal types
- Error handling provides actionable user feedback
- Integration test passes all validation checks

## Dependencies
- **Depends on:** GCP project directory structure
- **Required for:** All subsequent shared library implementations
- **Blocks:** T04_S01 (HTML Report Engine), T05_S01 (Permission Management)

## Notes
- This task establishes the foundation for the entire shared library framework
- Focus on creating robust, reusable functions that will serve all 9 requirement scripts
- Prioritize consistency and reliability over advanced features in this initial implementation
- Ensure functions are well-documented as they will be used by multiple team members

## Risk Considerations
- **Medium Risk:** Breaking compatibility with existing script interfaces
  - **Mitigation:** Maintain backward compatibility patterns and test thoroughly
- **Low Risk:** Performance impact from additional function call overhead
  - **Mitigation:** Keep functions lightweight and measure execution time
- **Low Risk:** Different terminal environments affecting color output
  - **Mitigation:** Test across multiple terminal types and provide fallback options