---
task_id: T05_S02 # Pilot Script Migration
sprint_sequence_id: S02 # S02_M01_REPORTING_SCOPE_MGMT
status: open # open | in_progress | pending_review | done | failed | blocked
complexity: High # Low | Medium | High
last_updated: 2025-06-06T15:45:00Z
---

# Task: Pilot Script Migration

## Task Description

**Objective:** Execute complete pilot migration of 3 GCP PCI DSS assessment scripts from monolithic architecture to the 4-library framework, establishing migration patterns and validating the complete framework functionality end-to-end.

This task serves as the critical validation point for the complete 4-library framework by migrating production-complexity scripts and ensuring 100% functional equivalence. The migration will establish reusable patterns for the remaining 5+ scripts while proving the framework's real-world effectiveness.

**High Complexity Rationale:**
- Requires integration of all 4 framework libraries (`gcp_common`, `gcp_permissions`, `gcp_html_report`, `gcp_scope_mgmt`)
- Must maintain 100% functional equivalence with original scripts
- Establishes migration patterns for remaining 5+ scripts
- Validates complete framework architecture end-to-end
- Critical path for Sprint S02 success

## Research Context

### Target Scripts Analysis
Based on codebase analysis, the following scripts are selected for pilot migration:

1. **check_gcp_pci_requirement1.sh** (932 lines)
   - Network security requirements with complex scope management
   - Heavy firewall rule analysis and HTML reporting
   - Strong candidate for `gcp_scope_mgmt` and `gcp_html_report` integration

2. **check_gcp_pci_requirement3.sh** (1,090 lines)
   - Data protection requirements with multi-service integration
   - Complex encryption and storage assessments
   - Demonstrates comprehensive framework usage

3. **check_gcp_pci_requirement2.sh** (Selected as third pilot)
   - System configuration requirements
   - Moderate complexity for progressive migration validation

### Framework Status
- **Available:** `gcp_common.sh` (469 lines), `gcp_permissions.sh` (147 lines) from Sprint S01
- **Required:** `gcp_html_report.sh` and `gcp_scope_mgmt.sh` from T01_S02 and T02_S02
- **Integration Example:** `check_gcp_pci_requirement1_integrated.sh` shows partial integration pattern

### Code Reduction Opportunities
Based on architectural analysis, expected reductions per script:
- **CLI Processing:** 80% reduction (40 lines → 8 lines via `gcp_common`)
- **Permission Validation:** 75% reduction (60 lines → 15 lines via `gcp_permissions`)
- **HTML Generation:** 85% reduction (200 lines → 30 lines via `gcp_html_report`)
- **Environment Setup:** 70% reduction (30 lines → 9 lines via `gcp_common`)
- **Overall Target:** 60%+ reduction per script

## Acceptance Criteria

### Primary Success Criteria
- [ ] **Complete Migration:** 3 scripts successfully migrated to use all 4 framework libraries
- [ ] **Code Reduction:** Achieve 60%+ code reduction across all migrated scripts
- [ ] **Functional Equivalence:** 100% identical assessment outputs compared to original scripts
- [ ] **Performance:** Framework overhead under 10% compared to original execution time
- [ ] **Integration Validation:** All 4 libraries working together seamlessly

### Quality Assurance Criteria
- [ ] **Output Validation:** Before/after comparison confirms identical results
- [ ] **Error Handling:** Migrated scripts maintain all original error handling
- [ ] **CLI Compatibility:** All original CLI options and behaviors preserved
- [ ] **Documentation:** Migration patterns documented for remaining scripts

### Framework Validation Criteria
- [ ] **Architecture Proof:** Complete 4-library framework validated in production scenarios
- [ ] **Reusable Patterns:** Migration templates created for remaining scripts
- [ ] **Performance Benchmarks:** Baseline metrics established for framework overhead

## Technical Guidance

### Migration Strategy Overview

The migration follows a systematic 4-phase approach:

```bash
Phase 1: Environment & Libraries → Phase 2: Core Functions → Phase 3: Assessment Logic → Phase 4: Validation
```

### Phase 1: Framework Integration Pattern

**Library Loading (Replaces ~30 lines with ~8 lines):**
```bash
# Original Pattern (in every script):
RED='\033[0;31m'
GREEN='\033[0;32m'
# ... 20+ color/variable definitions

# New Pattern:
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"
source "$LIB_DIR/gcp_html_report.sh"
source "$LIB_DIR/gcp_scope_mgmt.sh"
```

### Phase 2: CLI Processing Migration

**Command Line Parsing (Replaces ~60 lines with ~15 lines):**
```bash
# Original Pattern:
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--scope)
            ASSESSMENT_SCOPE="$2"
            # ... validation logic
        # ... 40+ lines of argument processing
    esac
done

# New Pattern:
parse_common_cli_args "$@"
validate_gcp_environment
setup_assessment_scope "$SCOPE" "$PROJECT_ID" "$ORG_ID"
```

### Phase 3: Permission & Environment Setup

**Permission Management (Replaces ~60 lines with ~15 lines):**
```bash
# Original Pattern:
# ... 40+ lines of manual permission checking
if ! gcloud projects test-iam-permissions "$PROJECT_ID" --permissions="..."; then
    # ... complex error handling
fi

# New Pattern:
register_required_permissions "$REQUIREMENT_NUMBER" \
    "compute.firewall.list" \
    "compute.networks.list" \
    "compute.subnetworks.list"
check_all_permissions || exit 1
```

### Phase 4: HTML Report Generation

**Report Integration (Replaces ~200 lines with ~30 lines):**
```bash
# Original Pattern:
cat > "$OUTPUT_FILE" << EOF
<!DOCTYPE html>
<html>
# ... 150+ lines of HTML template and generation logic

# New Pattern:
configure_html_report "$REQUIREMENT_NUMBER" "$REPORT_TITLE"
add_assessment_section "Network Security Controls" "network_security"
# ... assessment logic calls add_check_result
generate_final_report "$OUTPUT_FILE"
```

### Phase 5: Scope Management Integration

**Multi-Project Handling (Replaces ~50 lines with ~12 lines):**
```bash
# Original Pattern:
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    # ... complex organization enumeration
    for project in $(gcloud projects list --format="value(projectId)"); do
        # ... 30+ lines of project iteration logic
    done
fi

# New Pattern:
initialize_scope_management "$SCOPE_TYPE" "$ORG_ID"
for project_data in $(enumerate_projects); do
    setup_project_context "$project_data"
    # ... assessment logic
done
```

### Validation Methodology

**1. Output Equivalence Testing:**
```bash
# Run original script
./check_gcp_pci_requirement1.sh --scope project --project test-project > original_output.html

# Run migrated script  
./check_gcp_pci_requirement1_migrated.sh --scope project --project test-project > migrated_output.html

# Compare core assessment results (excluding timestamps)
diff <(grep -E "(PASS|FAIL|WARN)" original_output.html | sort) \
     <(grep -E "(PASS|FAIL|WARN)" migrated_output.html | sort)
```

**2. Performance Comparison:**
```bash
# Benchmark original
time ./check_gcp_pci_requirement1.sh --scope project

# Benchmark migrated
time ./check_gcp_pci_requirement1_migrated.sh --scope project

# Validate <10% overhead threshold
```

## Implementation Plan

### Phase 1: Environment Setup (2 hours)
1. **Library Dependencies:**
   - Verify `gcp_html_report.sh` and `gcp_scope_mgmt.sh` completion from T01_S02/T02_S02
   - Test all 4 libraries load successfully together
   - Resolve any cross-library dependencies

2. **Migration Workspace:**
   - Create `migrated/` directory for new script versions
   - Backup original scripts for comparison
   - Setup validation testing environment

### Phase 2: Requirement 1 Script Migration (4 hours)
1. **Framework Integration:**
   - Replace library loading with 4-library framework
   - Migrate CLI parsing to `gcp_common` functions
   - Convert permission checks to `gcp_permissions` API

2. **Core Logic Migration:**
   - Integrate `gcp_scope_mgmt` for project iteration
   - Convert HTML generation to `gcp_html_report` calls
   - Preserve all assessment logic unchanged

3. **Validation:**
   - Execute side-by-side comparison testing
   - Verify identical assessment results
   - Performance benchmark comparison

### Phase 3: Requirement 3 Script Migration (4 hours)
1. **Apply Patterns:** Use established patterns from Requirement 1 migration
2. **Complex Integration:** Handle multi-service assessment complexity
3. **Validation:** Comprehensive testing with data protection scenarios

### Phase 4: Requirement 2 Script Migration (3 hours)
1. **Pattern Refinement:** Apply lessons learned from first two migrations
2. **Template Development:** Create reusable migration template
3. **Final Validation:** Complete framework validation

### Phase 5: Documentation & Templates (2 hours)
1. **Migration Documentation:**
   - Document migration patterns and lessons learned
   - Create step-by-step migration guide
   - Performance analysis report

2. **Template Creation:**
   - Develop migration template for remaining 5+ scripts
   - Code reduction metrics documentation
   - Best practices guide

### Phase 6: Framework Validation Report (1 hour)
1. **Comprehensive Analysis:**
   - Framework performance metrics
   - Code reduction achievements
   - Integration success validation
   - Readiness assessment for remaining scripts

## Success Criteria

### Quantitative Metrics
- **Code Reduction:** 60%+ reduction across all 3 migrated scripts
- **Performance:** <10% execution time overhead
- **Functional Coverage:** 100% assessment result equivalence
- **Framework Integration:** All 4 libraries successfully integrated

### Qualitative Validations
- **Migration Patterns:** Reusable templates established
- **Framework Maturity:** Complete 4-library architecture validated
- **Maintenance Improvement:** Simplified script structure achieved
- **Developer Experience:** Clear migration path for remaining scripts

### Deliverables
1. **Migrated Scripts:** 3 fully functional scripts using complete framework
2. **Migration Guide:** Comprehensive documentation with patterns and examples
3. **Validation Report:** Performance and functional equivalence analysis
4. **Migration Template:** Reusable template for remaining 5+ scripts
5. **Framework Assessment:** Complete validation of 4-library architecture

## Risk Mitigation

### Technical Risks
- **Library Dependencies:** Ensure T01_S02/T02_S02 completion before starting
- **Integration Complexity:** Start with Requirement 1 (has existing partial integration)
- **Output Changes:** Maintain rigorous before/after validation testing

### Schedule Risks
- **Complexity Underestimation:** High complexity rating accounts for unknown integration issues
- **Dependency Delays:** Can begin with available libraries, integrate remaining as completed
- **Validation Time:** 40% of effort allocated to validation and testing

This task represents the critical validation milestone for the complete GCP PCI DSS framework, establishing the foundation for all remaining script migrations in future sprints.