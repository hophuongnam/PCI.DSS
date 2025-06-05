#!/bin/bash
# Coverage Helper Functions for GCP PCI DSS Testing Framework
# This file provides utilities for measuring and reporting test coverage

# Coverage configuration
setup_coverage_environment() {
    export COVERAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/coverage"
    export COVERAGE_REPORT_DIR="$COVERAGE_DIR/reports"
    export COVERAGE_DATA_DIR="$COVERAGE_DIR/data"
    
    mkdir -p "$COVERAGE_REPORT_DIR" "$COVERAGE_DATA_DIR"
    
    # Coverage targets
    export UNIT_TEST_FUNCTION_COVERAGE_TARGET=95
    export UNIT_TEST_LINE_COVERAGE_TARGET=90
    export INTEGRATION_TEST_COVERAGE_TARGET=85
    export OVERALL_COVERAGE_TARGET=90
}

# Generate coverage report using kcov
generate_kcov_coverage() {
    local test_file="$1"
    local library_file="$2"
    local output_dir="$3"
    local test_name="$(basename "$test_file" .bats)"
    
    echo "Generating coverage for $test_name..."
    
    # Ensure output directory exists
    mkdir -p "$output_dir"
    
    # Run kcov with the test
    if command -v kcov >/dev/null 2>&1; then
        kcov \
            --include-path="$(dirname "$library_file")" \
            --exclude-pattern="*test*,*/tests/*" \
            "$output_dir/$test_name" \
            bats "$test_file"
    else
        echo "Warning: kcov not available, skipping coverage for $test_name"
        return 1
    fi
}

# Parse kcov coverage results
parse_kcov_results() {
    local coverage_dir="$1"
    local test_name="$2"
    
    local index_file="$coverage_dir/$test_name/index.html"
    if [[ -f "$index_file" ]]; then
        # Extract coverage percentage from HTML report
        local line_coverage=$(grep -o 'Lines.*[0-9]\+\.[0-9]\+%' "$index_file" | grep -o '[0-9]\+\.[0-9]\+' | head -1)
        local function_coverage=$(grep -o 'Functions.*[0-9]\+\.[0-9]\+%' "$index_file" | grep -o '[0-9]\+\.[0-9]\+' | head -1)
        
        echo "Coverage for $test_name:"
        echo "  Line Coverage: ${line_coverage:-0.0}%"
        echo "  Function Coverage: ${function_coverage:-0.0}%"
        
        export LAST_LINE_COVERAGE="$line_coverage"
        export LAST_FUNCTION_COVERAGE="$function_coverage"
    else
        echo "Coverage report not found for $test_name"
        return 1
    fi
}

# Alternative coverage using bash built-in debugging
generate_bash_coverage() {
    local script_file="$1"
    local test_file="$2"
    local output_file="$3"
    
    echo "Generating bash coverage for $(basename "$script_file")..."
    
    # Create a coverage-enabled version of the script
    local instrumented_script="$COVERAGE_DATA_DIR/instrumented_$(basename "$script_file")"
    
    # Add line numbering and execution tracking
    cat > "$instrumented_script" << 'EOF'
#!/bin/bash
# Coverage instrumentation
declare -A coverage_lines
coverage_file="/tmp/coverage_$(basename "$0").data"

# Trap to record line execution
trap 'coverage_lines[$LINENO]=1; echo "$LINENO" >> "$coverage_file"' DEBUG

EOF
    
    # Append original script content with line numbers
    nl -nln "$script_file" | sed 's/^[[:space:]]*\([0-9]*\)[[:space:]]/# Line \1: /' >> "$instrumented_script"
    cat "$script_file" >> "$instrumented_script"
    
    chmod +x "$instrumented_script"
    
    # Run tests with instrumented script
    echo "Running instrumented tests..."
    # This would need integration with the specific test framework
}

# Function coverage analysis
analyze_function_coverage() {
    local library_file="$1"
    local test_file="$2"
    
    echo "Analyzing function coverage for $(basename "$library_file")..."
    
    # Extract all function definitions from library
    local functions_file="$COVERAGE_DATA_DIR/functions_$(basename "$library_file").list"
    grep -n "^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*(" "$library_file" | \
        sed 's/^\([0-9]*\):[[:space:]]*\([a-zA-Z_][a-zA-Z0-9_]*\).*/\2 (line \1)/' > "$functions_file"
    
    local total_functions=$(wc -l < "$functions_file")
    
    # Check which functions are tested
    local tested_functions=0
    local tested_functions_file="$COVERAGE_DATA_DIR/tested_functions_$(basename "$library_file").list"
    
    echo "Functions found in $library_file:" > "$tested_functions_file"
    cat "$functions_file" >> "$tested_functions_file"
    echo "" >> "$tested_functions_file"
    echo "Functions tested:" >> "$tested_functions_file"
    
    while IFS= read -r line; do
        local func_name=$(echo "$line" | cut -d' ' -f1)
        if grep -q "$func_name" "$test_file"; then
            echo "✓ $func_name" >> "$tested_functions_file"
            ((tested_functions++))
        else
            echo "✗ $func_name (not tested)" >> "$tested_functions_file"
        fi
    done < "$functions_file"
    
    local function_coverage_percentage=$(echo "scale=2; $tested_functions * 100 / $total_functions" | bc -l 2>/dev/null || python3 -c "print(round($tested_functions * 100 / $total_functions, 2))")
    
    echo "Function Coverage Analysis:"
    echo "  Total Functions: $total_functions"
    echo "  Tested Functions: $tested_functions"
    echo "  Coverage: ${function_coverage_percentage}%"
    
    export FUNCTION_COVERAGE_PERCENTAGE="$function_coverage_percentage"
    export TOTAL_FUNCTIONS="$total_functions"
    export TESTED_FUNCTIONS="$tested_functions"
}

# Line coverage analysis using simple execution tracking
analyze_line_coverage() {
    local library_file="$1"
    local coverage_trace_file="$2"
    
    echo "Analyzing line coverage for $(basename "$library_file")..."
    
    local total_lines=$(wc -l < "$library_file")
    local executable_lines=$(grep -c -v '^[[:space:]]*$\|^[[:space:]]*#' "$library_file")
    
    if [[ -f "$coverage_trace_file" ]]; then
        local executed_lines=$(sort -u "$coverage_trace_file" | wc -l)
        local line_coverage_percentage=$(echo "scale=2; $executed_lines * 100 / $executable_lines" | bc -l 2>/dev/null || python3 -c "print(round($executed_lines * 100 / $executable_lines, 2))")
        
        echo "Line Coverage Analysis:"
        echo "  Total Lines: $total_lines"
        echo "  Executable Lines: $executable_lines"
        echo "  Executed Lines: $executed_lines"
        echo "  Coverage: ${line_coverage_percentage}%"
        
        export LINE_COVERAGE_PERCENTAGE="$line_coverage_percentage"
    else
        echo "No coverage trace file found: $coverage_trace_file"
        export LINE_COVERAGE_PERCENTAGE="0.0"
    fi
}

# Generate comprehensive coverage report
generate_coverage_report() {
    local report_name="$1"
    local report_file="$COVERAGE_REPORT_DIR/${report_name}_coverage_report.html"
    
    echo "Generating comprehensive coverage report: $report_name"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>GCP PCI DSS Testing Framework - Coverage Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; }
        .metric { display: inline-block; margin: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .high-coverage { background-color: #d4edda; }
        .medium-coverage { background-color: #fff3cd; }
        .low-coverage { background-color: #f8d7da; }
        .details { margin-top: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>GCP PCI DSS Testing Framework - Coverage Report</h1>
        <p>Generated on: $(date)</p>
        <p>Report: $report_name</p>
    </div>
EOF
    
    # Add coverage metrics if available
    if [[ -n "$FUNCTION_COVERAGE_PERCENTAGE" ]]; then
        local coverage_class="low-coverage"
        if (( $(echo "$FUNCTION_COVERAGE_PERCENTAGE >= $UNIT_TEST_FUNCTION_COVERAGE_TARGET" | bc -l 2>/dev/null || echo 0) )); then
            coverage_class="high-coverage"
        elif (( $(echo "$FUNCTION_COVERAGE_PERCENTAGE >= 80" | bc -l 2>/dev/null || echo 0) )); then
            coverage_class="medium-coverage"
        fi
        
        cat >> "$report_file" << EOF
    <div class="metric $coverage_class">
        <h3>Function Coverage</h3>
        <p><strong>${FUNCTION_COVERAGE_PERCENTAGE}%</strong></p>
        <p>Target: ${UNIT_TEST_FUNCTION_COVERAGE_TARGET}%</p>
        <p>($TESTED_FUNCTIONS / $TOTAL_FUNCTIONS functions)</p>
    </div>
EOF
    fi
    
    if [[ -n "$LINE_COVERAGE_PERCENTAGE" ]]; then
        local coverage_class="low-coverage"
        if (( $(echo "$LINE_COVERAGE_PERCENTAGE >= $UNIT_TEST_LINE_COVERAGE_TARGET" | bc -l 2>/dev/null || echo 0) )); then
            coverage_class="high-coverage"
        elif (( $(echo "$LINE_COVERAGE_PERCENTAGE >= 75" | bc -l 2>/dev/null || echo 0) )); then
            coverage_class="medium-coverage"
        fi
        
        cat >> "$report_file" << EOF
    <div class="metric $coverage_class">
        <h3>Line Coverage</h3>
        <p><strong>${LINE_COVERAGE_PERCENTAGE}%</strong></p>
        <p>Target: ${UNIT_TEST_LINE_COVERAGE_TARGET}%</p>
    </div>
EOF
    fi
    
    cat >> "$report_file" << EOF
    <div class="details">
        <h2>Coverage Details</h2>
        <p>Detailed coverage information and recommendations would be added here based on specific test results.</p>
    </div>
</body>
</html>
EOF
    
    echo "Coverage report generated: $report_file"
}

# Check coverage thresholds
check_coverage_thresholds() {
    local test_type="$1"  # unit, integration, validation
    local function_coverage="${2:-0}"
    local line_coverage="${3:-0}"
    
    local threshold_met=true
    
    case "$test_type" in
        "unit")
            if (( $(echo "$function_coverage < $UNIT_TEST_FUNCTION_COVERAGE_TARGET" | bc -l 2>/dev/null || echo 1) )); then
                echo "⚠️  Function coverage ($function_coverage%) below target ($UNIT_TEST_FUNCTION_COVERAGE_TARGET%)"
                threshold_met=false
            fi
            if (( $(echo "$line_coverage < $UNIT_TEST_LINE_COVERAGE_TARGET" | bc -l 2>/dev/null || echo 1) )); then
                echo "⚠️  Line coverage ($line_coverage%) below target ($UNIT_TEST_LINE_COVERAGE_TARGET%)"
                threshold_met=false
            fi
            ;;
        "integration")
            if (( $(echo "$line_coverage < $INTEGRATION_TEST_COVERAGE_TARGET" | bc -l 2>/dev/null || echo 1) )); then
                echo "⚠️  Integration coverage ($line_coverage%) below target ($INTEGRATION_TEST_COVERAGE_TARGET%)"
                threshold_met=false
            fi
            ;;
        "overall")
            if (( $(echo "$line_coverage < $OVERALL_COVERAGE_TARGET" | bc -l 2>/dev/null || echo 1) )); then
                echo "⚠️  Overall coverage ($line_coverage%) below target ($OVERALL_COVERAGE_TARGET%)"
                threshold_met=false
            fi
            ;;
    esac
    
    if $threshold_met; then
        echo "✅ Coverage thresholds met for $test_type tests"
        return 0
    else
        echo "❌ Coverage thresholds not met for $test_type tests"
        return 1
    fi
}

# Cleanup coverage files
cleanup_coverage_files() {
    local days_to_keep="${1:-7}"
    
    echo "Cleaning up coverage files older than $days_to_keep days..."
    
    if [[ -d "$COVERAGE_DIR" ]]; then
        find "$COVERAGE_DIR" -type f -mtime +$days_to_keep -delete
        echo "Coverage cleanup completed"
    fi
}

# Export coverage functions
export -f setup_coverage_environment generate_kcov_coverage parse_kcov_results
export -f generate_bash_coverage analyze_function_coverage analyze_line_coverage
export -f generate_coverage_report check_coverage_thresholds cleanup_coverage_files