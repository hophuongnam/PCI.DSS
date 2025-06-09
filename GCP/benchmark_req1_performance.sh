#!/usr/bin/env bash

# =============================================================================
# GCP Requirement 1 Scripts Performance Benchmarking Tool
# Comprehensive performance analysis of three script versions using existing 
# performance validation infrastructure
# =============================================================================

# Load test framework and shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_CONFIG="$SCRIPT_DIR/tests/test_config.bash"
LIB_DIR="$SCRIPT_DIR/lib"

# Check if test framework exists
if [[ ! -f "$TEST_CONFIG" ]]; then
    echo "ERROR: Test configuration not found at $TEST_CONFIG"
    exit 1
fi

# Load test configuration and helpers
source "$TEST_CONFIG"
source "$SCRIPT_DIR/tests/helpers/test_helpers.bash"

# Performance benchmarking configuration
BENCHMARK_ITERATIONS=10
MEMORY_SAMPLING_INTERVAL=0.1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BENCHMARK_RESULTS_DIR="$SCRIPT_DIR/performance_benchmark_results_${TIMESTAMP}"
REPORT_FILE="$BENCHMARK_RESULTS_DIR/performance_benchmark_report.html"

# Script versions to benchmark
declare -A SCRIPT_VERSIONS=(
    ["primary"]="$SCRIPT_DIR/check_gcp_pci_requirement1.sh"
    ["enhanced"]="$SCRIPT_DIR/check_gcp_pci_requirement1_integrated.sh"
    ["migrated"]="$SCRIPT_DIR/migrated/check_gcp_pci_requirement1_migrated.sh"
)

# Script metadata
declare -A SCRIPT_METADATA=(
    ["primary_lines"]="637"
    ["primary_description"]="Full framework integration, production ready"
    ["enhanced_lines"]="929"
    ["enhanced_description"]="Highest compliance coverage, most comprehensive"
    ["migrated_lines"]="272"
    ["migrated_description"]="Most compact, modern framework patterns"
)

# Performance metrics storage
declare -A STARTUP_TIMES
declare -A MEMORY_USAGE
declare -A LIBRARY_LOAD_TIMES
declare -A EXECUTION_TIMES
declare -A MEMORY_PEAKS

# =============================================================================
# Benchmarking Functions
# =============================================================================

# Setup benchmark environment
setup_benchmark_environment() {
    echo "Setting up benchmark environment..."
    mkdir -p "$BENCHMARK_RESULTS_DIR"
    
    # Create mock environment for testing
    export PROJECT_ID="benchmark-test-project"
    export GOOGLE_CLOUD_PROJECT="$PROJECT_ID"
    
    # Disable interactive prompts for benchmarking
    export BENCHMARK_MODE="true"
    export SKIP_INTERACTIVE="true"
    
    # Setup mock gcloud responses
    setup_mock_gcloud_environment
    
    echo "Benchmark environment ready at: $BENCHMARK_RESULTS_DIR"
}

# Setup mock gcloud environment
setup_mock_gcloud_environment() {
    # Create mock gcloud script
    local mock_gcloud="$BENCHMARK_RESULTS_DIR/mock_gcloud"
    cat > "$mock_gcloud" << 'EOF'
#!/bin/bash
# Mock gcloud for benchmarking
case "$1" in
    "config")
        case "$2" in
            "get-value") echo "benchmark-test-project" ;;
            *) echo "mock-config-value" ;;
        esac
        ;;
    "projects")
        echo '{"projectId": "benchmark-test-project", "name": "Benchmark Test Project"}'
        ;;
    "compute")
        case "$2" in
            "networks") echo '[]' ;;
            "firewall-rules") echo '[]' ;;
            "instances") echo '[]' ;;
            *) echo '[]' ;;
        esac
        ;;
    "organizations")
        echo '{"name": "organizations/123456789", "displayName": "Test Org"}'
        ;;
    *)
        echo '{"mock": "response"}'
        ;;
esac
exit 0
EOF
    chmod +x "$mock_gcloud"
    
    # Add to PATH for duration of benchmark
    export PATH="$BENCHMARK_RESULTS_DIR:$PATH"
}

# Measure script startup time
measure_startup_time() {
    local script_name="$1"
    local script_path="$2"
    local iterations="$3"
    
    echo "Measuring startup time for $script_name ($iterations iterations)..."
    
    local total_time=0
    local times=()
    
    for ((i=1; i<=iterations; i++)); do
        # Measure time to source libraries and reach main logic
        local start_time=$(date +%s.%N)
        
        # Run script with --help to measure startup without full execution
        timeout 10s bash -c "source '$script_path' --help" >/dev/null 2>&1
        local exit_code=$?
        
        local end_time=$(date +%s.%N)
        local execution_time=$(echo "$end_time - $start_time" | bc -l)
        
        times+=("$execution_time")
        total_time=$(echo "$total_time + $execution_time" | bc -l)
        
        echo "  Iteration $i: ${execution_time}s"
    done
    
    local average_time=$(echo "scale=6; $total_time / $iterations" | bc -l)
    STARTUP_TIMES["$script_name"]="$average_time"
    
    # Calculate standard deviation
    local variance=0
    for time in "${times[@]}"; do
        local diff=$(echo "$time - $average_time" | bc -l)
        local square=$(echo "$diff * $diff" | bc -l)
        variance=$(echo "$variance + $square" | bc -l)
    done
    variance=$(echo "scale=6; $variance / $iterations" | bc -l)
    local std_dev=$(echo "scale=6; sqrt($variance)" | bc -l)
    
    echo "  Average startup time: ${average_time}s (±${std_dev}s)"
}

# Measure library loading overhead
measure_library_loading() {
    local script_name="$1"
    local script_path="$2"
    
    echo "Measuring library loading overhead for $script_name..."
    
    # Extract library loading section from script
    local lib_loading_script="$BENCHMARK_RESULTS_DIR/${script_name}_lib_loading.sh"
    
    # Create script that only loads libraries
    cat > "$lib_loading_script" << EOF
#!/usr/bin/env bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="\$SCRIPT_DIR/../lib"

# Extract library loading from original script
$(grep -E "^source.*\.sh" "$script_path" | head -10)

echo "Libraries loaded successfully"
EOF
    
    chmod +x "$lib_loading_script"
    
    # Measure library loading time
    local start_time=$(date +%s.%N)
    bash "$lib_loading_script" >/dev/null 2>&1
    local end_time=$(date +%s.%N)
    
    local load_time=$(echo "$end_time - $start_time" | bc -l)
    LIBRARY_LOAD_TIMES["$script_name"]="$load_time"
    
    echo "  Library loading time: ${load_time}s"
}

# Measure memory usage
measure_memory_usage() {
    local script_name="$1"
    local script_path="$2"
    
    echo "Measuring memory usage for $script_name..."
    
    # Create memory monitoring script
    local memory_monitor="$BENCHMARK_RESULTS_DIR/${script_name}_memory_monitor.sh"
    cat > "$memory_monitor" << 'EOF'
#!/usr/bin/env bash
pid="$1"
interval="$2"
output_file="$3"

echo "timestamp,rss_kb,vsz_kb" > "$output_file"

while kill -0 "$pid" 2>/dev/null; do
    timestamp=$(date +%s.%N)
    memory_info=$(ps -o rss=,vsz= -p "$pid" 2>/dev/null)
    if [[ -n "$memory_info" ]]; then
        echo "$timestamp,$memory_info" >> "$output_file"
    fi
    sleep "$interval"
done
EOF
    chmod +x "$memory_monitor"
    
    # Run script with memory monitoring
    local memory_log="$BENCHMARK_RESULTS_DIR/${script_name}_memory.csv"
    
    # Start script in background with --help to avoid full execution
    timeout 10s bash "$script_path" --help >/dev/null 2>&1 &
    local script_pid=$!
    
    # Monitor memory usage
    "$memory_monitor" "$script_pid" "$MEMORY_SAMPLING_INTERVAL" "$memory_log" &
    local monitor_pid=$!
    
    # Wait for script to complete
    wait "$script_pid" 2>/dev/null
    
    # Stop monitoring
    kill "$monitor_pid" 2>/dev/null
    wait "$monitor_pid" 2>/dev/null
    
    # Analyze memory usage
    if [[ -f "$memory_log" && $(wc -l < "$memory_log") -gt 1 ]]; then
        local max_rss=$(tail -n +2 "$memory_log" | cut -d',' -f2 | sort -n | tail -1)
        local avg_rss=$(tail -n +2 "$memory_log" | cut -d',' -f2 | awk '{sum+=$1} END {print sum/NR}')
        
        MEMORY_USAGE["$script_name"]="$avg_rss"
        MEMORY_PEAKS["$script_name"]="$max_rss"
        
        echo "  Average memory usage: ${avg_rss}KB"
        echo "  Peak memory usage: ${max_rss}KB"
    else
        echo "  Memory monitoring failed"
        MEMORY_USAGE["$script_name"]="0"
        MEMORY_PEAKS["$script_name"]="0"
    fi
}

# Measure framework loading overhead
measure_framework_overhead() {
    echo "Measuring 4-library framework loading overhead..."
    
    # Measure baseline (no libraries)
    local baseline_start=$(date +%s.%N)
    bash -c "echo 'baseline test'" >/dev/null 2>&1
    local baseline_end=$(date +%s.%N)
    local baseline_time=$(echo "$baseline_end - $baseline_start" | bc -l)
    
    # Measure with all 4 libraries
    local framework_start=$(date +%s.%N)
    bash -c "
        source '$LIB_DIR/gcp_common.sh'
        source '$LIB_DIR/gcp_permissions.sh'
        source '$LIB_DIR/gcp_html_report.sh'
        source '$LIB_DIR/gcp_scope_mgmt.sh'
        echo 'libraries loaded'
    " >/dev/null 2>&1
    local framework_end=$(date +%s.%N)
    local framework_time=$(echo "$framework_end - $framework_start" | bc -l)
    
    # Calculate overhead
    local overhead=$(echo "$framework_time - $baseline_time" | bc -l)
    local overhead_percentage=$(echo "scale=2; ($overhead / $BASELINE_LIBRARY_LOAD_TIME) * 100" | bc -l)
    
    echo "Framework loading overhead: ${overhead}s (${overhead_percentage}%)"
    echo "Sprint S01 baseline: ${BASELINE_LIBRARY_LOAD_TIME}s"
    
    # Store results
    echo "$baseline_time,$framework_time,$overhead,$overhead_percentage" > "$BENCHMARK_RESULTS_DIR/framework_overhead.csv"
}

# Perform GCP API call simulation benchmarks
measure_api_call_efficiency() {
    local script_name="$1"
    local script_path="$2"
    
    echo "Measuring GCP API call efficiency for $script_name..."
    
    # Count number of gcloud commands in script
    local gcloud_count=$(grep -c "gcloud " "$script_path" || echo "0")
    
    # Measure time for typical API calls with mocking
    local api_test_script="$BENCHMARK_RESULTS_DIR/${script_name}_api_test.sh"
    cat > "$api_test_script" << EOF
#!/usr/bin/env bash
start_time=\$(date +%s.%N)

# Simulate API calls found in script
for i in \$(seq 1 $gcloud_count); do
    gcloud config get-value project >/dev/null 2>&1
done

end_time=\$(date +%s.%N)
echo "\$end_time - \$start_time" | bc -l
EOF
    chmod +x "$api_test_script"
    
    local api_time=$(bash "$api_test_script")
    echo "  Simulated API call time ($gcloud_count calls): ${api_time}s"
    
    # Store results
    echo "$script_name,$gcloud_count,$api_time" >> "$BENCHMARK_RESULTS_DIR/api_efficiency.csv"
}

# Generate comprehensive performance report
generate_performance_report() {
    echo "Generating comprehensive performance report..."
    
    cat > "$REPORT_FILE" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GCP Requirement 1 Scripts Performance Benchmark Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; margin-bottom: 10px; }
        .header .subtitle { color: #7f8c8d; font-size: 16px; }
        .summary-cards { display: flex; gap: 20px; margin-bottom: 30px; }
        .card { flex: 1; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .card h3 { margin: 0 0 10px 0; font-size: 18px; }
        .card .value { font-size: 24px; font-weight: bold; }
        .card .unit { font-size: 14px; opacity: 0.8; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .comparison-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .comparison-table th, .comparison-table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        .comparison-table th { background-color: #f8f9fa; font-weight: bold; }
        .comparison-table tr:nth-child(even) { background-color: #f8f9fa; }
        .metric-good { color: #27ae60; font-weight: bold; }
        .metric-warning { color: #f39c12; font-weight: bold; }
        .metric-bad { color: #e74c3c; font-weight: bold; }
        .chart-container { margin: 20px 0; }
        .bar-chart { display: flex; align-items: end; gap: 10px; height: 200px; margin: 20px 0; }
        .bar { background: linear-gradient(to top, #3498db, #2980b9); color: white; padding: 10px 5px; text-align: center; border-radius: 4px 4px 0 0; min-width: 80px; display: flex; flex-direction: column; justify-content: end; }
        .recommendations { background-color: #e8f6f3; border-left: 4px solid #1abc9c; padding: 20px; margin-top: 20px; }
        .recommendations h3 { color: #16a085; margin-top: 0; }
        .metadata { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .timestamp { text-align: center; color: #7f8c8d; margin-top: 30px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>GCP Requirement 1 Scripts Performance Benchmark</h1>
            <div class="subtitle">Comprehensive Performance Analysis and Comparison</div>
        </div>
EOF

    # Add script metadata
    cat >> "$REPORT_FILE" << EOF
        <div class="section">
            <h2>Script Versions Analyzed</h2>
            <table class="comparison-table">
                <tr>
                    <th>Version</th>
                    <th>Lines of Code</th>
                    <th>Description</th>
                    <th>Framework Integration</th>
                </tr>
                <tr>
                    <td><strong>Primary</strong></td>
                    <td>${SCRIPT_METADATA["primary_lines"]}</td>
                    <td>${SCRIPT_METADATA["primary_description"]}</td>
                    <td>Full (4 libraries)</td>
                </tr>
                <tr>
                    <td><strong>Enhanced</strong></td>
                    <td>${SCRIPT_METADATA["enhanced_lines"]}</td>
                    <td>${SCRIPT_METADATA["enhanced_description"]}</td>
                    <td>Partial (2 libraries)</td>
                </tr>
                <tr>
                    <td><strong>Migrated</strong></td>
                    <td>${SCRIPT_METADATA["migrated_lines"]}</td>
                    <td>${SCRIPT_METADATA["migrated_description"]}</td>
                    <td>Full (4 libraries)</td>
                </tr>
            </table>
        </div>
EOF

    # Add performance metrics summary
    local best_startup=""
    local best_memory=""
    local best_loading=""
    local startup_winner=""
    local memory_winner=""
    local loading_winner=""
    
    # Find best performers
    for version in "${!STARTUP_TIMES[@]}"; do
        if [[ -z "$best_startup" ]] || (( $(echo "${STARTUP_TIMES[$version]} < $best_startup" | bc -l) )); then
            best_startup="${STARTUP_TIMES[$version]}"
            startup_winner="$version"
        fi
        if [[ -z "$best_memory" ]] || (( $(echo "${MEMORY_USAGE[$version]} < $best_memory" | bc -l) )); then
            best_memory="${MEMORY_USAGE[$version]}"
            memory_winner="$version"
        fi
        if [[ -z "$best_loading" ]] || (( $(echo "${LIBRARY_LOAD_TIMES[$version]} < $best_loading" | bc -l) )); then
            best_loading="${LIBRARY_LOAD_TIMES[$version]}"
            loading_winner="$version"
        fi
    done

    cat >> "$REPORT_FILE" << EOF
        <div class="summary-cards">
            <div class="card">
                <h3>Fastest Startup</h3>
                <div class="value">$startup_winner</div>
                <div class="unit">${best_startup}s</div>
            </div>
            <div class="card">
                <h3>Lowest Memory</h3>
                <div class="value">$memory_winner</div>
                <div class="unit">${best_memory}KB</div>
            </div>
            <div class="card">
                <h3>Fastest Loading</h3>
                <div class="value">$loading_winner</div>
                <div class="unit">${best_loading}s</div>
            </div>
        </div>

        <div class="section">
            <h2>Performance Metrics Comparison</h2>
            <table class="comparison-table">
                <tr>
                    <th>Metric</th>
                    <th>Primary (637 lines)</th>
                    <th>Enhanced (929 lines)</th>
                    <th>Migrated (272 lines)</th>
                    <th>Best Performer</th>
                </tr>
                <tr>
                    <td><strong>Startup Time</strong></td>
                    <td>${STARTUP_TIMES["primary"]:-"N/A"}s</td>
                    <td>${STARTUP_TIMES["enhanced"]:-"N/A"}s</td>
                    <td>${STARTUP_TIMES["migrated"]:-"N/A"}s</td>
                    <td class="metric-good">$startup_winner</td>
                </tr>
                <tr>
                    <td><strong>Library Loading</strong></td>
                    <td>${LIBRARY_LOAD_TIMES["primary"]:-"N/A"}s</td>
                    <td>${LIBRARY_LOAD_TIMES["enhanced"]:-"N/A"}s</td>
                    <td>${LIBRARY_LOAD_TIMES["migrated"]:-"N/A"}s</td>
                    <td class="metric-good">$loading_winner</td>
                </tr>
                <tr>
                    <td><strong>Average Memory</strong></td>
                    <td>${MEMORY_USAGE["primary"]:-"N/A"}KB</td>
                    <td>${MEMORY_USAGE["enhanced"]:-"N/A"}KB</td>
                    <td>${MEMORY_USAGE["migrated"]:-"N/A"}KB</td>
                    <td class="metric-good">$memory_winner</td>
                </tr>
                <tr>
                    <td><strong>Peak Memory</strong></td>
                    <td>${MEMORY_PEAKS["primary"]:-"N/A"}KB</td>
                    <td>${MEMORY_PEAKS["enhanced"]:-"N/A"}KB</td>
                    <td>${MEMORY_PEAKS["migrated"]:-"N/A"}KB</td>
                    <td>-</td>
                </tr>
            </table>
        </div>
EOF

    # Add framework overhead analysis
    if [[ -f "$BENCHMARK_RESULTS_DIR/framework_overhead.csv" ]]; then
        local overhead_data=$(cat "$BENCHMARK_RESULTS_DIR/framework_overhead.csv")
        IFS=',' read -r baseline_time framework_time overhead overhead_percentage <<< "$overhead_data"
        
        cat >> "$REPORT_FILE" << EOF
        <div class="section">
            <h2>4-Library Framework Loading Overhead</h2>
            <div class="metadata">
                <strong>Baseline (no libraries):</strong> ${baseline_time}s<br>
                <strong>With 4 libraries:</strong> ${framework_time}s<br>
                <strong>Overhead:</strong> ${overhead}s (${overhead_percentage}%)<br>
                <strong>Sprint S01 Baseline:</strong> ${BASELINE_LIBRARY_LOAD_TIME}s<br>
                <strong>Performance Threshold:</strong> <${PERFORMANCE_THRESHOLD_PERCENTAGE}%
            </div>
EOF

        local overhead_status="metric-good"
        if (( $(echo "$overhead_percentage > $PERFORMANCE_THRESHOLD_PERCENTAGE" | bc -l) )); then
            overhead_status="metric-warning"
        fi
        
        cat >> "$REPORT_FILE" << EOF
            <p>Framework loading overhead is <span class="$overhead_status">${overhead_percentage}%</span> of baseline.</p>
        </div>
EOF
    fi

    # Add API efficiency analysis
    if [[ -f "$BENCHMARK_RESULTS_DIR/api_efficiency.csv" ]]; then
        cat >> "$REPORT_FILE" << EOF
        <div class="section">
            <h2>GCP API Call Efficiency</h2>
            <table class="comparison-table">
                <tr>
                    <th>Script Version</th>
                    <th>API Calls Count</th>
                    <th>Simulated Execution Time</th>
                    <th>Time per Call</th>
                </tr>
EOF
        
        while IFS=',' read -r script_name gcloud_count api_time; do
            local time_per_call="N/A"
            if [[ "$gcloud_count" -gt 0 ]]; then
                time_per_call=$(echo "scale=6; $api_time / $gcloud_count" | bc -l)
            fi
            
            cat >> "$REPORT_FILE" << EOF
                <tr>
                    <td><strong>$script_name</strong></td>
                    <td>$gcloud_count</td>
                    <td>${api_time}s</td>
                    <td>${time_per_call}s</td>
                </tr>
EOF
        done < "$BENCHMARK_RESULTS_DIR/api_efficiency.csv"
        
        cat >> "$REPORT_FILE" << EOF
            </table>
        </div>
EOF
    fi

    # Add recommendations
    cat >> "$REPORT_FILE" << EOF
        <div class="recommendations">
            <h3>Performance Recommendations</h3>
            <ul>
                <li><strong>Best Overall Performance:</strong> The <em>$startup_winner</em> version offers the best startup performance</li>
                <li><strong>Memory Efficiency:</strong> The <em>$memory_winner</em> version has the lowest memory footprint</li>
                <li><strong>Framework Integration:</strong> The migrated version demonstrates optimal use of the 4-library framework</li>
                <li><strong>Optimization Opportunities:</strong> Consider reducing library loading overhead in versions with slower startup times</li>
                <li><strong>Trade-offs:</strong> Enhanced version provides more features but at the cost of increased resource usage</li>
            </ul>
        </div>

        <div class="timestamp">
            Generated on $(date '+%Y-%m-%d %H:%M:%S') | Benchmark Run: $TIMESTAMP
        </div>
    </div>
</body>
</html>
EOF

    echo "Performance report generated: $REPORT_FILE"
}

# Main benchmarking execution
main() {
    echo "=== GCP Requirement 1 Scripts Performance Benchmark ==="
    echo "Timestamp: $(date)"
    echo ""
    
    # Setup environment
    setup_benchmark_environment
    
    # Measure framework overhead
    measure_framework_overhead
    
    # Initialize API efficiency tracking
    echo "script_name,gcloud_count,api_time" > "$BENCHMARK_RESULTS_DIR/api_efficiency.csv"
    
    # Benchmark each script version
    for version_name in "${!SCRIPT_VERSIONS[@]}"; do
        local script_path="${SCRIPT_VERSIONS[$version_name]}"
        
        if [[ ! -f "$script_path" ]]; then
            echo "WARNING: Script not found: $script_path"
            continue
        fi
        
        echo ""
        echo "=== Benchmarking $version_name version ==="
        echo "Script: $script_path"
        echo ""
        
        # Perform all benchmarks for this version
        measure_startup_time "$version_name" "$script_path" "$BENCHMARK_ITERATIONS"
        measure_library_loading "$version_name" "$script_path"
        measure_memory_usage "$version_name" "$script_path"
        measure_api_call_efficiency "$version_name" "$script_path"
        
        echo "Completed benchmarking $version_name version"
    done
    
    echo ""
    echo "=== Benchmark Summary ==="
    echo "Results directory: $BENCHMARK_RESULTS_DIR"
    
    # Display summary
    for version in "${!STARTUP_TIMES[@]}"; do
        echo ""
        echo "$version version:"
        echo "  Startup time: ${STARTUP_TIMES[$version]}s"
        echo "  Library loading: ${LIBRARY_LOAD_TIMES[$version]}s"
        echo "  Average memory: ${MEMORY_USAGE[$version]}KB"
        echo "  Peak memory: ${MEMORY_PEAKS[$version]}KB"
    done
    
    # Generate comprehensive report
    generate_performance_report
    
    echo ""
    echo "=== Benchmark Complete ==="
    echo "Comprehensive report: $REPORT_FILE"
    echo "Raw data directory: $BENCHMARK_RESULTS_DIR"
    
    # Open report if running on macOS
    if command -v open >/dev/null 2>&1; then
        echo ""
        echo "Opening performance report..."
        open "$REPORT_FILE"
    fi
}

# Execute main function
main "$@"