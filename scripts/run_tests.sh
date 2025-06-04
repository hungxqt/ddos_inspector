#!/bin/bash

# Enhanced Test Runner for DDoS Inspector
# Supports parallel execution, coverage, performance monitoring, and CI/CD integration

set -e  # Exit on any error

# Get script directory and source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source common functions library
source "$SCRIPT_DIR/common_functions.sh"

# Configuration
BUILD_DIR="build"
COVERAGE_DIR="${BUILD_DIR}/coverage_html"
TEST_RESULTS_DIR="${BUILD_DIR}/test_results"
PARALLEL_JOBS=$(nproc)

# Command line options
COVERAGE=false
PERFORMANCE=false
VERBOSE=false
PARALLEL=true
CI_MODE=false
MEMORY_CHECK=false
TEST_FILTER=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --coverage)
            COVERAGE=true
            shift
            ;;
        --performance)
            PERFORMANCE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --no-parallel)
            PARALLEL=false
            shift
            ;;
        --ci)
            CI_MODE=true
            shift
            ;;
        --memory-check)
            MEMORY_CHECK=true
            shift
            ;;
        --filter)
            TEST_FILTER="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --coverage      Generate code coverage report"
            echo "  --performance   Run performance benchmarks"
            echo "  --verbose       Enable verbose output"
            echo "  --no-parallel   Disable parallel test execution"
            echo "  --ci            CI/CD mode with XML output"
            echo "  --memory-check  Run with valgrind memory checking"
            echo "  --filter REGEX  Filter tests by regex pattern"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Print configuration
print_info "🧪 Enhanced Test Runner for DDoS Inspector"
print_info "📁 Build directory: ${BUILD_DIR}"
print_info "🔧 Parallel jobs: ${PARALLEL_JOBS}"
print_info "⚡ Parallel execution: ${PARALLEL}"
print_info "📊 Coverage analysis: ${COVERAGE}"
print_info "🏃 Performance testing: ${PERFORMANCE}"
print_info "🔍 Memory checking: ${MEMORY_CHECK}"
print_info "🤖 CI mode: ${CI_MODE}"
if [[ -n "$TEST_FILTER" ]]; then
    print_info "🔍 Test filter: ${TEST_FILTER}"
fi
echo ""

# Verify build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    print_error "❌ Build directory not found. Please run cmake build first."
    exit 1
fi

cd "$BUILD_DIR"

# Create test results directory
mkdir -p "$TEST_RESULTS_DIR"

# Start timing
START_TIME=$(date +%s)

print_info "🔍 Verifying test executables..."
if [ ! -f "unit_tests" ] || [ ! -f "test_stats_engine" ] || [ ! -f "test_behavior_tracker" ] || [ ! -f "test_firewall_action" ]; then
    print_error "❌ Test executables not found. Please build the project first."
    exit 1
fi

# Configure test execution parameters
CTEST_ARGS="--output-on-failure"

if [ "$PARALLEL" = true ]; then
    CTEST_ARGS="$CTEST_ARGS --parallel $PARALLEL_JOBS"
fi

if [ "$VERBOSE" = true ]; then
    CTEST_ARGS="$CTEST_ARGS --verbose"
fi

if [ "$CI_MODE" = true ]; then
    CTEST_ARGS="$CTEST_ARGS --output-junit ${TEST_RESULTS_DIR}/test_results.xml"
fi

if [[ -n "$TEST_FILTER" ]]; then
    CTEST_ARGS="$CTEST_ARGS -R $TEST_FILTER"
fi

# Run memory check if requested
if [ "$MEMORY_CHECK" = true ]; then
    if command -v valgrind &> /dev/null; then
        print_info "🔍 Running memory check with valgrind..."
        valgrind --tool=memcheck --leak-check=full --error-exitcode=1 ./unit_tests
    else
        print_warning "⚠️  Valgrind not found, skipping memory check"
    fi
fi

# Run main test suite
print_info "🧪 Running test suite..."
if ctest $CTEST_ARGS; then
    print_success "✅ All tests passed!"
    TEST_SUCCESS=true
else
    print_error "❌ Some tests failed!"
    TEST_SUCCESS=false
fi

# Performance testing
if [ "$PERFORMANCE" = true ]; then
    print_info "🏃 Running performance benchmarks..."
    
    print_info "📊 StatsEngine Performance:"
    time ./test_stats_engine --gtest_filter="*Performance*" 2>&1 | tee "${TEST_RESULTS_DIR}/stats_engine_perf.log"
    
    print_info "📊 BehaviorTracker Performance:"
    time ./test_behavior_tracker --gtest_filter="*Performance*" 2>&1 | tee "${TEST_RESULTS_DIR}/behavior_tracker_perf.log"
    
    print_info "📊 FirewallAction Performance:"
    time ./test_firewall_action --gtest_filter="*Performance*" 2>&1 | tee "${TEST_RESULTS_DIR}/firewall_action_perf.log"
fi

# Generate coverage report
if [ "$COVERAGE" = true ]; then
    print_info "📊 Generating coverage report..."
    
    # Check if coverage data exists
    if command -v gcov &> /dev/null && command -v lcov &> /dev/null; then
        # Generate coverage info
        lcov --capture --directory . --output-file coverage.info --quiet
        
        # Filter out external libraries and test files
        lcov --remove coverage.info '/usr/*' '*_test.cpp' '*test_*.cpp' --output-file coverage_filtered.info --quiet
        
        # Generate HTML report
        mkdir -p "$COVERAGE_DIR"
        genhtml coverage_filtered.info --output-directory "$COVERAGE_DIR" --quiet
        
        # Generate summary
        lcov --summary coverage_filtered.info 2>&1 | tee "${TEST_RESULTS_DIR}/coverage_summary.txt"
        
        print_success "📊 Coverage report generated at: ${COVERAGE_DIR}/index.html"
    else
        print_warning "⚠️  Coverage tools (gcov/lcov) not found. Please install for coverage analysis."
    fi
fi

# Calculate execution time
END_TIME=$(date +%s)
EXECUTION_TIME=$((END_TIME - START_TIME))

# Generate summary report
echo ""
print_info "📋 Test Execution Summary"
echo "=================================="
echo "⏱️  Total execution time: ${EXECUTION_TIME}s"
echo "🧪 Tests run with $([ "$PARALLEL" = true ] && echo "parallel" || echo "sequential") execution"
echo "📊 Coverage analysis: $([ "$COVERAGE" = true ] && echo "enabled" || echo "disabled")"
echo "🏃 Performance testing: $([ "$PERFORMANCE" = true ] && echo "enabled" || echo "disabled")"
echo "🔍 Memory checking: $([ "$MEMORY_CHECK" = true ] && echo "enabled" || echo "disabled")"

if [ "$TEST_SUCCESS" = true ]; then
    print_success "🎉 All tests completed successfully!"
    
    # Performance warnings
    if [ $EXECUTION_TIME -gt 30 ]; then
        print_warning "⚠️  Warning: Test execution took longer than expected (>30s)"
    fi
    
    exit 0
else
    print_error "💥 Test execution failed!"
    print_info "Check test results in: ${TEST_RESULTS_DIR}/"
    exit 1
fi
