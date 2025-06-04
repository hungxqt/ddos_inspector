#!/bin/bash

# Enhanced build script for DDoS Inspector Plugin
set -e  # Exit on any error

# Get script directory and source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source common functions library
source "$SCRIPT_DIR/common_functions.sh"

# Default configuration
BUILD_TYPE="Debug"
BUILD_JOBS=$(nproc)
BUILD_DIR="build"
RELEASE_DIR="$PROJECT_ROOT/release"
CLEAN_BUILD=false
RUN_TESTS=true
VERBOSE=false
FORCE_GENERATOR=""

# Function to show help
show_help() {
    echo -e "${BLUE}DDoS Inspector Plugin Build Script${NC}"
    echo
    echo -e "${YELLOW}Usage:${NC} $0 [OPTIONS]"
    echo
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  -t, --type TYPE        Build type: Debug, Release, RelWithDebInfo, MinSizeRel (default: Debug)"
    echo -e "  -j, --jobs JOBS        Number of parallel build jobs (default: $(nproc))"
    echo -e "  -c, --clean            Clean build directory before building"
    echo -e "  --no-tests             Skip running tests after build"
    echo -e "  -v, --verbose          Enable verbose build output"
    echo -e "  -g, --generator GEN    Force CMake generator: Ninja, Unix Makefiles"
    echo -e "  --build-dir DIR        Custom build directory (default: build)"
    echo -e "  --release-dir DIR      Custom release directory (default: release)"
    echo -e "  -h, --help             Show this help message"
    echo
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  $0                     # Build with default settings (Debug)"
    echo -e "  $0 -t Release -j 4     # Release build with 4 jobs"
    echo -e "  $0 --clean --verbose   # Clean build with verbose output"
    echo -e "  $0 --no-tests          # Build without running tests"
    echo -e "  $0 -g Ninja            # Force use of Ninja generator"
    echo
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            BUILD_TYPE="$2"
            if [[ ! "$BUILD_TYPE" =~ ^(Debug|Release|RelWithDebInfo|MinSizeRel)$ ]]; then
                print_error "Invalid build type: $BUILD_TYPE"
                print_info "Valid types: Debug, Release, RelWithDebInfo, MinSizeRel"
                exit 1
            fi
            shift 2
            ;;
        -j|--jobs)
            BUILD_JOBS="$2"
            if ! [[ "$BUILD_JOBS" =~ ^[0-9]+$ ]] || [ "$BUILD_JOBS" -lt 1 ]; then
                print_error "Invalid number of jobs: $BUILD_JOBS"
                exit 1
            fi
            shift 2
            ;;
        -c|--clean)
            CLEAN_BUILD=true
            shift
            ;;
        --no-tests)
            RUN_TESTS=false
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -g|--generator)
            FORCE_GENERATOR="$2"
            if [[ ! "$FORCE_GENERATOR" =~ ^(Ninja|Unix\ Makefiles)$ ]]; then
                print_error "Invalid generator: $FORCE_GENERATOR"
                print_info "Valid generators: Ninja, Unix Makefiles"
                exit 1
            fi
            shift 2
            ;;
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --release-dir)
            RELEASE_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            print_info "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

print_info "🔨 Building DDoS Inspector Plugin..."
print_info "Build Configuration:"
echo -e "  Build Type: $BUILD_TYPE"
echo -e "  Build Jobs: $BUILD_JOBS"
echo -e "  Build Directory: $BUILD_DIR"
echo -e "  Release Directory: $RELEASE_DIR"
echo -e "  Clean Build: $CLEAN_BUILD"
echo -e "  Run Tests: $RUN_TESTS"
echo -e "  Verbose: $VERBOSE"
if [ -n "$FORCE_GENERATOR" ]; then
    echo -e "  Forced Generator: $FORCE_GENERATOR"
fi
echo

# Ensure we're in the project root
cd "$PROJECT_ROOT"

# Clean build directory if requested
if [ "$CLEAN_BUILD" = true ]; then
    print_warning "🧹 Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

# Create build directory
mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"

# Set verbose flags if requested
CMAKE_VERBOSE=""
BUILD_VERBOSE=""
if [ "$VERBOSE" = true ]; then
    CMAKE_VERBOSE="-DCMAKE_VERBOSE_MAKEFILE=ON"
    BUILD_VERBOSE="--verbose"
fi

# Check if we have Ninja or need to use Make
if [ -n "$FORCE_GENERATOR" ]; then
    print_info "🔧 Using forced generator: $FORCE_GENERATOR..."
    if [ "$FORCE_GENERATOR" = "Ninja" ]; then
        cmake .. -GNinja -DCMAKE_BUILD_TYPE="$BUILD_TYPE" $CMAKE_VERBOSE
        BUILD_TOOL="ninja $BUILD_VERBOSE"
        TEST_COMMAND="ninja test"
    else
        cmake .. -G"Unix Makefiles" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" $CMAKE_VERBOSE
        BUILD_TOOL="make -j$BUILD_JOBS $BUILD_VERBOSE"
        TEST_COMMAND="make test"
    fi
elif command -v ninja &> /dev/null && [ -f "build.ninja" ]; then
    print_info "🔧 Using existing Ninja build system..."
    BUILD_TOOL="ninja $BUILD_VERBOSE"
    TEST_COMMAND="ninja test"
elif [ -f "Makefile" ]; then
    print_info "🔧 Using existing Make build system..."
    BUILD_TOOL="make -j$BUILD_JOBS $BUILD_VERBOSE"
    TEST_COMMAND="make test"
else
    print_info "⚙️  Configuring project with CMake..."
    # Try Ninja first, fall back to Make
    if command -v ninja &> /dev/null; then
        cmake .. -GNinja -DCMAKE_BUILD_TYPE="$BUILD_TYPE" $CMAKE_VERBOSE
        BUILD_TOOL="ninja $BUILD_VERBOSE"
        TEST_COMMAND="ninja test"
    else
        cmake .. -DCMAKE_BUILD_TYPE="$BUILD_TYPE" $CMAKE_VERBOSE
        BUILD_TOOL="make -j$BUILD_JOBS $BUILD_VERBOSE"
        TEST_COMMAND="make test"
    fi
fi

# Build the project
print_info "🔨 Building project..."
if $BUILD_TOOL; then
    print_success "Build successful!"
    
    # Run tests if requested and available
    if [ "$RUN_TESTS" = true ] && ([ -f "CTestTestfile.cmake" ] || [ -f "test" ]); then
        print_info "🧪 Running tests..."
        if $TEST_COMMAND; then
            print_success "All tests passed!"
        else
            print_warning "Some tests failed, but build completed"
        fi
    elif [ "$RUN_TESTS" = false ]; then
        print_info "⏭️  Skipping tests as requested"
    fi
    
    # Copy plugin to release folder
    print_info "📦 Preparing release artifacts..."
    
    # Create release directory if it doesn't exist
    mkdir -p "$RELEASE_DIR"
    
    # Copy the main plugin file
    if [ -f "libddos_inspector.so" ]; then
        cp "libddos_inspector.so" "$RELEASE_DIR/"
        print_success "Copied libddos_inspector.so to release folder"
        
        # Create a version info file
        echo "Build Date: $(date)" > "$RELEASE_DIR/BUILD_INFO.txt"
        echo "Build Type: $BUILD_TYPE" >> "$RELEASE_DIR/BUILD_INFO.txt"
        echo "Git Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'N/A')" >> "$RELEASE_DIR/BUILD_INFO.txt"
        echo "Build Host: $(hostname)" >> "$RELEASE_DIR/BUILD_INFO.txt"
        
        # Copy configuration file if it exists
        if [ -f "$PROJECT_ROOT/snort_ddos_config.lua" ]; then
            cp "$PROJECT_ROOT/snort_ddos_config.lua" "$RELEASE_DIR/"
            print_success "Copied configuration file to release folder"
        fi
        
        # Copy documentation
        if [ -f "$PROJECT_ROOT/README.md" ]; then
            cp "$PROJECT_ROOT/README.md" "$RELEASE_DIR/"
        fi
        
        # Make plugin executable if needed
        chmod +x "$RELEASE_DIR/libddos_inspector.so"
        
    else
        print_error "Plugin file libddos_inspector.so not found!"
        exit 1
    fi
    
    # Copy additional build artifacts if they exist
    if [ -f "libddos_core.a" ]; then
        cp "libddos_core.a" "$RELEASE_DIR/"
        print_success "Copied core library to release folder"
    fi
    
    # Show build artifacts
    print_info "📦 Build artifacts created:"
    echo -e "  Plugin: $RELEASE_DIR/libddos_inspector.so"
    if [ -f "$RELEASE_DIR/libddos_core.a" ]; then
        echo -e "  Core Library: $RELEASE_DIR/libddos_core.a"
    fi
    if [ -f "$RELEASE_DIR/snort_ddos_config.lua" ]; then
        echo -e "  Configuration: $RELEASE_DIR/snort_ddos_config.lua"
    fi
    echo -e "  Build Info: $RELEASE_DIR/BUILD_INFO.txt"
    
    # Display release folder contents
    print_info "📁 Release folder contents:"
    ls -la "$RELEASE_DIR"
    
    print_success "🎉 Build completed successfully and artifacts copied to release folder!"
    
else
    print_error "Build failed!"
    exit 1
fi
