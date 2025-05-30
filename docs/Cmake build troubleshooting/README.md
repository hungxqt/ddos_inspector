# CMake Build Error Resolution Guide

## Problem Description
You're encountering CMake configuration errors that prevent the project from building properly.

## Error Analysis
The error indicates:
1. CMake cache conflicts requiring cleanup
2. Missing dependencies or incorrect configuration
3. Incomplete configuration preventing build

## Resolution Steps

### Step 1: Complete Clean Build Environment
```bash
# Navigate to project root
cd /home/hungqt/res

# Remove all build artifacts
rm -rf build/
rm -rf CMakeCache.txt
rm -rf CMakeFiles/
```

### Step 2: Install Dependencies Using Project Script
```bash
# Run the project's dependency installation script
./scripts/install_dependencies.sh

# This script will install GoogleTest locally and other required dependencies
```

### Step 3: System Dependencies Check
```bash
# Update package manager
sudo apt update

# Install essential build tools
sudo apt install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    pkg-config \
    libssl-dev \
    libcurl4-openssl-dev

# Verify CMake version (should be >= 3.16)
cmake --version
```

### Step 4: CMakeLists.txt Verification
Check your main CMakeLists.txt file uses direct GoogleTest linking:

```cmake
# Look for these lines that directly link with gtest libraries
target_link_libraries(unit_tests gtest gtest_main pthread)
target_link_libraries(test_stats_engine gtest gtest_main pthread)
target_link_libraries(test_behavior_tracker gtest gtest_main pthread)
target_link_libraries(test_firewall_action gtest gtest_main pthread)
```

### Step 5: Fresh Build Process
```bash
# Create new build directory
mkdir -p build
cd build

# Configure with verbose output for debugging
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_VERBOSE_MAKEFILE=ON

# If the above fails, try without Ninja
cd ..
rm -rf build/
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Build the project
make -j$(nproc)
```

### Step 6: Alternative Manual GoogleTest Installation

If the install script fails, manually install GoogleTest:

```bash
# Install GoogleTest system-wide
sudo apt install -y libgtest-dev libgmock-dev

# Or build from source locally
cd /tmp
git clone https://github.com/google/googletest.git
cd googletest
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make -j$(nproc)
sudo make install
```

## Debugging Commands

### Check Build Status
```bash
# Verbose CMake configuration
cmake .. -DCMAKE_BUILD_TYPE=Debug --debug-output

# Check CMake cache
cmake -N -LA | grep -i google

# Verify compiler setup
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++
```

### Environment Verification
```bash
# Check available disk space
df -h

# Check memory
free -h

# Check compiler versions
gcc --version
g++ --version

# Check CMake modules
cmake --help module-list | grep -i fetch
```

## Common Issues and Solutions

### Issue 1: CMake Generator Mismatch Error
**Error Message:**
```
CMake Error: Error: generator : Ninja
Does not match the generator used previously: Unix Makefiles
Either remove the CMakeCache.txt file and CMakeFiles directory or choose a different binary directory.
```

**Root Cause:** 
The build directory was previously configured with one generator (e.g., "Unix Makefiles") but CMake is now trying to use a different generator (e.g., "Ninja"). CMake doesn't allow switching generators in the same build directory.

**Solution:**
```bash
# Step 1: Remove the conflicting build directory
cd /home/hungqt/res
rm -rf build

# Step 2: Run dependency installation script
./scripts/install_dependencies.sh

# Step 3: Create fresh build directory
mkdir build

# Step 4: Configure with consistent generator
cmake -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=TRUE \
      -DCMAKE_C_COMPILER=/usr/bin/gcc \
      -DCMAKE_CXX_COMPILER=/usr/bin/g++ \
      -S . -B build -G "Unix Makefiles"

# Step 5: Build the project
make -C build
```

**Verification:**
```bash
# Check that build completed successfully
ls -la build/ddos_inspector.so
ls -la build/test_*
```

**Prevention:** Always use the same generator consistently, or clean the build directory when switching generators.

### Issue 2: Missing GoogleTest Dependencies
```bash
# If GoogleTest is not found, ensure the install script ran successfully
./scripts/install_dependencies.sh

# Verify GoogleTest installation
pkg-config --modversion gtest
ldconfig -p | grep gtest
```

### Issue 3: Permission Errors
```bash
# Fix ownership issues
sudo chown -R $USER:$USER /home/hungqt/res

# Fix permissions
chmod -R 755 /home/hungqt/res
```

### Issue 4: Corrupted CMake Cache
```bash
# Nuclear option - complete reset
cd /home/hungqt/res
sudo rm -rf build/ CMakeCache.txt CMakeFiles/
```

## Final Build Script
Create this script for reliable builds:

```bash
#!/bin/bash
# save as: rebuild.sh

set -e

echo "🧹 Cleaning build environment..."
rm -rf build/ CMakeCache.txt CMakeFiles/

echo "📦 Installing dependencies..."
./scripts/install_dependencies.sh

echo "🔧 Configuring project..."
mkdir build
cd build

echo "📦 Running CMake configuration..."
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

echo "🏗️ Building project..."
make -j$(nproc)

echo "🧪 Running tests..."
make test

echo "✅ Build completed successfully!"
```

Make it executable and run:
```bash
chmod +x rebuild.sh
./rebuild.sh
```

## Verification Steps

After successful build:
```bash
# Verify shared library is created
ls -la build/ddos_inspector.so

# Verify test executables exist
ls -la build/test_*

# Run a quick test
cd build
./test_behavior_tracker
```

## If All Else Fails

Contact system administrator or try building in a Docker container:
```bash
# Use provided Docker environment
docker-compose up --build
```

This ensures a clean, consistent build environment regardless of host system issues.