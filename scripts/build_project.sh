#!/bin/bash

echo "🔨 Building project..."

# Create the build directory if it doesn't exist
mkdir -p build && cd build

# Run CMake and Make
cmake ..
make -j$(nproc)

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed!"
    exit 1
fi
