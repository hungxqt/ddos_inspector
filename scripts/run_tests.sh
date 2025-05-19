#!/bin/bash

echo "🧪 Running unit tests..."

# Navigate to build directory
cd build

# Run tests
ctest --output-on-failure

if [ $? -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "❌ Some tests failed!"
    exit 1
fi
