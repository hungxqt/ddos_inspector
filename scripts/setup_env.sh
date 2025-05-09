#!/bin/bash

echo "🚀 Setting up the development environment..."

# Update the system
sudo apt-get update && sudo apt-get upgrade -y

# Install dependencies
sudo apt-get install -y build-essential cmake libpcap-dev \
                        libboost-all-dev snort3 clang-tidy

# Verify installation
echo "Dependencies installed successfully!"
echo "Versions:"
cmake --version
snort --version
