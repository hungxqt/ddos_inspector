#!/bin/bash

echo "🐳 Building Docker image..."

# Build the Docker image
docker build -t ddos_inspector .

echo "🚀 Running Docker container..."
docker run --rm -d --name ddos_inspector_container -p 8080:8080 ddos_inspector

echo "✅ Docker container running at http://localhost:8080"
