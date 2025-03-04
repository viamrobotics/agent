#!/bin/bash

# Check if binary path is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <path-to-binary>"
    exit 1
fi

BINARY_PATH="$1"
BINARY_NAME=$(basename "$BINARY_PATH")

# Extract version from binary name
VERSION=$(echo "$BINARY_NAME" | sed -E 's/viam-agent-v([0-9]+\.[0-9]+\.[0-9]+(-dev\.[0-9]+)?).*/\1/')

# Determine if this is a prerelease
if [[ "$VERSION" == *"-dev"* ]]; then
    BINNAME="prerelease/$BINARY_NAME"
else
    BINNAME="$BINARY_NAME"
fi

# Set platform based on architecture in binary name
if [[ "$BINARY_NAME" == *"x86_64"* ]]; then
    PLATFORM="linux/amd64"
elif [[ "$BINARY_NAME" == *"aarch64"* ]]; then
    PLATFORM="linux/arm64"
else
    echo "Unknown architecture in binary name"
    exit 1
fi

# Calculate SHA256
SHA256=$(sha256sum "$BINARY_PATH" | cut -d' ' -f1)

# Generate json manifest with binary-specific name
mkdir -p etc
cat > "etc/${BINARY_NAME}.json" << EOF
{
	"subsystem": "viam-agent",
	"version": "$VERSION",
	"platform": "$PLATFORM",
	"upload-path": "packages.viam.com/apps/viam-agent/$BINNAME",
	"sha256": "$SHA256"
}
EOF
