#!/bin/bash

# Build Windows Installer EXE
# -------------------------
# This script builds the Windows installer executable by:
# 1. Triggering the GitHub Actions workflow that builds the installer
# 2. Monitoring the workflow progress
# 3. Downloading the resulting installer executable
#
# Prerequisites:
# - GitHub CLI (gh) installed and authenticated
#
# Usage:
#   ./build-windows-installer-exe.sh
#   # or
#   make windows-installer
#
# Output:
# - viam-agent-windows-installer.exe (for main branch)
# - viam-agent-windows-installer-{branch name.exe (for other branches)
# - Job URL for reference

if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is not installed."
    echo "Please install it from: https://cli.github.com/"
    exit 1
fi

if ! gh auth status &> /dev/null; then
    echo "Error: Not authenticated with GitHub."
    echo "Please run 'gh auth login' first."
    exit 1
fi

read -p "Enter branch name (leave empty for main): " branch
branch=${branch:-main}
echo "Starting Windows installer build for branch: $branch"
gh workflow run build-windows-installer.yaml --ref "$branch"

echo "Waiting for workflow to start..."

# Wait for workflow to start with timeout (90 seconds)
start_time=$(date +%s)
workflow_started=false

while true; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    
    if [ $elapsed -ge 90 ]; then
        echo "Timeout: Workflow did not start within 90 seconds."
        echo "Please check the workflow status manually at: https://github.com/viamrobotics/agent/actions/workflows/build-windows-installer.yaml"
        echo "Once completed, you can download the artifact using: gh run download <run-id> --name viam-agent-installer.exe"
        exit 1
    fi
    
    # Try to get the latest run ID
    if job_id=$(gh run list --workflow=build-windows-installer.yaml --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null); then
        job_url="https://github.com/viamrobotics/agent/actions/runs/$job_id"
        echo "Job started: $job_url"
        workflow_started=true
        break
    fi
    
    echo "Waiting for workflow to start... (${elapsed}/90 seconds)"
    sleep 10
done

# Wait for job completion with timeout (5 minutes = 300 seconds)
timeout=300
start_time=$(date +%s)

while true; do
    run_info=$(gh run view "$job_id" --json status,conclusion)
    status=$(echo "$run_info" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    conclusion=$(echo "$run_info" | grep -o '"conclusion":"[^"]*"' | cut -d'"' -f4)
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))

    if [ "$status" = "completed" ]; then
        if [ "$conclusion" = "success" ]; then
            echo "Build completed successfully!"
            break
        else
            echo "Build failed! Check the job at: $job_url"
            exit 1
        fi
    elif [ $elapsed -ge $timeout ]; then
        echo "Build timed out after 5 minutes. Check the job at: $job_url"
        exit 1
    fi
    echo "Waiting for build to complete... ($elapsed/$timeout seconds)"
    sleep 10
done

# Determine the output filename based on the branch
if [ "$branch" = "main" ]; then
    output_name="viam-agent-windows-installer.exe"
else
    output_name="viam-agent-windows-installer-$branch.exe"
fi

echo "Downloading installer artifact..."
rm -rf artifacts viam-agent-installer.exe "$output_name"
gh run download "$job_id" --name viam-agent-installer.exe --dir artifacts

if [ ! -f "artifacts/viam-agent-installer.exe" ]; then
    echo "Error: Failed to download artifact"
    exit 1
fi

mv artifacts/viam-agent-installer.exe "$output_name"
rm -rf artifacts

echo "Build completed successfully!"
echo "Installer location: $(pwd)/$output_name"
echo "Job reference: $job_url" 