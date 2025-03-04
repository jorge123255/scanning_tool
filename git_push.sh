#!/bin/bash

# Change to the GitHubScan directory
cd /Users/georgeszulc/GitHubScan

# Check git status
echo "Current git status:"
git status

# Add all changes
echo -e "\nAdding all changes..."
git add .

# Commit changes
echo -e "\nCommitting changes..."
git commit -m "Fix PSScriptAnalyzer function and improve error handling"

# Push to GitHub
echo -e "\nPushing to GitHub..."
git push origin main

echo -e "\nDone!" 