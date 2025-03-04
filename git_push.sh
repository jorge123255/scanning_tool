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
git commit -m "Fix PDF generation issues and test with DVWA repository"

# Push to GitHub
echo -e "\nPushing to GitHub..."
git push origin main

echo -e "\nDone!" 