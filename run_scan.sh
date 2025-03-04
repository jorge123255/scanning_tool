#!/bin/bash

# Change to the GitHubScan directory
cd /Users/georgeszulc/GitHubScan

# Remove any existing report
rm -f report.pdf

# Run the scan
python3 githubscan.py https://github.com/Micke-K/IntuneManagement.git --output-format pdf

# Check if the report was generated
if [ -f "report.pdf" ]; then
    echo "Scan completed successfully. Report generated at: /Users/georgeszulc/GitHubScan/report.pdf"
    ls -la report.pdf
else
    echo "Scan failed or report was not generated."
    # Check the last few lines of the scan output
    python3 githubscan.py https://github.com/Micke-K/IntuneManagement.git --output-format text | tail -n 10
fi 